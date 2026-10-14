// Package safenet is the SSRF boundary shared by the master and the agent.
//
// Every outbound connection to a user-influenced target goes through it:
// the target is resolved exactly once, every resolved address is checked
// against the blocked ranges, and the connection is then made to one of
// those pinned addresses (never re-resolving the hostname). A dialer
// Control hook re-checks the address actually being connected to, so even
// a code path that forgot to pin cannot reach a blocked range.
package safenet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

var (
	// ErrBlocked means the target is, or resolves to, a forbidden address.
	ErrBlocked = errors.New("target resolves to a private, loopback, link-local, multicast or otherwise non-public address")
	// ErrNoAddress means the name resolved to no usable address.
	ErrNoAddress = errors.New("target has no IP addresses")
)

var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8",       // "this network", unspecified
	"10.0.0.0/8",      // RFC 1918
	"100.64.0.0/10",   // CGNAT shared space
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local incl. 169.254.169.254 metadata
	"172.16.0.0/12",   // RFC 1918
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.88.99.0/24",  // 6to4 relay anycast (deprecated)
	"192.168.0.0/16",  // RFC 1918
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved + broadcast
	"::/128",          // unspecified
	"::1/128",         // loopback
	"::ffff:0:0/96",   // v4-mapped (checked after Unmap, kept for safety)
	"::/96",           // deprecated IPv4-compatible (::a.b.c.d)
	"::ffff:0:0:0/96", // SIIT IPv4-translated
	"64:ff9b:1::/48",  // local-use NAT64
	"100::/64",        // discard-only
	"2001:db8::/32",   // documentation
	"fc00::/7",        // ULA incl. fd00:ec2::254 metadata
	"fe80::/10",       // link-local
	"fec0::/10",       // site-local (deprecated)
	"ff00::/8",        // multicast
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// IsBlocked reports whether a is not a public unicast address.
func IsBlocked(a netip.Addr) bool {
	if !a.IsValid() {
		return true
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	// NAT64 well-known prefix: judge the embedded IPv4 address.
	if a.Is6() && netip.MustParsePrefix("64:ff9b::/96").Contains(a) {
		b := a.As16()
		v4 := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		return IsBlocked(v4)
	}
	// 6to4: 2002:VVVV:VVVV::/48 embeds an IPv4 address.
	if a.Is6() && netip.MustParsePrefix("2002::/16").Contains(a) {
		b := a.As16()
		v4 := netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
		return IsBlocked(v4)
	}
	return false
}

// Resolver is the subset of *net.Resolver used here; tests inject fakes.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Resolve resolves host exactly once and returns the pinned public addresses.
// If any returned address is blocked the whole target is rejected: a name
// that mixes public and private answers is treated as hostile.
func Resolve(ctx context.Context, r Resolver, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if IsBlocked(a) {
			return nil, ErrBlocked
		}
		return []netip.Addr{a.Unmap()}, nil
	}
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, ErrNoAddress
	}
	out := make([]netip.Addr, 0, len(addrs))
	seen := map[netip.Addr]bool{}
	for _, a := range addrs {
		a = a.Unmap()
		if IsBlocked(a) {
			return nil, ErrBlocked
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}

// CheckAddrs validates a caller-supplied pinned list (used by the agent on
// the IPs the master sends it).
func CheckAddrs(addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return ErrNoAddress
	}
	for _, a := range addrs {
		if IsBlocked(a) {
			return ErrBlocked
		}
	}
	return nil
}

// Control is a net.Dialer Control hook that refuses to connect to blocked
// addresses. It is the last line of defence and sees the real socket address.
func Control(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("safenet: unparsable dial address: %w", ErrBlocked)
	}
	if IsBlocked(ap.Addr()) {
		return ErrBlocked
	}
	return nil
}

// Dialer returns a net.Dialer guarded by Control.
func Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: Control}
}

// PinnedDialContext returns a DialContext func that ignores the host part
// of the address it is asked to dial and connects to the pinned IPs instead
// (in order, first success wins). The port is taken from the request.
// This is what makes DNS rebinding impossible: no second lookup ever happens.
func PinnedDialContext(ips []netip.Addr, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := Dialer(timeout)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var lastErr error = ErrNoAddress
		for _, ip := range ips {
			if IsBlocked(ip) {
				lastErr = ErrBlocked
				continue
			}
			c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return c, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, lastErr
	}
}
