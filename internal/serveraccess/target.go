package serveraccess

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"

	"domaindoctor/internal/safenet"
)

// Target is a validated server-accessibility target: a literal public IP, or
// a hostname with the public addresses it resolved to (pinned once, never
// re-resolved — the same anti-rebinding discipline as the rest of the app).
type Target struct {
	Input string       // what the operator entered (trimmed)
	Host  string       // ASCII hostname, empty for an IP literal
	IPs   []netip.Addr // pinned public addresses
}

// Target-parsing errors. The API maps these to stable codes.
var (
	ErrEmpty    = errors.New("enter a server IP address or hostname")
	ErrTooLong  = errors.New("the target is too long")
	ErrInvalid  = errors.New("this does not look like a valid IP address or hostname")
	ErrPrivate  = errors.New("that address is private, loopback, link-local or reserved and cannot be checked")
	ErrNoIP     = errors.New("the hostname does not resolve to any public IP address")
	ErrReserved = errors.New("local or reserved names (localhost, .local, .internal, ...) cannot be checked")
)

var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.ValidateLabels(true),
	idna.StrictDomainName(true),
	idna.Transitional(false),
)

var reservedSuffixes = []string{
	"localhost", "local", "internal", "invalid", "test", "example",
	"home.arpa", "arpa", "lan", "corp", "home", "intranet", "onion",
}

// ParseTarget validates and resolves raw. For a hostname it resolves exactly
// once through safenet (rejecting any private/blocked answer); for an IP
// literal it validates the address. r may be nil (default resolver).
func ParseTarget(ctx context.Context, r safenet.Resolver, raw string) (Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Target{}, ErrEmpty
	}
	if len(s) > 255 {
		return Target{}, ErrTooLong
	}
	// Strip an accidental scheme or trailing path/port the operator pasted.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimSuffix(s, "/")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}

	// IP literal (optionally bracketed, no port).
	host := strings.Trim(s, "[]")
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return Target{}, ErrInvalid
		}
		a = a.Unmap()
		if safenet.IsBlocked(a) {
			return Target{}, ErrPrivate
		}
		return Target{Input: s, IPs: []netip.Addr{a}}, nil
	}

	// Hostname: strip a trailing :port if present.
	if h, _, ok := splitHostMaybePort(s); ok {
		s = h
	}
	name, err := idnaProfile.ToASCII(strings.TrimSuffix(s, "."))
	if err != nil || name == "" {
		return Target{}, ErrInvalid
	}
	name = strings.ToLower(name)
	for _, suf := range reservedSuffixes {
		if name == suf || strings.HasSuffix(name, "."+suf) {
			return Target{}, ErrReserved
		}
	}
	if !strings.Contains(name, ".") {
		return Target{}, ErrInvalid
	}
	ips, err := safenet.Resolve(ctx, r, name)
	if err != nil {
		if errors.Is(err, safenet.ErrBlocked) {
			return Target{}, ErrPrivate
		}
		if errors.Is(err, safenet.ErrNoAddress) {
			return Target{}, ErrNoIP
		}
		return Target{}, ErrNoIP
	}
	if len(ips) == 0 {
		return Target{}, ErrNoIP
	}
	return Target{Input: s, Host: name, IPs: ips}, nil
}

// probeIPs picks up to 2 IPv4 and 2 IPv6 addresses to measure, like the
// domain-reachability layer, so one target with many A records is bounded.
func (t Target) probeIPs() []netip.Addr {
	var v4, v6 []netip.Addr
	for _, a := range t.IPs {
		if a.Is4() && len(v4) < 2 {
			v4 = append(v4, a)
		} else if a.Is6() && len(v6) < 2 {
			v6 = append(v6, a)
		}
	}
	return append(v4, v6...)
}

// splitHostMaybePort splits "host:port" only when the part after the last
// colon is all digits (so IPv6 literals, already handled above, are safe).
func splitHostMaybePort(s string) (host, port string, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 || strings.IndexByte(s, ':') != i {
		return s, "", false // no colon, or several (IPv6) — leave it
	}
	p := s[i+1:]
	if p == "" {
		return s, "", false
	}
	for _, r := range p {
		if r < '0' || r > '9' {
			return s, "", false
		}
	}
	return s[:i], p, true
}
