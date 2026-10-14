// Package clientip extracts the real client IP behind a known number of
// trusted reverse proxies. Raw X-Forwarded-For is never trusted: only the
// entries appended by our own proxies count.
package clientip

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Extractor is configured once at startup.
type Extractor struct {
	// Hops is the number of trusted reverse proxies in front of the master
	// (nginx alone = 1, CDN + nginx = 2). 0 means use RemoteAddr only.
	Hops int
	// TrustedCIDRs, if set, must contain RemoteAddr for X-Forwarded-For to be
	// consulted at all (defence against direct connections bypassing nginx).
	TrustedCIDRs []netip.Prefix
}

// Key returns the rate-limit key: the IPv4 address, or the IPv6 /64.
// One subscriber typically owns a whole /64, so per-/128 limits are
// trivially bypassed by rotating addresses.
func (e Extractor) Key(r *http.Request) string {
	ip := e.IP(r)
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Is4() {
		return ip
	}
	p, _ := a.Prefix(64)
	return p.String()
}

// IP returns the client IP for logging (use Key for rate limiting).
func (e Extractor) IP(r *http.Request) string {
	remote := remoteIP(r.RemoteAddr)
	if e.Hops <= 0 {
		return remote
	}
	if len(e.TrustedCIDRs) > 0 {
		ra, err := netip.ParseAddr(remote)
		if err != nil || !contains(e.TrustedCIDRs, ra) {
			return remote
		}
	}
	var entries []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		for _, p := range strings.Split(h, ",") {
			if p = strings.TrimSpace(p); p != "" {
				entries = append(entries, p)
			}
		}
	}
	// Each trusted proxy appends the peer it saw. With N proxies, the
	// N-th entry from the right was written by the outermost proxy and is
	// the real client; anything left of it is client-controlled.
	idx := len(entries) - e.Hops
	if idx < 0 || idx >= len(entries) {
		return remote
	}
	a, err := netip.ParseAddr(stripPort(entries[idx]))
	if err != nil {
		return remote
	}
	return a.Unmap().String()
}

func contains(ps []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func remoteIP(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		h = addr
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	return h
}

func stripPort(s string) string {
	if strings.HasPrefix(s, "[") {
		if h, _, err := net.SplitHostPort(s); err == nil {
			return h
		}
		return strings.Trim(s, "[]")
	}
	if strings.Count(s, ":") == 1 {
		if h, _, err := net.SplitHostPort(s); err == nil {
			return h
		}
	}
	return s
}

// ParseCIDRs parses a comma-separated list; invalid entries are returned as error.
func ParseCIDRs(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			a, err := netip.ParseAddr(p)
			if err != nil {
				return nil, err
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		pr, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	return out, nil
}
