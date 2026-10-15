package input

import (
	"errors"
	"net/netip"
	"strings"

	"domaindoctor/internal/safenet"
)

// ParseOriginIP validates a user-supplied origin address for the
// origin-direct test: a literal public IP only (no host names; no private,
// loopback, link-local, CGNAT, documentation or metadata addresses).
// An empty string means "no origin test".
func ParseOriginIP(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.Addr{}, errors.New("originIp must be an IP address (for example 93.184.215.14)")
	}
	if a.Zone() != "" {
		return netip.Addr{}, errors.New("originIp must not contain an IPv6 zone")
	}
	a = a.Unmap()
	if safenet.IsBlocked(a) {
		return netip.Addr{}, errors.New("originIp must be a public address; private, loopback, link-local and metadata addresses are not allowed")
	}
	return a, nil
}
