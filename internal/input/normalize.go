// Package input turns messy user input (URLs, uppercase, ports, paths,
// trailing dots, www., Unicode) into a bare ASCII domain name.
package input

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Domain is a normalized target.
type Domain struct {
	Input   string `json:"input"`   // what the user typed (trimmed)
	Name    string `json:"name"`    // ASCII (punycode) host, www. stripped
	Unicode string `json:"unicode"` // display form
	Apex    string `json:"apex"`    // registrable domain (eTLD+1)
}

var (
	ErrEmpty       = errors.New("please enter a domain name")
	ErrIP          = errors.New("IP addresses are not supported — enter a domain name such as example.com")
	ErrLocal       = errors.New("local or reserved names (localhost, .local, .internal, ...) cannot be checked")
	ErrInvalid     = errors.New("this does not look like a valid domain name")
	ErrNoTLD       = errors.New("enter a full domain including its TLD, e.g. example.com")
	ErrPublicSufix = errors.New("this is a public suffix (like a TLD), not a registrable domain")
)

// reservedSuffixes are special-use names (RFC 6761/6762/8375 and common
// internal conventions) that must never be probed.
var reservedSuffixes = []string{
	"localhost", "local", "internal", "invalid", "test", "example",
	"home.arpa", "arpa", "lan", "corp", "home", "intranet", "onion",
}

var profile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.ValidateLabels(true),
	idna.StrictDomainName(true),
	idna.Transitional(false),
)

// Normalize parses s and returns a Domain or a user-facing error.
func Normalize(s string) (Domain, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Domain{}, ErrEmpty
	}
	if len(raw) > 2048 {
		return Domain{}, ErrInvalid
	}
	h := raw
	// Strip scheme ("https://", "ftp://", or a bare "//").
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	h = strings.TrimPrefix(h, "//")
	// Cut path, query, fragment.
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	// Strip userinfo.
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	// Bracketed IPv6 literal (with optional port).
	if strings.HasPrefix(h, "[") {
		return Domain{}, ErrIP
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return Domain{}, ErrIP
	}
	// Strip port.
	if i := strings.LastIndex(h, ":"); i >= 0 {
		port := h[i+1:]
		if !allDigits(port) {
			return Domain{}, ErrInvalid
		}
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return Domain{}, ErrEmpty
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return Domain{}, ErrIP
	}
	if looksLikeIPv4(h) {
		return Domain{}, ErrIP
	}

	ascii, err := profile.ToASCII(h)
	if err != nil {
		return Domain{}, fmt.Errorf("%w: %v", ErrInvalid, idnaReason(err))
	}
	ascii = strings.ToLower(ascii)
	if strings.HasPrefix(ascii, "www.") {
		ascii = ascii[4:]
	}
	if err := checkSyntax(ascii); err != nil {
		return Domain{}, err
	}
	for _, r := range reservedSuffixes {
		if ascii == r || strings.HasSuffix(ascii, "."+r) {
			return Domain{}, ErrLocal
		}
	}
	if !strings.Contains(ascii, ".") {
		return Domain{}, ErrNoTLD
	}
	apex, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		return Domain{}, ErrPublicSufix
	}
	uni, err := idna.Display.ToUnicode(ascii)
	if err != nil {
		uni = ascii
	}
	return Domain{Input: raw, Name: ascii, Unicode: uni, Apex: apex}, nil
}

// checkSyntax enforces LDH labels, length limits, and an alphabetic TLD.
func checkSyntax(d string) error {
	if len(d) > 253 {
		return ErrInvalid
	}
	labels := strings.Split(d, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return ErrInvalid
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return ErrInvalid
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ErrInvalid
			}
		}
	}
	tld := labels[len(labels)-1]
	if allDigits(tld) {
		return ErrIP
	}
	return nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// looksLikeIPv4 catches shorthand/odd forms like "127.1" or "0x7f.1".
func looksLikeIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		p = strings.ToLower(p)
		if strings.HasPrefix(p, "0x") && len(p) > 2 {
			continue
		}
		if !allDigits(p) {
			return false
		}
	}
	return true
}

func idnaReason(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return msg
}
