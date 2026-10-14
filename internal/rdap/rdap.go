// Package rdap looks up domain registration data via RDAP (IANA bootstrap).
// WHOIS (package whois) is the fallback for TLDs without RDAP.
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"domaindoctor/internal/safenet"
)

const DefaultBootstrapURL = "https://data.iana.org/rdap/dns.json"

var (
	// ErrNotFound means the registry says the domain does not exist.
	ErrNotFound = errors.New("domain not found in registry")
	// ErrNoService means the TLD publishes no RDAP service.
	ErrNoService = errors.New("no RDAP service for this TLD")
)

// Info is normalized registration data from RDAP or WHOIS.
type Info struct {
	Source      string     `json:"source"` // "rdap" or "whois"
	Server      string     `json:"server"`
	Registrar   string     `json:"registrar,omitempty"`
	Created     *time.Time `json:"created,omitempty"`
	Updated     *time.Time `json:"updated,omitempty"`
	Expires     *time.Time `json:"expires,omitempty"`
	Status      []string   `json:"status"` // EPP codes, camelCase (clientHold, ...)
	Nameservers []string   `json:"nameservers,omitempty"`
}

// Client fetches RDAP data. Zero value is not usable; use New.
type Client struct {
	HTTP         *http.Client
	BootstrapURL string

	mu       sync.Mutex
	services map[string][]string // tld/suffix -> base URLs
	fetched  time.Time
}

func New() *Client {
	return &Client{HTTP: safenet.SafeHTTPClient(10 * time.Second), BootstrapURL: DefaultBootstrapURL}
}

func (c *Client) getJSON(ctx context.Context, u string, v any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "DomainDoctor/1.0")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, json.Unmarshal(body, v)
}

func (c *Client) bootstrap(ctx context.Context) (map[string][]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.services != nil && time.Since(c.fetched) < 24*time.Hour {
		return c.services, nil
	}
	var doc struct {
		Services [][][]string `json:"services"`
	}
	if _, err := c.getJSON(ctx, c.BootstrapURL, &doc); err != nil {
		if c.services != nil {
			return c.services, nil // serve stale on refresh failure
		}
		return nil, fmt.Errorf("RDAP bootstrap: %w", err)
	}
	m := map[string][]string{}
	for _, svc := range doc.Services {
		if len(svc) < 2 {
			continue
		}
		for _, tld := range svc[0] {
			m[strings.ToLower(tld)] = svc[1]
		}
	}
	c.services, c.fetched = m, time.Now()
	return m, nil
}

// BaseURLs returns RDAP base URLs for domain, longest matching suffix first.
func (c *Client) BaseURLs(ctx context.Context, domain string) ([]string, error) {
	svc, err := c.bootstrap(ctx)
	if err != nil {
		return nil, err
	}
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(domain), "."), ".")
	for i := 1; i < len(labels); i++ {
		if urls, ok := svc[strings.Join(labels[i:], ".")]; ok && len(urls) > 0 {
			return urls, nil
		}
	}
	return nil, ErrNoService
}

// Lookup returns registration data for domain.
func (c *Client) Lookup(ctx context.Context, domain string) (*Info, error) {
	bases, err := c.BaseURLs(ctx, domain)
	if err != nil {
		return nil, err
	}
	// Prefer https.
	for i, b := range bases {
		if strings.HasPrefix(b, "https://") && i > 0 {
			bases[0], bases[i] = bases[i], bases[0]
			break
		}
	}
	var lastErr error
	for _, base := range bases {
		if !strings.HasSuffix(base, "/") {
			base += "/"
		}
		u := base + "domain/" + url.PathEscape(domain)
		var doc rdapDomain
		code, err := c.getJSON(ctx, u, &doc)
		if code == http.StatusNotFound {
			return nil, ErrNotFound
		}
		if err != nil {
			lastErr = err
			continue
		}
		info := doc.toInfo()
		info.Server = hostOf(base)
		return info, nil
	}
	return nil, lastErr
}

func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return p.Host
}

type rdapDomain struct {
	LDHName string   `json:"ldhName"`
	Status  []string `json:"status"`
	Events  []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities    []rdapEntity `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
}

type rdapEntity struct {
	Roles      []string        `json:"roles"`
	Handle     string          `json:"handle"`
	VCardArray json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity    `json:"entities"`
}

func (d *rdapDomain) toInfo() *Info {
	info := &Info{Source: "rdap", Status: []string{}}
	for _, s := range d.Status {
		info.Status = append(info.Status, NormalizeStatus(s))
	}
	for _, e := range d.Events {
		t, ok := ParseDate(e.Date)
		if !ok {
			continue
		}
		switch strings.ToLower(e.Action) {
		case "registration":
			info.Created = &t
		case "expiration":
			info.Expires = &t
		case "last changed":
			info.Updated = &t
		}
	}
	for _, e := range d.Entities {
		if hasRole(e.Roles, "registrar") {
			info.Registrar = vcardFN(e.VCardArray)
			if info.Registrar == "" {
				info.Registrar = e.Handle
			}
		}
	}
	for _, ns := range d.Nameservers {
		info.Nameservers = append(info.Nameservers, strings.ToLower(ns.LDHName))
	}
	return info
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// vcardFN extracts the "fn" property from a jCard: ["vcard", [[name, params, type, value], ...]].
func vcardFN(raw json.RawMessage) string {
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil || len(arr) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if json.Unmarshal(arr[1], &props) != nil {
		return ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var name, val string
		if json.Unmarshal(p[0], &name) == nil && name == "fn" && json.Unmarshal(p[3], &val) == nil {
			return val
		}
	}
	return ""
}

// NormalizeStatus maps RDAP ("client hold") and WHOIS ("clientHold https://icann.org/epp#clientHold")
// forms to EPP camelCase ("clientHold").
func NormalizeStatus(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, " http"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "("); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	words := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '_' || r == '-' })
	if len(words) == 0 {
		return ""
	}
	if len(words) == 1 {
		w := words[0]
		// Already camelCase (clientHold) — just lower the first rune.
		return strings.ToLower(w[:1]) + w[1:]
	}
	var b strings.Builder
	for i, w := range words {
		w = strings.ToLower(w)
		if i > 0 {
			r := []rune(w)
			r[0] = unicode.ToUpper(r[0])
			w = string(r)
		}
		b.WriteString(w)
	}
	return b.String()
}

var dateLayouts = []string{
	time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05",
	"2006-01-02 15:04:05", "2006-01-02 15:04:05 MST", "2006-01-02", "02-Jan-2006", "2006.01.02",
	"2006/01/02", "02.01.2006", "January 2 2006",
}

// ParseDate accepts the many date formats seen in RDAP and WHOIS.
func ParseDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	// "2026-01-02T00:00:00.0Z" with odd fractional parts, or trailing text.
	if len(s) >= 10 {
		if t, err := time.Parse("2006-01-02", s[:10]); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
