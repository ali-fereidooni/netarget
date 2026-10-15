// Package whois is the port-43 fallback for registration data when a TLD
// has no RDAP service.
package whois

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"domaindoctor/internal/rdap"
	"domaindoctor/internal/safenet"
)

type Client struct {
	// Dial connects to a WHOIS server ("host:43"). Defaults to the safenet dialer.
	Dial       func(ctx context.Context, network, addr string) (net.Conn, error)
	IANAServer string
	Timeout    time.Duration
	// ServerOverride, if set, is used instead of the IANA referral (tests).
	ServerOverride string
}

func New() *Client {
	return &Client{Dial: safenet.SafeDialContext(5 * time.Second), IANAServer: "whois.iana.org:43", Timeout: 10 * time.Second}
}

// Query sends q to server and returns the (size-limited) response.
func (c *Client) Query(ctx context.Context, server, q string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	conn, err := c.Dial(ctx, "tcp", server)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := io.WriteString(conn, q+"\r\n"); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(conn, 256<<10))
	if err != nil && len(b) == 0 {
		return "", err
	}
	return string(b), nil
}

// knownServers are registry WHOIS servers used without asking IANA. Some
// hosts cannot reach whois.iana.org at all (the beta master times out on it),
// and for TLDs without RDAP that referral was the only way to the registry.
var knownServers = map[string]string{
	"ir": "whois.nic.ir:43", // IRNIC; no RDAP service
}

// Server finds the authoritative WHOIS server for the TLD: a known server,
// otherwise the IANA referral.
func (c *Client) Server(ctx context.Context, domain string) (string, error) {
	if c.ServerOverride != "" {
		return c.ServerOverride, nil
	}
	labels := strings.Split(domain, ".")
	tld := labels[len(labels)-1]
	if s, ok := knownServers[tld]; ok {
		return s, nil
	}
	resp, err := c.Query(ctx, c.IANAServer, tld)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(resp, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "whois") {
			if v = strings.TrimSpace(v); v != "" {
				return net.JoinHostPort(v, "43"), nil
			}
		}
	}
	return "", errors.New("no WHOIS server for this TLD")
}

// Lookup returns registration data, or rdap.ErrNotFound when the registry
// says the domain is not registered.
func (c *Client) Lookup(ctx context.Context, domain string) (*rdap.Info, error) {
	server, err := c.Server(ctx, domain)
	if err != nil {
		return nil, err
	}
	q := domain
	if strings.HasPrefix(server, "whois.verisign-grs.com") {
		q = "domain " + domain
	}
	resp, err := c.Query(ctx, server, q)
	if err != nil {
		return nil, fmt.Errorf("WHOIS query failed: %w", err)
	}
	info, err := Parse(resp)
	if err != nil {
		return nil, err
	}
	info.Server, _, _ = net.SplitHostPort(server)
	return info, nil
}

var notFound = []string{
	"no match for", "not found", "no entries found", "no data found", "status: free",
	"status:\tfree", "status: available", "is available for registration", "no object found",
	"domain not found", "object does not exist", "no such domain",
}

var (
	registrarKeys = []string{"registrar", "sponsoring registrar", "registrar name", "registrar organization"}
	createdKeys   = []string{"creation date", "created", "created on", "registered on", "registration time", "domain registration date", "created date"}
	expiresKeys   = []string{"registry expiry date", "registrar registration expiration date", "expiration date", "expiry date", "expires", "expire", "paid-till", "expire-date", "expiration-date", "expires on", "expiration time", "valid until"}
	updatedKeys   = []string{"updated date", "last updated", "last-update", "last-updated", "changed", "last modified", "modified"}
	statusKeys    = []string{"domain status", "status", "state"}
	nsKeys        = []string{"name server", "nserver", "nameserver", "name servers"}
)

func keyIn(k string, keys []string) bool {
	for _, x := range keys {
		if k == x {
			return true
		}
	}
	return false
}

// Parse extracts registration data from a WHOIS text response.
func Parse(resp string) (*rdap.Info, error) {
	low := strings.ToLower(resp)
	info := &rdap.Info{Source: "whois", Status: []string{}}
	found := false
	sc := bufio.NewScanner(strings.NewReader(resp))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">>>") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch {
		case keyIn(k, registrarKeys) && info.Registrar == "":
			info.Registrar, found = v, true
		case keyIn(k, createdKeys) && info.Created == nil:
			if t, ok := rdap.ParseDate(v); ok {
				info.Created, found = &t, true
			}
		case keyIn(k, expiresKeys) && info.Expires == nil:
			if t, ok := rdap.ParseDate(v); ok {
				info.Expires, found = &t, true
			}
		case keyIn(k, updatedKeys) && info.Updated == nil:
			if t, ok := rdap.ParseDate(v); ok {
				info.Updated = &t
			}
		case keyIn(k, statusKeys):
			for _, s := range strings.Split(v, ",") {
				if n := rdap.NormalizeStatus(s); n != "" {
					info.Status = append(info.Status, n)
				}
			}
			found = true
		case keyIn(k, nsKeys):
			info.Nameservers = append(info.Nameservers, strings.ToLower(strings.Fields(v)[0]))
			found = true
		}
	}
	if !found {
		for _, p := range notFound {
			if strings.Contains(low, p) {
				return nil, rdap.ErrNotFound
			}
		}
		return nil, errors.New("unrecognized WHOIS response")
	}
	return info, nil
}
