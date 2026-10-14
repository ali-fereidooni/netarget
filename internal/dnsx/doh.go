package dnsx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"

	"domaindoctor/internal/safenet"
)

var defaultDoHClient = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		Proxy:               nil,
		DialContext:         safenet.SafeDialContext(5 * time.Second),
		TLSHandshakeTimeout: 5 * time.Second,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
		ForceAttemptHTTP2:   true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// exchangeDoH sends m as an RFC 8484 POST (application/dns-message).
func (c *Client) exchangeDoH(ctx context.Context, m *dns.Msg, endpoint string) (*dns.Msg, time.Duration, error) {
	q := m.Copy()
	q.Id = 0 // RFC 8484 §4.1: use ID 0 for cache friendliness
	b, err := q.Pack()
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	hc := c.DoHHTTP
	if hc == nil {
		hc = defaultDoHClient
	}
	start := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("HTTP %d from DoH resolver", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, 0, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, 0, fmt.Errorf("invalid DoH response")
	}
	r.Id = m.Id
	r.Answer, r.Ns, r.Extra = capRRs(r.Answer), capRRs(r.Ns), capRRs(r.Extra)
	return r, time.Since(start), nil
}

// ProbeDirect reports whether root servers answer over port 53.
func (c *Client) ProbeDirect(ctx context.Context) bool {
	for i, root := range c.Roots {
		if i >= 3 {
			break
		}
		if _, _, err := c.Query(ctx, root, ".", dns.TypeSOA, false, false); err == nil {
			return true
		}
	}
	return false
}

// ProbeDoH reports whether at least one resolver answers over HTTPS.
func (c *Client) ProbeDoH(ctx context.Context) bool {
	saved := c.DoH
	c.DoH = true
	defer func() { c.DoH = saved }()
	for _, r := range c.Resolvers {
		if _, _, err := c.Query(ctx, r.IP, ".", dns.TypeSOA, true, false); err == nil {
			return true
		}
	}
	return false
}
