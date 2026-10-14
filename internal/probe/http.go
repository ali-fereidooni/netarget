package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"domaindoctor/internal/safenet"
)

// HTTPProber runs redirect chains. Zero value is production-safe.
type HTTPProber struct {
	Timeout       time.Duration
	AllowLoopback bool              // tests only
	PortMap       map[string]string // tests/demo only (with AllowLoopback): "80" -> real port
	Roots         *x509.CertPool    // nil = system roots
	Now           func() time.Time
}

// SecurityHeaders are reported when present.
var SecurityHeaders = []string{
	"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
	"X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
}

var infoHeaders = []string{"Server", "Via", "CF-Ray", "X-Amz-Cf-Id", "X-Served-By", "X-Cache", "Content-Type"}

const maxHops = 10

// Run follows each start URL's redirect chain manually (never automatically),
// re-resolving and re-validating every new host through safenet.
func (p *HTTPProber) Run(ctx context.Context, req HTTPRequest) *HTTPResponse {
	resp := &HTTPResponse{Chains: make([]Chain, 0, len(req.URLs))}
	limit := req.MaxHops
	if limit <= 0 || limit > maxHops {
		limit = maxHops
	}
	for _, start := range req.URLs {
		resp.Chains = append(resp.Chains, p.chain(ctx, start, req.Pinned, limit))
	}
	return resp
}

func (p *HTTPProber) chain(ctx context.Context, start string, pinned map[string][]netip.Addr, limit int) Chain {
	ch := Chain{Start: start}
	seen := map[string]bool{}
	cur := start
	for i := 0; i < limit; i++ {
		if seen[cur] {
			ch.Loop = true
			return ch
		}
		seen[cur] = true
		hop := p.hop(ctx, cur, pinned)
		ch.Hops = append(ch.Hops, hop)
		if hop.ErrorKind != "" || hop.Location == "" || hop.Status < 300 || hop.Status > 399 {
			return ch
		}
		base, _ := url.Parse(cur)
		next, err := base.Parse(hop.Location)
		if err != nil {
			ch.Hops[len(ch.Hops)-1].ErrorKind, ch.Hops[len(ch.Hops)-1].Error = "bad_url", "invalid Location header"
			return ch
		}
		next.Fragment = ""
		cur = next.String()
	}
	// Ran out of hops while still redirecting.
	ch.Loop = true
	return ch
}

func (p *HTTPProber) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return 10 * time.Second
}

func (p *HTTPProber) hop(ctx context.Context, rawURL string, pinned map[string][]netip.Addr) (h Hop) {
	h.URL = rawURL
	fail := func(kind, msg string) Hop { h.ErrorKind, h.Error = kind, msg; return h }
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fail("bad_url", "unsupported URL")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	if pn, _ := strconv.Atoi(port); !p.AllowLoopback && !(pn == 80 || pn == 443 || pn == 8080 || pn == 8443) {
		return fail("bad_url", "redirect to non-standard port "+port+" not followed")
	}

	start := time.Now()
	ips := pinned[host]
	if len(ips) == 0 {
		var err error
		if p.AllowLoopback {
			ips, err = resolveAny(ctx, host)
		} else {
			ips, err = safenet.Resolve(ctx, nil, host)
		}
		h.Timing.DNSms = ms(time.Since(start))
		if err != nil {
			return fail(ErrorKind(err), "could not resolve "+host)
		}
	} else if !p.AllowLoopback {
		if err := safenet.CheckAddrs(ips); err != nil {
			return fail("blocked", "target address not allowed")
		}
	}

	var remote string
	var connStart, connDone, tlsStart, tlsDone, firstByte time.Time
	dial := safenet.PinnedDialContext(ips, 5*time.Second)
	if p.AllowLoopback {
		dial = loopbackDial(ips, p.PortMap, 5*time.Second)
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	var tlsInfo *TLSInfo
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			connStart = time.Now()
			c, err := dial(ctx, network, addr)
			connDone = time.Now()
			if err == nil {
				remote = c.RemoteAddr().String()
			}
			return c, err
		},
		TLSClientConfig: &tls.Config{
			ServerName:         host,
			MinVersion:         tls.VersionTLS10,
			InsecureSkipVerify: true, // we verify ourselves in VerifyConnection to describe failures
			VerifyConnection: func(cs tls.ConnectionState) error {
				tlsInfo = InspectTLS(cs, host, p.Roots, now())
				return nil
			},
		},
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    p.timeout(),
		ResponseHeaderTimeout:  p.timeout(),
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer tr.CloseIdleConnections()
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { tlsDone = time.Now() },
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}
	rctx, cancel := context.WithTimeout(httptrace.WithClientTrace(ctx, trace), p.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fail("bad_url", "invalid URL")
	}
	req.Header.Set("User-Agent", "DomainDoctor/1.0 (+web check)")
	req.Header.Set("Accept", "text/html,*/*")
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if !connStart.IsZero() && !connDone.IsZero() {
		h.Timing.ConnectMS = ms(connDone.Sub(connStart))
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		h.Timing.TLSms = ms(tlsDone.Sub(tlsStart))
	}
	h.TLS = tlsInfo
	if remote != "" {
		if ap, err := netip.ParseAddrPort(remote); err == nil {
			h.IP = ap.Addr().Unmap().String()
		}
	}
	if err != nil {
		h.Timing.TotalMS = ms(time.Since(start))
		kind := ErrorKind(err)
		return fail(kind, describe(kind))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if !firstByte.IsZero() {
		h.Timing.TTFBms = ms(firstByte.Sub(start))
	}
	h.Timing.TotalMS = ms(time.Since(start))
	h.Status = resp.StatusCode
	h.StatusText = http.StatusText(resp.StatusCode)
	h.Location = resp.Header.Get("Location")
	h.Server = resp.Header.Get("Server")
	h.Headers = map[string]string{}
	for _, k := range append(append([]string{}, SecurityHeaders...), infoHeaders...) {
		if v := resp.Header.Get(k); v != "" {
			if len(v) > 300 {
				v = v[:300] + "…"
			}
			h.Headers[k] = v
		}
	}
	h.CDN, h.CDNError = detectCDN(resp, body)
	return h
}

// detectCDN identifies the CDN and whether the response is a CDN-generated error page.
func detectCDN(resp *http.Response, body []byte) (string, bool) {
	b := strings.ToLower(string(body))
	server := strings.ToLower(resp.Header.Get("Server"))
	switch {
	case resp.Header.Get("CF-Ray") != "" || server == "cloudflare":
		return "Cloudflare", resp.StatusCode >= 520 && resp.StatusCode <= 530 ||
			(resp.StatusCode >= 500 && strings.Contains(b, "cloudflare") && strings.Contains(b, "ray id"))
	case resp.Header.Get("X-Amz-Cf-Id") != "" || strings.Contains(strings.ToLower(resp.Header.Get("Via")), "cloudfront"):
		return "CloudFront", resp.StatusCode >= 500 && strings.Contains(b, "generated by cloudfront")
	case strings.HasPrefix(server, "akamai") || strings.Contains(b, "reference&#32;&#35;") || strings.Contains(server, "akamaighost"):
		return "Akamai", resp.StatusCode >= 500
	case resp.Header.Get("X-Served-By") != "" && strings.Contains(strings.ToLower(resp.Header.Get("Via")), "varnish"):
		return "Fastly", resp.StatusCode >= 500 && strings.Contains(b, "fastly")
	}
	return "", false
}

func describe(kind string) string {
	switch kind {
	case "timeout":
		return "connection or response timed out"
	case "refused":
		return "connection refused (nothing listening on the port)"
	case "reset":
		return "connection reset by the server"
	case "tls_handshake":
		return "TLS handshake failed"
	case "dns":
		return "host name could not be resolved"
	case "blocked":
		return "target address not allowed"
	case "unreachable":
		return "network unreachable"
	}
	return "request failed"
}

func resolveAny(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// loopbackDial is the test-only pinned dialer without the safenet guard.
func loopbackDial(ips []netip.Addr, portMap map[string]string, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if p, ok := portMap[port]; ok {
			port = p
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no ips")
		}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
}
