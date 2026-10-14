package checks

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"domaindoctor/internal/nodes"
	"domaindoctor/internal/probe"
)

// cannedProber returns fixed responses.
type cannedProber struct {
	probe *probe.ProbeResponse
	http  *probe.HTTPResponse
	err   error
}

func (c *cannedProber) Health(context.Context) error { return c.err }
func (c *cannedProber) Probe(context.Context, probe.ProbeRequest) (*probe.ProbeResponse, error) {
	return c.probe, c.err
}
func (c *cannedProber) HTTP(_ context.Context, req probe.HTTPRequest) (*probe.HTTPResponse, error) {
	return c.http, c.err
}
func (c *cannedProber) Traceroute(context.Context, netip.Addr, int, func(string)) error { return c.err }

func node(id string, p probe.Prober) *nodes.Node {
	return &nodes.Node{ID: id, Name: id, Location: id, P: p}
}

func ipProbe(ip string, recv int, p80, p443 string) probe.IPProbe {
	r := probe.IPProbe{IP: netip.MustParseAddr(ip), TCP: []probe.TCPResult{{Port: 80, Status: p80}, {Port: 443, Status: p443}}}
	if recv >= 0 {
		r.Ping = &probe.PingResult{Sent: 4, Received: recv, Loss: float64(4-recv) * 25, RTTAvg: 10}
	} else {
		r.PingError = "ping not available"
	}
	return r
}

func reachState() *State {
	return &State{Domain: "example.com", Apex: "example.com",
		ApexV4: []netip.Addr{netip.MustParseAddr("5.0.0.1")}, ApexV6: []netip.Addr{netip.MustParseAddr("2a00::1")}}
}

func TestReach(t *testing.T) {
	ok := &probe.ProbeResponse{Results: []probe.IPProbe{ipProbe("5.0.0.1", 4, "open", "open"), ipProbe("2a00::1", 4, "open", "open")}}
	icmpBlocked := &probe.ProbeResponse{Results: []probe.IPProbe{ipProbe("5.0.0.1", 0, "open", "open"), ipProbe("2a00::1", 0, "open", "open")}}
	down := &probe.ProbeResponse{Results: []probe.IPProbe{ipProbe("5.0.0.1", 0, "filtered", "filtered"), ipProbe("2a00::1", 0, "filtered", "filtered")}}
	v6bad := &probe.ProbeResponse{Results: []probe.IPProbe{ipProbe("5.0.0.1", 4, "open", "open"), ipProbe("2a00::1", 0, "filtered", "filtered")}}

	noV6 := &probe.ProbeResponse{Results: []probe.IPProbe{ipProbe("5.0.0.1", 4, "open", "open"), {IP: netip.MustParseAddr("2a00::1"), Skipped: "this node has no IPv6 connectivity"}}}
	cases := []struct {
		name     string
		ns       []*nodes.Node
		status   Status
		blocking bool
		codes    []string
	}{
		{"healthy", []*nodes.Node{node("a", &cannedProber{probe: ok}), node("b", &cannedProber{probe: ok})}, OK, false, nil},
		{"icmp blocked", []*nodes.Node{node("a", &cannedProber{probe: icmpBlocked})}, OK, false, []string{"reach.icmp_blocked"}},
		{"down", []*nodes.Node{node("a", &cannedProber{probe: down}), node("b", &cannedProber{probe: down})}, FAIL, true, []string{"reach.down_all"}},
		{"partial", []*nodes.Node{node("a", &cannedProber{probe: ok}), node("b", &cannedProber{probe: down})}, WARN, false, []string{"reach.partial"}},
		{"v6 broken", []*nodes.Node{node("a", &cannedProber{probe: v6bad})}, WARN, false, []string{"reach.v6_broken"}},
		// A node without IPv6 must not make the target look IPv6-broken.
		{"node without ipv6", []*nodes.Node{node("a", &cannedProber{probe: noV6})}, OK, false, nil},
		{"agent error", []*nodes.Node{node("a", &cannedProber{err: errors.New("x")})}, WARN, false, []string{"reach.no_data"}},
	}
	for _, c := range cases {
		r := Reach(context.Background(), reachState(), c.ns)
		if r.Status != c.status || r.Blocking != c.blocking {
			t.Errorf("%s: status %s blocking %v [%s]", c.name, r.Status, r.Blocking, codes(r))
		}
		for _, code := range c.codes {
			if !r.Has(code) {
				t.Errorf("%s: missing %s in [%s]", c.name, code, codes(r))
			}
		}
	}
	if r := Reach(context.Background(), &State{Domain: "x.com"}, nil); r.Status != SKIPPED {
		t.Error("no targets should skip")
	}
}

func goodTLS(now time.Time) *probe.TLSInfo {
	return &probe.TLSInfo{Version: "TLS 1.3", Subject: "example.com", Issuer: "R3", NotBefore: now.Add(-24 * time.Hour),
		NotAfter: now.Add(60 * 24 * time.Hour), DaysLeft: 60, SANs: []string{"example.com", "www.example.com"}, HostnameMatch: true, ChainValid: true}
}

func hop(url string, status int, loc string, tls *probe.TLSInfo, hdr map[string]string) probe.Hop {
	return probe.Hop{URL: url, Status: status, StatusText: "x", Location: loc, TLS: tls, Headers: hdr, Timing: probe.Timing{TotalMS: 50}}
}

var secureHdr = map[string]string{"Strict-Transport-Security": "max-age=1", "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
	"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}

func webState() *State {
	return &State{Domain: "example.com", Apex: "example.com", ApexV4: []netip.Addr{netip.MustParseAddr("5.0.0.1")},
		WWWV4: []netip.Addr{netip.MustParseAddr("5.0.0.1")}, WWWExists: true}
}

func healthyChains(now time.Time) []probe.Chain {
	return []probe.Chain{
		{Start: "http://example.com/", Hops: []probe.Hop{hop("http://example.com/", 301, "https://example.com/", nil, nil), hop("https://example.com/", 200, "", goodTLS(now), secureHdr)}},
		{Start: "https://example.com/", Hops: []probe.Hop{hop("https://example.com/", 200, "", goodTLS(now), secureHdr)}},
		{Start: "http://www.example.com/", Hops: []probe.Hop{hop("http://www.example.com/", 301, "https://example.com/", nil, nil), hop("https://example.com/", 200, "", goodTLS(now), secureHdr)}},
		{Start: "https://www.example.com/", Hops: []probe.Hop{hop("https://www.example.com/", 301, "https://example.com/", goodTLS(now), nil), hop("https://example.com/", 200, "", goodTLS(now), secureHdr)}},
	}
}

func TestWebHealthy(t *testing.T) {
	now := testNow
	r := Web(context.Background(), webState(), []*nodes.Node{node("a", &cannedProber{http: &probe.HTTPResponse{Chains: healthyChains(now)}})}, now)
	if r.Status != OK {
		t.Fatalf("status %s [%s] %+v", r.Status, codes(r), r.Findings)
	}
}

func TestWebProblems(t *testing.T) {
	now := testNow
	expired := goodTLS(now)
	expired.NotAfter, expired.DaysLeft, expired.ChainValid, expired.ChainError = now.Add(-48*time.Hour), -2, false, "certificate expired or not yet valid"
	mismatch := goodTLS(now)
	mismatch.HostnameMatch = false

	chains := []probe.Chain{
		// http stays on http
		{Start: "http://example.com/", Hops: []probe.Hop{hop("http://example.com/", 200, "", nil, nil)}},
		// https works but cert expired, no HSTS
		{Start: "https://example.com/", Hops: []probe.Hop{hop("https://example.com/", 200, "", expired, map[string]string{})}},
		// www loops
		{Start: "http://www.example.com/", Loop: true, Hops: []probe.Hop{hop("http://www.example.com/", 302, "http://www.example.com/a", nil, nil), hop("http://www.example.com/a", 302, "http://www.example.com/", nil, nil)}},
		// www https: hostname mismatch, 502
		{Start: "https://www.example.com/", Hops: []probe.Hop{hop("https://www.example.com/", 502, "", mismatch, nil)}},
	}
	r := Web(context.Background(), webState(), []*nodes.Node{node("a", &cannedProber{http: &probe.HTTPResponse{Chains: chains}})}, now)
	wantCodes(t, r, "web.no_https_redirect", "tls.expired", "web.no_hsts", "web.redirect_loop", "tls.hostname_mismatch", "web.5xx", "web.apex_www_inconsistent")
}

func TestWebDownAndCDN(t *testing.T) {
	now := testNow
	refused := func(u string) probe.Chain {
		return probe.Chain{Start: u, Hops: []probe.Hop{{URL: u, ErrorKind: "refused", Error: "connection refused"}}}
	}
	cdn := probe.Hop{URL: "https://example.com/", Status: 522, CDN: "Cloudflare", CDNError: true}
	st := webState()
	st.WWWV4, st.WWWExists = nil, false
	r := Web(context.Background(), st, []*nodes.Node{node("a", &cannedProber{http: &probe.HTTPResponse{Chains: []probe.Chain{
		refused("http://example.com/"), {Start: "https://example.com/", Hops: []probe.Hop{cdn}},
	}}})}, now)
	wantCodes(t, r, "web.refused", "web.cdn_error")
	if r.Status != FAIL {
		t.Fatalf("status %s", r.Status)
	}
	for _, f := range r.Findings {
		if f.Code == "web.cdn_error" && f.Severity != Critical {
			t.Fatal("cdn error on the only working URL should be critical")
		}
	}
}

func TestWebPartialAcrossNodes(t *testing.T) {
	now := testNow
	bad := []probe.Chain{}
	for _, c := range healthyChains(now) {
		bad = append(bad, probe.Chain{Start: c.Start, Hops: []probe.Hop{{URL: c.Start, ErrorKind: "timeout"}}})
	}
	r := Web(context.Background(), webState(), []*nodes.Node{
		node("a", &cannedProber{http: &probe.HTTPResponse{Chains: healthyChains(now)}}),
		node("b", &cannedProber{http: &probe.HTTPResponse{Chains: bad}}),
	}, now)
	wantCodes(t, r, "web.partial")
}
