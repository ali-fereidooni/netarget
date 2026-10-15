package checks

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"domaindoctor/internal/nodes"
	"domaindoctor/internal/probe"
)

// siteProber answers each matrix spec with fn(spec) — a fake agent.
type siteProber struct {
	fn  func(s probe.ReqSpec) probe.Chain
	res *probe.ResourceResponse
}

func (p *siteProber) Health(context.Context) error { return nil }
func (p *siteProber) Probe(context.Context, probe.ProbeRequest) (*probe.ProbeResponse, error) {
	return nil, nil
}
func (p *siteProber) Traceroute(context.Context, netip.Addr, int, func(string)) error { return nil }
func (p *siteProber) Resources(context.Context, probe.ResourceRequest) (*probe.ResourceResponse, error) {
	if p.res == nil {
		return &probe.ResourceResponse{}, nil
	}
	return p.res, nil
}
func (p *siteProber) HTTP(_ context.Context, req probe.HTTPRequest) (*probe.HTTPResponse, error) {
	out := &probe.HTTPResponse{}
	for _, s := range req.Specs {
		out.Results = append(out.Results, probe.SpecResult{Spec: s, Chain: p.fn(s)})
	}
	return out, nil
}

func hh(url string, status int, kv ...string) probe.Hop {
	h := probe.Hop{URL: url, Status: status, AllHeaders: map[string][]string{}, Proto: "HTTP/2.0", BodySize: 800,
		Timing: probe.Timing{TTFBms: 80, TotalMS: 120}}
	for i := 0; i+1 < len(kv); i += 2 {
		h.AllHeaders[kv[i]] = append(h.AllHeaders[kv[i]], kv[i+1])
	}
	h.Server = first(h.AllHeaders["server"])
	return h
}

func chain(hops ...probe.Hop) probe.Chain { return probe.Chain{Start: hops[0].URL, Hops: hops} }

var goodHeaders = []string{"server", "nginx", "strict-transport-security", "max-age=63072000", "content-security-policy", "default-src 'self'",
	"x-content-type-options", "nosniff", "referrer-policy", "no-referrer", "content-type", "text/html"}

func goodCert() *probe.TLSInfo {
	return &probe.TLSInfo{Version: "TLS 1.3", Subject: "example.com", Issuer: "R3", NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter: time.Now().Add(60 * 24 * time.Hour), DaysLeft: 60, SANs: []string{"example.com", "www.example.com"}, HostnameMatch: true, ChainValid: true}
}

// healthySite: http → https, www → apex, nginx, all security headers, gzip.
func healthySite(s probe.ReqSpec) probe.Chain {
	ok := hh("https://example.com/", 200, goodHeaders...)
	ok.TLS = goodCert()
	if s.Compress != nil && *s.Compress {
		ok.ContentEncoding = "gzip"
	}
	if strings.HasPrefix(s.URL, "http://") || strings.Contains(s.URL, "://www.") {
		return chain(probe.Hop{URL: s.URL, Status: 301, Location: "https://example.com/"}, ok)
	}
	return chain(ok)
}

func webStateX() *State {
	return &State{Domain: "example.com", Apex: "example.com", ApexV4: []netip.Addr{netip.MustParseAddr("5.0.0.1")},
		WWWV4: []netip.Addr{netip.MustParseAddr("5.0.0.1")}, WWWExists: true}
}

func runWeb(t *testing.T, st *State, ps ...probe.Prober) (*Result, *WebDetails) {
	t.Helper()
	var ns []*nodes.Node
	for i, p := range ps {
		ns = append(ns, &nodes.Node{ID: string(rune('a' + i)), Name: "N" + string(rune('A'+i)), Location: "x", P: p})
	}
	r := Web(context.Background(), st, ns, time.Now())
	return r, r.Details.(*WebDetails)
}

func TestWebHealthy(t *testing.T) {
	r, d := runWeb(t, webStateX(), &siteProber{fn: healthySite}, &siteProber{fn: healthySite})
	if r.Status != OK {
		t.Fatalf("status %s [%s]", r.Status, codes(r))
	}
	if d.Verdict == nil || d.Verdict.Layer != "none" || !strings.Contains(d.Verdict.Text, "loads normally") {
		t.Fatalf("verdict %+v", d.Verdict)
	}
	if s := d.Fingerprints.Primary("server"); s == nil || s.ID != "nginx" {
		t.Fatalf("server fingerprint %+v", d.Fingerprints.Server)
	}
	if len(d.Matrix) != 2*11 || len(d.Nodes) != 8 {
		t.Fatalf("matrix rows %d node rows %d", len(d.Matrix), len(d.Nodes))
	}
}

func TestWebCDN525WithOriginDirect(t *testing.T) {
	// Through Cloudflare: 525. Origin direct: HTTPS handshake fails, HTTP works.
	site := func(s probe.ReqSpec) probe.Chain {
		if s.OriginIP.IsValid() {
			if strings.HasPrefix(s.URL, "https://") {
				return chain(probe.Hop{URL: s.URL, ErrorKind: "tls_handshake"})
			}
			return chain(hh(s.URL, 200, "server", "nginx"))
		}
		h := hh(s.URL, 525, "server", "cloudflare", "cf-ray", "8a1b2c3d4e-FRA")
		h.BodySample = "SSL handshake failed | example.com | Cloudflare Ray ID: 8a1b2c3d4e"
		return chain(h)
	}
	st := webStateX()
	st.OriginIP = netip.MustParseAddr("203.0.113.10")
	r, d := runWeb(t, st, &siteProber{fn: site})
	if r.Status != FAIL || d.Verdict.RuleID != "cf.525" || d.Verdict.Layer != "tls" {
		t.Fatalf("verdict %+v [%s]", d.Verdict, codes(r))
	}
	if !strings.Contains(d.Verdict.Text, "Cloudflare") || d.Verdict.Level != "high" {
		t.Fatalf("verdict text/level %+v", d.Verdict)
	}
	if d.OriginIP != "203.0.113.10" {
		t.Fatal("origin IP not reported")
	}
	wantCodes(t, r, "load.cf.525")
	if sn := d.Verdict.Fixes[0].Snippets["nginx"]; !strings.Contains(sn, "server_name example.com") {
		t.Fatalf("snippet not rendered: %q", sn)
	}
}

func TestWebApache403Htaccess(t *testing.T) {
	site := func(s probe.ReqSpec) probe.Chain {
		h := hh(s.URL, 403, "server", "Apache/2.4.58 (Ubuntu)", "content-type", "text/html")
		h.BodySample = `<h1>Forbidden</h1><p>You don't have permission to access this resource. Server unable to read htaccess file, denying access to be safe</p><address>Apache/2.4.58 (Ubuntu) Server at example.com Port 443</address>`
		return chain(h)
	}
	r, d := runWeb(t, webStateX(), &siteProber{fn: site})
	if d.Verdict.RuleID != "http.403.apache" {
		t.Fatalf("verdict %+v [%s]", d.Verdict, codes(r))
	}
	if d.Verdict.Confidence < 0.8 {
		t.Fatalf("confidence %.2f (htaccess boost missing?)", d.Verdict.Confidence)
	}
	all := ""
	for _, f := range d.Verdict.Fixes {
		all += f.Step + strings.Join(mapValues(f.Snippets), "")
	}
	if strings.Contains(all, "777") || !strings.Contains(all, "chmod 755") {
		t.Fatalf("unsafe or missing permission advice: %s", all)
	}
	dontWant(t, r, "load.http.403.generic") // same group: only the best 403 rule is reported
}

func TestWebRedirectLoopAndMixedContent(t *testing.T) {
	loop := func(s probe.ReqSpec) probe.Chain {
		c := chain(probe.Hop{URL: "https://example.com/", Status: 301, Location: "https://www.example.com/"},
			probe.Hop{URL: "https://www.example.com/", Status: 301, Location: "https://example.com/"})
		c.Loop = true
		return c
	}
	r, d := runWeb(t, webStateX(), &siteProber{fn: loop})
	if d.Verdict.RuleID != "site.redirect-loop" || r.Status != FAIL {
		t.Fatalf("verdict %+v [%s]", d.Verdict, codes(r))
	}

	mixed := &probe.ResourceResponse{Page: probe.PageInfo{URL: "https://example.com/", Status: 200, Found: 2, Checked: 2},
		Resources: []probe.Resource{
			{URL: "http://example.com/app.js", Host: "example.com", Kind: "script", Status: 200, Issues: []string{"mixed_content"}},
			{URL: "https://example.com/a.css", Host: "example.com", Kind: "stylesheet", Status: 200},
		}}
	r, d = runWeb(t, webStateX(), &siteProber{fn: healthySite, res: mixed})
	wantCodes(t, r, "load.content.mixed")
	if d.Verdict.RuleID != "content.mixed" || r.Status != WARN {
		t.Fatalf("verdict %+v status %s", d.Verdict, r.Status)
	}
}

func TestWebRegionalAndAgentDown(t *testing.T) {
	down := func(s probe.ReqSpec) probe.Chain { return chain(probe.Hop{URL: s.URL, ErrorKind: "timeout"}) }
	r, d := runWeb(t, webStateX(), &siteProber{fn: healthySite}, &siteProber{fn: down}, &cannedProber{err: errAgent})
	wantCodes(t, r, "load.site.regional")
	unreachable := 0
	for _, n := range d.Nodes {
		if n.ErrorKind == "agent_unreachable" {
			unreachable++
		}
	}
	if unreachable == 0 {
		t.Fatal("unreachable agent not reported")
	}
}

type agentErr struct{}

func (agentErr) Error() string { return "agent unreachable" }

var errAgent = agentErr{}

func mapValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
