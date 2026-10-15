package probe

import (
	"compress/gzip"
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

// wafSite: blocks curl, answers HEAD with 405, serves gzip when asked.
func wafSite(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.UserAgent(), "curl/") {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(403)
		w.Write([]byte("<center>nginx</center> blocked"))
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(405)
		return
	}
	w.Header().Set("Server", "nginx")
	w.Header().Add("Set-Cookie", "sid=secret-value; HttpOnly")
	w.Header().Set("Content-Type", "text/html")
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte("<html>hello " + r.Proto + "</html>"))
		gz.Close()
		return
	}
	w.Write([]byte("<html>hello " + r.Proto + "</html>"))
}

func newTLSLocal(t *testing.T, h http.HandlerFunc) (*Local, string) {
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	u, _ := url.Parse(srv.URL)
	var port int
	for _, c := range u.Port() {
		port = port*10 + int(c-'0')
	}
	l := &Local{AllowLoopback: true, PortMap: map[int]int{443: port}, HTTPProber: HTTPProber{Roots: pool, Timeout: 3 * time.Second}}
	return l, "https://example.com/"
}

func TestMatrixVariants(t *testing.T) {
	l, u := newTLSLocal(t, wafSite)
	pin := map[string][]netip.Addr{"example.com": {netip.MustParseAddr("127.0.0.1")}}
	specs := []ReqSpec{
		{ID: "browser", URL: u, Method: "GET", UA: "browser", Sample: true},
		{ID: "curl", URL: u, Method: "GET", UA: "curl", Sample: true},
		{ID: "head", URL: u, Method: "HEAD", UA: "browser"},
		{ID: "h1", URL: u, Method: "GET", UA: "browser", Proto: "h1", Sample: true},
		{ID: "h2", URL: u, Method: "GET", UA: "browser", Proto: "h2", Sample: true},
		{ID: "gzip", URL: u, Method: "GET", UA: "browser", Compress: boolp(true), Sample: true},
		{ID: "identity", URL: u, Method: "GET", UA: "browser", Compress: boolp(false), Sample: true},
	}
	resp, err := l.HTTP(context.Background(), HTTPRequest{Pinned: pin, Specs: specs})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Hop{}
	for _, r := range resp.Results {
		got[r.Spec.ID] = *r.Chain.Final()
	}
	if got["browser"].Status != 200 || got["curl"].Status != 403 || got["head"].Status != 405 || got["head"].Method != "HEAD" {
		t.Fatalf("statuses: browser %d curl %d head %d", got["browser"].Status, got["curl"].Status, got["head"].Status)
	}
	if got["h1"].Proto != "HTTP/1.1" || got["h2"].Proto != "HTTP/2.0" {
		t.Fatalf("protos h1=%s h2=%s", got["h1"].Proto, got["h2"].Proto)
	}
	if got["gzip"].ContentEncoding != "gzip" || !strings.Contains(got["gzip"].BodySample, "hello") {
		t.Fatalf("gzip: enc=%q sample=%q", got["gzip"].ContentEncoding, got["gzip"].BodySample)
	}
	if got["identity"].ContentEncoding != "" {
		t.Fatalf("identity got encoding %q", got["identity"].ContentEncoding)
	}
	b := got["browser"]
	if len(b.Cookies) != 1 || b.Cookies[0] != "sid" || b.AllHeaders["server"][0] != "nginx" {
		t.Fatalf("cookies %v headers %v", b.Cookies, b.AllHeaders)
	}
	if _, leaked := b.AllHeaders["set-cookie"]; leaked {
		t.Fatal("Set-Cookie values must not be returned")
	}
	if got["head"].BodySample != "" {
		t.Fatal("unsampled request kept a body")
	}
}

func TestMatrixPolicy(t *testing.T) {
	l := &Local{}
	ctx := context.Background()
	u := "https://example.com/"
	bad := []ReqSpec{
		{URL: u, Method: "POST"},
		{URL: u, Method: "GET", UA: "sqlmap/1.0"},
		{URL: u, Method: "GET", Proto: "h3"},
		{URL: "ftp://example.com/", Method: "GET"},
		{URL: u, Method: "GET", OriginIP: netip.MustParseAddr("10.0.0.5")},
		{URL: u, Method: "GET", OriginIP: netip.MustParseAddr("169.254.169.254")},
		{URL: u, Method: "GET", OriginIP: netip.MustParseAddr("127.0.0.1")},
	}
	for _, s := range bad {
		if _, err := l.HTTP(ctx, HTTPRequest{Specs: []ReqSpec{s}}); err == nil {
			t.Errorf("accepted %+v", s)
		}
	}
	many := make([]ReqSpec, MaxSpecs+1)
	for i := range many {
		many[i] = ReqSpec{URL: u, Method: "GET"}
	}
	if _, err := l.HTTP(ctx, HTTPRequest{Specs: many}); err == nil {
		t.Error("accepted too many specs")
	}
}

// TestOriginDirectPinsOnlyStartHost: the origin IP replaces DNS for the start
// host; redirects to another host are resolved independently.
func TestOriginDirectPinsOnlyStartHost(t *testing.T) {
	var hosts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hosts = append(hosts, r.Host)
		if r.Host == "example.com" {
			http.Redirect(w, r, "http://www.example.com/", 301)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	p := HTTPProber{AllowLoopback: true, PortMap: map[string]string{"80": u.Port()}, Timeout: 2 * time.Second}
	pin := map[string][]netip.Addr{"www.example.com": {netip.MustParseAddr("127.0.0.1")}}
	ch := p.chain(context.Background(), "http://example.com/", pin, 10, HopOpts{OriginIP: netip.MustParseAddr("127.0.0.1")})
	if len(ch.Hops) != 2 || ch.Final().Status != 200 {
		t.Fatalf("chain %+v", ch)
	}
	if len(hosts) != 2 || hosts[0] != "example.com" || hosts[1] != "www.example.com" {
		t.Fatalf("Host headers %v (SNI/Host must stay the real name)", hosts)
	}
}

func TestSampleBudget(t *testing.T) {
	big := strings.Repeat("x", 600<<10)
	rs := []SpecResult{
		{Chain: Chain{Hops: []Hop{{BodySample: "drop me"}, {BodySample: big}}}},
		{Chain: Chain{Hops: []Hop{{BodySample: big}}}},
	}
	enforceSampleBudget(rs, 1<<20)
	if rs[0].Chain.Hops[0].BodySample != "" {
		t.Fatal("intermediate hop sample kept")
	}
	total := len(rs[0].Chain.Hops[1].BodySample) + len(rs[1].Chain.Hops[0].BodySample)
	if total > 1<<20 {
		t.Fatalf("budget exceeded: %d", total)
	}
}
