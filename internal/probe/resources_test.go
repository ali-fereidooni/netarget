package probe

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testPage = `<!doctype html><html><head>
<link rel="stylesheet" href="/style.css">
<link rel="icon" href="/favicon.ico">
<script src="/app.js"></script>
<script src="/slow.js"></script>
</head><body>
<img src="/missing.png">
<img src="http://example.com/insecure.png">
<img srcset="/a.png 1x, /b.png 2x">
<img src="data:image/png;base64,AAAA">
</body></html>`

func assetSite(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Host == "cdn.example.net" || strings.HasPrefix(r.Host, "cdn.example.net:"):
		// Font on another origin without Access-Control-Allow-Origin.
		w.Header().Set("Content-Type", "font/woff2")
		w.Header().Set("Cache-Control", "public, max-age=31536000")
		w.Write([]byte("wOF2"))
		return
	}
	switch r.URL.Path {
	case "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(testPage))
	case "/style.css":
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write([]byte(`@font-face{src:url("https://cdn.example.net/f.woff2")}` + strings.Repeat("/* pad */", 300)))
	case "/app.js":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Write([]byte("console.log(1)"))
	case "/slow.js":
		time.Sleep(2200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Write([]byte("1"))
	case "/favicon.ico", "/a.png", "/insecure.png":
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Write([]byte("png"))
	default:
		http.NotFound(w, r)
	}
}

func portOf(raw string) string { u, _ := url.Parse(raw); return u.Port() }

func TestCheckResources(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(assetSite))
	defer tlsSrv.Close()
	plain := httptest.NewServer(http.HandlerFunc(assetSite))
	defer plain.Close()
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	p := HTTPProber{AllowLoopback: true, Roots: pool, Timeout: 5 * time.Second,
		PortMap: map[string]string{"443": portOf(tlsSrv.URL), "80": portOf(plain.URL)}}
	lo := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	pin := map[string][]netip.Addr{"example.com": lo, "cdn.example.net": lo}

	resp := p.CheckResources(context.Background(), ResourceRequest{PageURL: "https://example.com/", Pinned: pin})
	if resp.Page.Status != 200 || resp.Page.Found < 7 {
		t.Fatalf("page %+v", resp.Page)
	}
	by := map[string]Resource{}
	for _, r := range resp.Resources {
		by[strings.TrimPrefix(strings.TrimPrefix(r.URL, "https://example.com"), "http://example.com")] = r
	}
	want := map[string][]string{
		"/missing.png":                    {"failed"},
		"/insecure.png":                   {"mixed_content"},
		"/app.js":                         {"wrong_mime", "blocked_mime"},
		"/slow.js":                        {"slow"},
		"/style.css":                      {"uncompressed"},
		"https://cdn.example.net/f.woff2": {"cors"},
	}
	for path, issues := range want {
		r, ok := by[path]
		if !ok {
			t.Errorf("%s not checked; got %v", path, keys(by))
			continue
		}
		for _, i := range issues {
			if !contains(r.Issues, i) {
				t.Errorf("%s: missing issue %s (got %v)", path, i, r.Issues)
			}
		}
	}
	if r := by["/a.png"]; len(r.Issues) != 0 {
		t.Errorf("healthy image flagged: %v", r.Issues)
	}
	if !by["https://cdn.example.net/f.woff2"].ThirdParty || by["/app.js"].ThirdParty {
		t.Error("third-party classification wrong")
	}
	if s := resp.Summary(); s["failed"] != 1 || s["mixed_content"] != 1 {
		t.Errorf("summary %v", s)
	}

	// Cap.
	capped := p.CheckResources(context.Background(), ResourceRequest{PageURL: "https://example.com/", Pinned: pin, Max: 2})
	if len(capped.Resources) != 2 || capped.Page.Checked != 2 {
		t.Fatalf("cap: %d resources", len(capped.Resources))
	}
}

// TestResourceToPrivateHostIsBlocked: a page may reference internal hosts;
// the production prober reports them as blocked and never connects.
func TestResourceToPrivateHostIsBlocked(t *testing.T) {
	p := HTTPProber{Timeout: time.Second}
	page, _ := url.Parse("https://example.com/")
	for _, u := range []string{"http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/x.js", "http://127.0.0.1:8082/api/nodes"} {
		r := p.checkOne(context.Background(), page, ref{url: u, kind: "script"}, nil)
		if !contains(r.Issues, "blocked") && !contains(r.Issues, "failed") {
			t.Errorf("%s: %+v", u, r)
		}
		if r.Status != 0 {
			t.Errorf("%s: got a response (%d) — must never be fetched", u, r.Status)
		}
	}
}

func TestExtractRefs(t *testing.T) {
	base, _ := url.Parse("https://example.com/blog/post")
	refs := extractRefs(base, `<link rel="preload" as="font" href="../f.woff2"><link rel="stylesheet" href="//cdn.x.com/a.css" crossorigin>
<script src="javascript:alert(1)"></script><a href="/page">x</a><img src="/i.png#frag"><img src="/i.png">`)
	got := []string{}
	for _, r := range refs {
		got = append(got, fmt.Sprintf("%s:%s:%v", r.kind, r.url, r.crossorigin))
	}
	want := "font:https://example.com/f.woff2:true stylesheet:https://cdn.x.com/a.css:true image:https://example.com/i.png:false"
	if strings.Join(got, " ") != want {
		t.Fatalf("got  %s\nwant %s", strings.Join(got, " "), want)
	}
}

func TestLocalResourcesPolicy(t *testing.T) {
	l := &Local{}
	for _, req := range []ResourceRequest{
		{PageURL: "file:///etc/passwd"},
		{PageURL: "https://example.com/", Max: MaxResources + 1},
		{PageURL: "https://example.com/", Pinned: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("10.1.1.1")}}},
	} {
		if _, err := l.Resources(context.Background(), req); err == nil {
			t.Errorf("accepted %+v", req)
		}
	}
}

func keys(m map[string]Resource) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
