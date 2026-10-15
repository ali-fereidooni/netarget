package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type seen struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (s *seen) add(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, r.Clone(context.Background()))
}

func (s *seen) find(host string) []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*http.Request
	for _, r := range s.reqs {
		if strings.HasPrefix(r.Host, host) {
			out = append(out, r)
		}
	}
	return out
}

func lo() []netip.Addr { return []netip.Addr{netip.MustParseAddr("127.0.0.1")} }

// TestMatrixNoOpenProxy: a site that redirects to another site cannot use the
// matrix to read that site's page: no body/headers are kept, and spoofed
// User-Agents are not sent off-site.
func TestMatrixNoOpenProxy(t *testing.T) {
	var s seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		if strings.HasPrefix(r.Host, "evil.com") {
			http.Redirect(w, r, "http://victim.org/admin/export?x=1", http.StatusFound)
			return
		}
		w.Header().Set("X-Secret", "internal-value")
		w.Write([]byte("victim private page"))
	}))
	defer srv.Close()
	l := &Local{AllowLoopback: true, PortMap: map[int]int{80: atoi(portOf(srv.URL))}, HTTPProber: HTTPProber{Timeout: 2 * time.Second}}
	pin := map[string][]netip.Addr{"evil.com": lo(), "victim.org": lo()}
	resp, err := l.HTTP(context.Background(), HTTPRequest{Pinned: pin, Specs: []ReqSpec{
		{ID: "a", URL: "http://evil.com/", Method: "GET", UA: "googlebot", Sample: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	f := resp.Results[0].Chain.Final()
	if f.Status != 200 || f.URL != "http://victim.org/admin/export?x=1" {
		t.Fatalf("chain %+v", resp.Results[0].Chain)
	}
	if f.BodySample != "" || f.AllHeaders != nil {
		t.Fatalf("off-site response leaked: body=%q headers=%v", f.BodySample, f.AllHeaders)
	}
	if v := s.find("victim.org"); len(v) != 1 || strings.Contains(v[0].UserAgent(), "Googlebot") {
		t.Fatalf("spoofed UA sent off-site: %v", v[0].UserAgent())
	}
	if e := s.find("evil.com"); len(e) != 1 || !strings.Contains(e[0].UserAgent(), "Googlebot") {
		t.Fatal("on-site request should use the requested UA")
	}
}

func TestCredentialURLsNotFollowed(t *testing.T) {
	var s seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		if r.URL.Path == "/" {
			http.Redirect(w, r, "http://admin:hunter2@example.com/next", http.StatusFound)
			return
		}
		w.Write([]byte("x"))
	}))
	defer srv.Close()
	p := &HTTPProber{AllowLoopback: true, PortMap: map[string]string{"80": portOf(srv.URL)}, Timeout: 2 * time.Second}
	ch := p.chain(context.Background(), "http://example.com/", map[string][]netip.Addr{"example.com": lo()}, 5, HopOpts{})
	if f := ch.Final(); f.ErrorKind != "bad_url" {
		t.Fatalf("credential URL followed: %+v", f)
	}
	for _, r := range s.reqs {
		if r.Header.Get("Authorization") != "" {
			t.Fatal("credentials were sent")
		}
	}
}

func TestResourcesThirdPartyHEADAndOffSitePage(t *testing.T) {
	var s seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		switch {
		case strings.HasPrefix(r.Host, "tracker.net"):
			w.Header().Set("Content-Type", "image/gif")
			w.Header().Set("Cache-Control", "max-age=60")
		case r.URL.Path == "/moved":
			http.Redirect(w, r, "http://other.org/", http.StatusFound)
		default:
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<img src="http://tracker.net/pixel.gif?id=1%27%20OR%201=1--">`))
		}
	}))
	defer srv.Close()
	p := HTTPProber{AllowLoopback: true, PortMap: map[string]string{"80": portOf(srv.URL)}, Timeout: 2 * time.Second}
	pin := map[string][]netip.Addr{"example.com": lo(), "tracker.net": lo(), "other.org": lo()}
	resp := p.CheckResources(context.Background(), ResourceRequest{PageURL: "http://example.com/", Pinned: pin, Site: "example.com"})
	if len(resp.Resources) != 1 || !resp.Resources[0].ThirdParty {
		t.Fatalf("resources %+v", resp.Resources)
	}
	tr := s.find("tracker.net")
	if len(tr) != 1 || tr[0].Method != http.MethodHead || tr[0].URL.RawQuery != "" {
		t.Fatalf("third-party request: %+v", tr)
	}
	// A page that redirects to another site is not crawled.
	resp = p.CheckResources(context.Background(), ResourceRequest{PageURL: "http://example.com/moved", Pinned: pin, Site: "example.com"})
	if resp.Page.Skipped == "" || len(resp.Resources) != 0 {
		t.Fatalf("off-site page crawled: %+v", resp.Page)
	}
}

func TestSameSite(t *testing.T) {
	cases := map[[2]string]bool{
		{"www.example.co.uk", "cdn.example.co.uk"}: true,
		{"example.com", "example.com.evil.net"}:     false,
		{"a.github.io", "b.github.io"}:              false, // public suffix
		{"example.com", "EXAMPLE.com."}:             true,
	}
	for c, want := range cases {
		if got := SameSite(c[0], c[1]); got != want {
			t.Errorf("SameSite(%q,%q)=%v", c[0], c[1], got)
		}
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
