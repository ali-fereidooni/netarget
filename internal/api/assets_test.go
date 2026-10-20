package api

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"domaindoctor/internal/nodes"
)

// index.html gets content-hashed asset URLs (so a CDN cache cannot serve a stale
// app.js after a deploy), and the cache headers match: HTML revalidates,
// versioned assets are immutable.
func TestVersionedAssets(t *testing.T) {
	ui := fstest.MapFS{
		"index.html": {Data: []byte(`<link rel="stylesheet" href="/static/style.css"><script src="/static/app.js"></script>`)},
		"app.js":     {Data: []byte("console.log(1)")},
		"style.css":  {Data: []byte("body{}")},
	}
	s := New(Config{Registry: nodes.New(&nodes.Node{ID: "n1", Name: "Node 1", Location: "Test", P: nopProber{}}), UI: ui})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	b.Write(buf[:n])
	resp.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("index Cache-Control %q", resp.Header.Get("Cache-Control"))
	}
	m := regexp.MustCompile(`/static/app\.js\?v=([0-9a-f]{10})"`).FindStringSubmatch(b.String())
	if m == nil || !strings.Contains(b.String(), "/static/style.css?v=") {
		t.Fatalf("assets not versioned: %s", b.String())
	}

	resp, err = http.Get(ts.URL + "/static/app.js?v=" + m[1])
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Errorf("versioned asset: %d %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
}

// The server-check page versions its own script the same way, so staff never
// get a new page running a stale servercheck.js after a deploy.
func TestServerCheckPageVersioned(t *testing.T) {
	ui := fstest.MapFS{
		"index.html":       {Data: []byte(`<script src="/static/app.js"></script>`)},
		"app.js":           {Data: []byte("1")},
		"servercheck.html": {Data: []byte(`<link rel="stylesheet" href="/static/style.css"><script src="/static/servercheck.js"></script>`)},
		"servercheck.js":   {Data: []byte("console.log(2)")},
		"style.css":        {Data: []byte("body{}")},
	}
	s := New(Config{Registry: nodes.New(&nodes.Node{ID: "n1", Name: "Node 1", Location: "Test", P: nopProber{}}), UI: ui})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/server-check")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	resp.Body.Close()
	body := string(buf[:n])
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("server-check page: %d %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	if !regexp.MustCompile(`/static/servercheck\.js\?v=[0-9a-f]{10}"`).MatchString(body) || !strings.Contains(body, "/static/style.css?v=") {
		t.Errorf("assets not versioned: %s", body)
	}
}
