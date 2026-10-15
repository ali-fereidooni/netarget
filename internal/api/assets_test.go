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
