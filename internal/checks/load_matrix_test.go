package checks

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"domaindoctor/internal/probe"
)

func res(id, url string, hops ...probe.Hop) probe.SpecResult {
	return probe.SpecResult{Spec: probe.ReqSpec{ID: id, URL: url, Method: "GET", UA: "browser"}, Chain: probe.Chain{Start: url, Hops: hops}}
}

func okHop(url string, hdr ...string) probe.Hop {
	h := probe.Hop{URL: url, Status: 200, AllHeaders: map[string][]string{}, Proto: "HTTP/2.0", BodySize: 5000}
	for i := 0; i+1 < len(hdr); i += 2 {
		h.AllHeaders[hdr[i]] = append(h.AllHeaders[hdr[i]], hdr[i+1])
	}
	return h
}

func names(s []Signal) string {
	var out []string
	for _, x := range s {
		out = append(out, x.Name)
	}
	return strings.Join(out, ",")
}

func has(s []Signal, n string) bool {
	for _, x := range s {
		if x.Name == n {
			return true
		}
	}
	return false
}

func TestBuildSpecs(t *testing.T) {
	s := buildSpecs([]string{"example.com", "www.example.com"}, netip.Addr{})
	if len(s) != 11 || len(s) > probe.MaxSpecs {
		t.Fatalf("specs %d", len(s))
	}
	for _, x := range s {
		if x.Method != "GET" && x.Method != "HEAD" {
			t.Fatalf("non read-only method %s", x.Method)
		}
		if x.OriginIP.IsValid() {
			t.Fatal("origin spec without origin IP")
		}
	}
	s = buildSpecs([]string{"example.com"}, netip.MustParseAddr("203.0.113.9"))
	if s[len(s)-1].OriginIP.String() != "203.0.113.9" || len(s) != 11 {
		t.Fatalf("origin specs %+v", s[len(s)-2:])
	}
}

func TestSignalsHealthyAndWAF(t *testing.T) {
	m := matrixView{
		"base:https:example.com":     res("base:https:example.com", "https://example.com/", okHop("https://example.com/", "strict-transport-security", "max-age=1", "content-type", "text/html")),
		"base:http:example.com":      res("base:http:example.com", "http://example.com/", probe.Hop{URL: "http://example.com/", Status: 301, Location: "https://example.com/"}, okHop("https://example.com/")),
		"base:https:www.example.com": res("base:https:www.example.com", "https://www.example.com/", probe.Hop{URL: "https://www.example.com/", Status: 301, Location: "https://example.com/"}, okHop("https://example.com/")),
		"ua:curl":                    res("ua:curl", "https://example.com/", probe.Hop{URL: "https://example.com/", Status: 403}),
		"ua:googlebot":               res("ua:googlebot", "https://example.com/", okHop("https://example.com/")),
		"proto:h1":                   res("proto:h1", "https://example.com/", okHop("https://example.com/")),
		"proto:h2":                   res("proto:h2", "https://example.com/", okHop("https://example.com/")),
		"head":                       res("head", "https://example.com/", probe.Hop{URL: "https://example.com/", Status: 405}),
	}
	s := deriveSignals(m, "example.com", true, nil)
	for _, want := range []string{"https_ok", "ua_dependent_block", "head_differs", "security_headers_missing"} {
		if !has(s, want) {
			t.Errorf("missing %s in [%s]", want, names(s))
		}
	}
	for _, not := range []string{"http_no_https_redirect", "www_fail", "apex_www_split", "googlebot_blocked", "hsts_missing", "redirect_loop"} {
		if has(s, not) {
			t.Errorf("unexpected %s", not)
		}
	}
}

func TestSignalsFailures(t *testing.T) {
	loop := res("base:https:example.com", "https://example.com/",
		probe.Hop{URL: "https://example.com/", Status: 301, Location: "http://example.com/"},
		probe.Hop{URL: "http://example.com/", Status: 301, Location: "https://example.com/"})
	loop.Chain.Loop = true
	expired := okHop("https://example.com/")
	expired.TLS = &probe.TLSInfo{DaysLeft: -3, NotAfter: time.Now().Add(-72 * time.Hour), HostnameMatch: false, Subject: "other.org", SANs: []string{"other.org"}}
	m := matrixView{
		"base:https:example.com": loop,
		"base:http:example.com":  res("base:http:example.com", "http://example.com/", okHop("http://example.com/")),
		"origin:https":           res("origin:https", "https://example.com/", okHop("https://example.com/")),
		"origin:http":            res("origin:http", "http://example.com/", okHop("http://example.com/")),
		"proto:h1":               res("proto:h1", "https://example.com/", okHop("https://example.com/")),
		"proto:h2":               res("proto:h2", "https://example.com/", probe.Hop{URL: "https://example.com/", ErrorKind: "reset"}),
	}
	other := matrixView{"base:https:example.com": res("base:https:example.com", "https://example.com/", okHop("https://example.com/"))}
	s := deriveSignals(m, "example.com", false, []matrixView{other})
	for _, want := range []string{"redirect_loop", "https_fail_http_ok", "origin_tested", "origin_ok_cdn_fail", "h2_fail", "regional"} {
		if !has(s, want) {
			t.Errorf("missing %s in [%s]", want, names(s))
		}
	}

	page := okHop("https://example.com/", "retry-after", "120")
	page.Status = 503
	page.BodySample = `<h1>Briefly unavailable for scheduled maintenance.</h1><b>Fatal error</b>: Allowed memory size of 134217728 bytes exhausted`
	page.TLS = expired.TLS
	m = matrixView{"base:https:example.com": res("base:https:example.com", "https://example.com/", page)}
	s = deriveSignals(m, "example.com", false, nil)
	for _, want := range []string{"maintenance_page", "php_error_visible", "retry_after", "tls_expired", "tls_hostname_mismatch"} {
		if !has(s, want) {
			t.Errorf("missing %s in [%s]", want, names(s))
		}
	}
}

func TestSignalsContent(t *testing.T) {
	def := okHop("https://example.com/", "content-type", "text/html")
	def.BodySample = "<title>Welcome to nginx!</title>"
	gz := okHop("https://example.com/", "content-type", "text/html; charset=utf-8")
	gz.BodySize = 90000
	m := matrixView{
		"base:https:example.com": res("base:https:example.com", "https://example.com/", def),
		"enc:gzip":               res("enc:gzip", "https://example.com/", gz),
	}
	s := deriveSignals(m, "example.com", false, nil)
	if !has(s, "default_page") || !has(s, "no_compression") {
		t.Fatalf("[%s]", names(s))
	}
	park := okHop("https://example.com/")
	park.BodySample = "This domain may be for sale!"
	s = deriveSignals(matrixView{"base:https:example.com": res("base:https:example.com", "https://example.com/", park)}, "example.com", false, nil)
	if !has(s, "parked_page") || has(s, "default_page") {
		t.Fatalf("[%s]", names(s))
	}
}
