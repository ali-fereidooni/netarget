package checks

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"domaindoctor/internal/probe"
)

// MatrixRow is one request of the matrix as executed by one node.
type MatrixRow struct {
	Node      string  `json:"node"`
	SpecID    string  `json:"spec"`
	Label     string  `json:"label"`
	URL       string  `json:"url"`
	FinalURL  string  `json:"final_url,omitempty"`
	Status    int     `json:"status,omitempty"`
	ErrorKind string  `json:"error_kind,omitempty"`
	Hops      int     `json:"hops"`
	Loop      bool    `json:"loop,omitempty"`
	Proto     string  `json:"proto,omitempty"`
	Encoding  string  `json:"encoding,omitempty"`
	BodySize  int64   `json:"body_size"`
	TTFBms    float64 `json:"ttfb_ms"`
	TotalMS   float64 `json:"total_ms"`
	Server    string  `json:"server,omitempty"`
	Diff      bool    `json:"diff,omitempty"` // differs from the baseline browser request
}

// Signal is a derived cross-request fact with the evidence behind it.
type Signal struct {
	Name     string `json:"name"`
	Evidence string `json:"evidence"`
}

func boolPtr(b bool) *bool { return &b }

// buildSpecs returns the request matrix for one host.
//   - baseline: GET with a browser UA to http/https × host/www
//   - variants on https://host/: HEAD, curl, Googlebot, HTTP/1.1, HTTP/2, gzip, identity
//   - origin direct (optional): GET http/https with the supplied origin IP
func buildSpecs(hosts []string, origin netip.Addr) []probe.ReqSpec {
	var s []probe.ReqSpec
	for _, h := range hosts {
		for _, sch := range []string{"https", "http"} {
			s = append(s, probe.ReqSpec{ID: "base:" + sch + ":" + h, URL: sch + "://" + h + "/", Method: "GET", UA: "browser", Sample: true})
		}
	}
	main := "https://" + hosts[0] + "/"
	s = append(s,
		probe.ReqSpec{ID: "head", URL: main, Method: "HEAD", UA: "browser"},
		probe.ReqSpec{ID: "ua:curl", URL: main, Method: "GET", UA: "curl", Sample: true},
		probe.ReqSpec{ID: "ua:googlebot", URL: main, Method: "GET", UA: "googlebot", Sample: true},
		probe.ReqSpec{ID: "proto:h1", URL: main, Method: "GET", UA: "browser", Proto: "h1"},
		probe.ReqSpec{ID: "proto:h2", URL: main, Method: "GET", UA: "browser", Proto: "h2"},
		probe.ReqSpec{ID: "enc:gzip", URL: main, Method: "GET", UA: "browser", Compress: boolPtr(true), Sample: true},
		probe.ReqSpec{ID: "enc:identity", URL: main, Method: "GET", UA: "browser", Compress: boolPtr(false)},
	)
	if origin.IsValid() {
		s = append(s,
			probe.ReqSpec{ID: "origin:https", URL: main, Method: "GET", UA: "browser", OriginIP: origin, Sample: true},
			probe.ReqSpec{ID: "origin:http", URL: "http://" + hosts[0] + "/", Method: "GET", UA: "browser", OriginIP: origin, Sample: true},
		)
	}
	return s
}

func specLabel(s probe.ReqSpec) string {
	parts := []string{s.Method, s.URL}
	switch {
	case s.OriginIP.IsValid():
		parts = append(parts, "origin "+s.OriginIP.String())
	case s.UA != "" && s.UA != "browser":
		parts = append(parts, s.UA+" UA")
	}
	if s.Proto == "h1" {
		parts = append(parts, "HTTP/1.1")
	}
	if s.Proto == "h2" {
		parts = append(parts, "HTTP/2")
	}
	if s.Compress != nil {
		if *s.Compress {
			parts = append(parts, "gzip")
		} else {
			parts = append(parts, "no compression")
		}
	}
	return strings.Join(parts, " ")
}

func ok(h *probe.Hop, loop bool) bool {
	return h != nil && !loop && h.ErrorKind == "" && h.Status >= 200 && h.Status < 400
}

func rowFrom(node string, r probe.SpecResult) MatrixRow {
	row := MatrixRow{Node: node, SpecID: r.Spec.ID, Label: specLabel(r.Spec), URL: r.Spec.URL, Hops: len(r.Chain.Hops), Loop: r.Chain.Loop}
	if f := r.Chain.Final(); f != nil {
		row.FinalURL, row.Status, row.ErrorKind = f.URL, f.Status, f.ErrorKind
		row.Proto, row.Encoding, row.BodySize = f.Proto, f.ContentEncoding, f.BodySize
		row.TTFBms, row.TotalMS, row.Server = f.Timing.TTFBms, f.Timing.TotalMS, f.Server
	}
	return row
}

// matrixView indexes one node's results by spec id.
type matrixView map[string]probe.SpecResult

func (m matrixView) final(id string) (*probe.Hop, bool) {
	r, found := m[id]
	if !found {
		return nil, false
	}
	return r.Chain.Final(), r.Chain.Loop
}

func (m matrixView) okSpec(id string) bool {
	h, loop := m.final(id)
	return ok(h, loop)
}

func describeHop(id string, m matrixView) string {
	r, found := m[id]
	if !found {
		return id + ": not run"
	}
	h := r.Chain.Final()
	if h == nil {
		return specLabel(r.Spec) + ": no response"
	}
	if r.Chain.Loop {
		return fmt.Sprintf("%s → redirect loop after %d hops", specLabel(r.Spec), len(r.Chain.Hops))
	}
	if h.ErrorKind != "" {
		return fmt.Sprintf("%s → %s", specLabel(r.Spec), h.ErrorKind)
	}
	return fmt.Sprintf("%s → %d", specLabel(r.Spec), h.Status)
}

var (
	reDefaultPage = regexp.MustCompile(`(?i)Welcome to nginx!|Apache2 (Ubuntu|Debian) Default Page|<h1>It works!</h1>|Test Page for the (Apache|nginx) HTTP Server|IIS Windows Server|Welcome to CentOS|Congratulations! Your website is up|LiteSpeed Web Server.*Congratulations|Welcome to Caddy`)
	reParked      = regexp.MustCompile(`(?i)this domain (is|may be) for sale|domain (is )?parked|parkingcrew|sedoparking|bodis\.com|Buy this domain`)
	reDirListing  = regexp.MustCompile(`(?i)<title>Index of /|<h1>Index of /`)
	reMaintenance = regexp.MustCompile(`(?i)maintenance mode|under maintenance|briefly unavailable for scheduled maintenance|we.ll be back soon`)
	rePHPError    = regexp.MustCompile(`(?i)(Fatal error|Parse error)</b>?:|Allowed memory size of \d+ bytes exhausted|Uncaught (Error|Exception)`)
	reApache500   = regexp.MustCompile(`(?i)The server encountered an internal error or\s+misconfiguration`)
	reHtaccess    = regexp.MustCompile(`(?i)\.?htaccess`) // Apache says "unable to read htaccess file"
)

// deriveSignals computes cross-request facts for one node's matrix.
func deriveSignals(m matrixView, host string, hasWWW bool, others []matrixView) []Signal {
	var sig []Signal
	add := func(name, ev string) { sig = append(sig, Signal{Name: name, Evidence: ev}) }
	httpsID, httpID := "base:https:"+host, "base:http:"+host
	httpsOK, httpOK := m.okSpec(httpsID), m.okSpec(httpID)
	hs, _ := m.final(httpsID)
	hh, _ := m.final(httpID)

	if httpsOK {
		add("https_ok", describeHop(httpsID, m))
	}
	if httpOK && !httpsOK {
		add("https_fail_http_ok", describeHop(httpsID, m)+"; "+describeHop(httpID, m))
	}
	if httpOK && hh != nil && strings.HasPrefix(hh.URL, "http://") && httpsOK {
		add("http_no_https_redirect", describeHop(httpID, m)+" (stays on http://)")
	}
	if r, found := m[httpsID]; found && r.Chain.Loop {
		add("redirect_loop", describeHop(httpsID, m))
	}
	if r, found := m[httpID]; found && r.Chain.Loop {
		add("redirect_loop", describeHop(httpID, m))
	}
	if hasWWW {
		wid := "base:https:www." + host
		wOK := m.okSpec(wid)
		switch {
		case httpsOK && !wOK:
			add("www_fail", describeHop(wid, m))
		case wOK && !httpsOK:
			add("apex_fail", describeHop(httpsID, m)+"; "+describeHop(wid, m))
		case wOK && httpsOK:
			wh, _ := m.final(wid)
			if hostOf(wh.URL) != hostOf(hs.URL) {
				add("apex_www_split", fmt.Sprintf("%s and %s end at different hosts", hs.URL, wh.URL))
			}
		}
	}

	// User-agent dependent results (bot/WAF blocks).
	for _, id := range []string{"ua:curl", "ua:googlebot"} {
		h, _ := m.final(id)
		if h == nil || hs == nil {
			continue
		}
		if httpsOK && !m.okSpec(id) {
			add("ua_dependent_block", describeHop(httpsID, m)+" but "+describeHop(id, m))
			if id == "ua:googlebot" {
				add("googlebot_blocked", describeHop(id, m))
			}
		}
		if !httpsOK && m.okSpec(id) {
			add("browser_ua_blocked", describeHop(httpsID, m)+" but "+describeHop(id, m))
		}
	}
	if h, _ := m.final("head"); h != nil && hs != nil && h.ErrorKind == "" && hs.ErrorKind == "" && h.Status/100 != hs.Status/100 {
		add("head_differs", describeHop("head", m)+" vs GET → "+fmt.Sprint(hs.Status))
	}
	if h1, h2 := m.okSpec("proto:h1"), m.okSpec("proto:h2"); h1 != h2 {
		if h1 {
			add("h2_fail", describeHop("proto:h2", m)+" while HTTP/1.1 works")
		} else {
			add("h1_fail", describeHop("proto:h1", m)+" while HTTP/2 works")
		}
	}
	if h, _ := m.final("proto:h2"); h != nil && h.ErrorKind == "" && h.Proto != "" && !strings.HasPrefix(h.Proto, "HTTP/2") {
		add("no_http2", "the server negotiated "+h.Proto+" when HTTP/2 was offered")
	}
	if h, _ := m.final("enc:gzip"); h != nil && h.ErrorKind == "" && h.Status == 200 && h.ContentEncoding == "" && h.BodySize > 1024 &&
		strings.Contains(strings.ToLower(first(h.AllHeaders["content-type"])), "text/html") {
		add("no_compression", fmt.Sprintf("GET with Accept-Encoding: gzip returned %d bytes uncompressed", h.BodySize))
	}

	// Origin direct vs through the CDN.
	if _, tested := m["origin:https"]; tested {
		// Compare like with like: the canonical request is HTTPS, so only a
		// working origin HTTPS proves the CDN path is at fault. Origin HTTP
		// working while origin HTTPS fails points at the origin's TLS setup.
		oHTTPS, oHTTP := m.okSpec("origin:https"), m.okSpec("origin:http")
		add("origin_tested", describeHop("origin:https", m)+"; "+describeHop("origin:http", m))
		switch {
		case oHTTPS && !httpsOK:
			add("origin_ok_cdn_fail", describeHop("origin:https", m)+" but "+describeHop(httpsID, m))
		case !oHTTPS && !oHTTP && !httpsOK:
			add("origin_fail_too", describeHop("origin:https", m)+"; "+describeHop("origin:http", m))
		}
		if !oHTTPS && oHTTP {
			add("origin_https_fail", describeHop("origin:https", m)+" while origin http works")
		}
	}

	// Page content of the main response.
	if hs != nil {
		b := hs.BodySample
		switch {
		case reParked.MatchString(b):
			add("parked_page", "the page looks like a domain-parking page")
		case reDefaultPage.MatchString(b):
			add("default_page", "the page is a web server's default welcome page: "+reDefaultPage.FindString(b))
		}
		if reDirListing.MatchString(b) {
			add("directory_listing", "the page is an automatic directory listing")
		}
		if reMaintenance.MatchString(b) {
			add("maintenance_page", "the page says the site is in maintenance: "+reMaintenance.FindString(b))
		}
		if rePHPError.MatchString(b) {
			add("php_error_visible", "the page shows a PHP error: "+rePHPError.FindString(b))
		}
		if reApache500.MatchString(b) {
			add("apache_500_page", "Apache's generic 500 page (\"internal error or misconfiguration\")")
		}
		if reHtaccess.MatchString(b) {
			add("mentions_htaccess", "the error page mentions .htaccess")
		}
		if v := first(hs.AllHeaders["retry-after"]); v != "" {
			add("retry_after", "Retry-After: "+v)
		}
		if hs.ErrorKind == "" && hs.Timing.TTFBms > 1500 {
			add("slow_ttfb", fmt.Sprintf("time to first byte %.0f ms", hs.Timing.TTFBms))
		}
		if hs.BodySize > 3<<20 || hs.BodyTruncated {
			add("large_page", fmt.Sprintf("HTML document is at least %d KB", hs.BodySize>>10))
		}
		cs := strings.ToLower(first(hs.AllHeaders["cf-cache-status"]) + " " + first(hs.AllHeaders["x-cache"]) + " " + first(hs.AllHeaders["akamai-cache-status"]))
		switch {
		case strings.Contains(cs, "hit"):
			add("cache_hit", "CDN cache status: "+strings.TrimSpace(cs))
		case strings.Contains(cs, "miss") || strings.Contains(cs, "dynamic") || strings.Contains(cs, "bypass"):
			add("cache_miss", "CDN cache status: "+strings.TrimSpace(cs)+" (the request went to the origin)")
		}
		if t := hs.TLS; t != nil {
			switch {
			case t.DaysLeft < 0:
				add("tls_expired", fmt.Sprintf("certificate expired %s (issuer %s)", t.NotAfter.Format("2006-01-02"), t.Issuer))
			case t.DaysLeft < 14:
				add("tls_expiring_soon", fmt.Sprintf("certificate expires in %d days", t.DaysLeft))
			}
			if !t.HostnameMatch {
				add("tls_hostname_mismatch", fmt.Sprintf("certificate for %s does not cover %s (SAN %s)", t.Subject, host, strings.Join(t.SANs, ", ")))
			}
			if t.IncompleteChain {
				add("tls_incomplete_chain", "the server sends no intermediate certificate")
			} else if !t.ChainValid && t.DaysLeft >= 0 {
				add("tls_untrusted", "certificate not trusted: "+t.ChainError)
			}
			if t.Version == "TLS 1.0" || t.Version == "TLS 1.1" {
				add("tls_old_protocol", "negotiated "+t.Version)
			}
		}
		if httpsOK && hs.AllHeaders != nil {
			if len(hs.AllHeaders["strict-transport-security"]) == 0 {
				add("hsts_missing", "no Strict-Transport-Security header on "+hs.URL)
			} else if v := first(hs.AllHeaders["strict-transport-security"]); strings.Contains(strings.ToLower(v), "preload") {
				add("hsts_preload", "HSTS with preload: "+v)
			}
			var miss []string
			for _, n := range []string{"content-security-policy", "x-content-type-options", "referrer-policy"} {
				if len(hs.AllHeaders[n]) == 0 {
					miss = append(miss, n)
				}
			}
			if len(miss) > 0 {
				add("security_headers_missing", "missing: "+strings.Join(miss, ", "))
			}
		}
	}
	// Cross-node comparison.
	if len(others) > 0 {
		okN, failN := 0, 0
		for _, o := range append([]matrixView{m}, others...) {
			if o.okSpec(httpsID) {
				okN++
			} else {
				failN++
			}
		}
		if okN > 0 && failN > 0 {
			add("regional", fmt.Sprintf("%d node(s) load the site, %d fail", okN, failN))
		}
		if okN == 0 {
			add("all_nodes_fail", fmt.Sprintf("all %d nodes fail", failN))
		}
	}
	sort.SliceStable(sig, func(i, j int) bool { return sig[i].Name < sig[j].Name })
	return dedupeSignals(sig)
}

func dedupeSignals(s []Signal) []Signal {
	out := s[:0]
	seen := map[string]bool{}
	for _, x := range s {
		if !seen[x.Name] {
			seen[x.Name] = true
			out = append(out, x)
		}
	}
	return out
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func hostOf(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(u, "/:?"); i >= 0 {
		u = u[:i]
	}
	return strings.ToLower(u)
}

// reCFCode extracts a Cloudflare 1xxx error code from an error page.
var reCFCode = regexp.MustCompile(`(?i)Error (1\d{3})\b|error code: (1\d{3})\b`)
