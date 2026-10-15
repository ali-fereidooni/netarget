package kb

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// KnownSignals are the derived facts the Go side can produce (see
// checks/load_matrix.go and checks/web.go). Rules may only reference these.
var KnownSignals = []string{
	"https_ok", "https_fail_http_ok", "http_no_https_redirect", "redirect_loop",
	"www_fail", "apex_fail", "apex_www_split",
	"ua_dependent_block", "googlebot_blocked", "browser_ua_blocked", "head_differs",
	"h2_fail", "h1_fail", "no_http2", "no_compression",
	"origin_tested", "origin_ok_cdn_fail", "origin_fail_too", "origin_https_fail",
	"parked_page", "default_page", "directory_listing", "maintenance_page", "php_error_visible",
	"apache_500_page", "mentions_htaccess", "retry_after", "slow_ttfb", "large_page",
	"cache_hit", "cache_miss",
	"tls_expired", "tls_expiring_soon", "tls_hostname_mismatch", "tls_incomplete_chain", "tls_untrusted", "tls_old_protocol",
	"hsts_missing", "hsts_preload", "security_headers_missing",
	"regional", "all_nodes_fail",
	"cdn_detected", "no_cdn",
	"res_failed", "res_slow", "res_mixed_content", "res_wrong_mime", "res_blocked_mime", "res_uncompressed",
	"res_weak_cache", "res_cors", "res_third_party_failed",
}

// Observation is the normalized evidence the rules match against: the
// canonical request (browser GET https://host/ from the primary node),
// fingerprints, and derived signals with their evidence text.
type Observation struct {
	Host      string
	URL       string
	Request   string // human-readable description of the canonical request
	Status    int
	ErrorKind string
	Headers   map[string][]string // lower-case names
	Body      string
	CDN       string // fingerprint id, "" when none
	Server    string
	Platform  string
	Names     map[string]string // id -> display name (Cloudflare, nginx…)
	Signals   map[string]string // signal -> evidence
	Values    map[string]string // extra template values (cf_code…)
}

// MatchResult is one rule that matched, with everything the user needs.
type MatchResult struct {
	RuleID          string   `json:"rule_id"`
	Title           string   `json:"title"`
	Layer           string   `json:"layer"`
	Severity        string   `json:"severity"`
	Confidence      float64  `json:"confidence"`
	Level           string   `json:"level"`
	Verdict         string   `json:"verdict"`
	Evidence        []string `json:"evidence"`
	Causes          []Cause  `json:"causes"`
	Fixes           []Fix    `json:"fixes"`
	CannotDetermine []string `json:"cannot_determine"`
	Warnings        []string `json:"warnings,omitempty"`
	Group           string   `json:"group,omitempty"`
	priority        int
}

func (c *Cond) eval(o *Observation) (bool, string) {
	switch {
	case len(c.Status) > 0:
		for _, s := range c.Status {
			if o.Status == s {
				return true, fmt.Sprintf("HTTP %d on %s", o.Status, o.Request)
			}
		}
	case c.StatusRange != "":
		if o.Status >= c.lo && o.Status <= c.hi {
			return true, fmt.Sprintf("HTTP %d on %s", o.Status, o.Request)
		}
	case len(c.ErrorKind) > 0:
		if o.ErrorKind != "" && in(o.ErrorKind, c.ErrorKind) {
			return true, fmt.Sprintf("%s: connection error %q", o.Request, o.ErrorKind)
		}
	case len(c.CDN) > 0:
		id := o.CDN
		if id == "" {
			id = "none"
		}
		if in(id, c.CDN) || (id != "none" && in("any", c.CDN)) {
			if id == "none" {
				return true, "no CDN or WAF detected in front of the site"
			}
			return true, "CDN/WAF detected: " + o.name(id)
		}
	case len(c.Server) > 0:
		id := o.Server
		if id == "" {
			id = "unknown"
		}
		if in(id, c.Server) {
			return true, "web server detected: " + o.name(id)
		}
	case len(c.Platform) > 0:
		if o.Platform != "" && in(o.Platform, c.Platform) {
			return true, "platform detected: " + o.name(o.Platform)
		}
	case c.Header != nil:
		for _, v := range o.Headers[c.Header.Name] {
			if c.Header.re == nil || c.Header.re.MatchString(v) {
				return true, fmt.Sprintf("response header %s: %s", c.Header.Name, clip(v, 100))
			}
		}
	case c.Body != "":
		if m := c.bodyRe.FindString(o.Body); m != "" {
			return true, fmt.Sprintf("response body contains %q", clip(m, 80))
		}
	case c.Signal != "":
		if ev, ok := o.Signals[c.Signal]; ok {
			return true, ev
		}
	}
	return false, ""
}

func (o *Observation) name(id string) string {
	if n, ok := o.Names[id]; ok && n != "" {
		return n
	}
	return id
}

// Evaluate returns every matching rule, most important first: severity,
// then confidence, then rule priority.
func (k *KB) Evaluate(o *Observation) []MatchResult {
	var out []MatchResult
	for i := range k.Rules {
		if m, ok := k.Rules[i].evaluate(o); ok {
			out = append(out, m)
		}
	}
	sevRank := map[string]int{"fail": 0, "warn": 1, "info": 2}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		if a.priority != b.priority {
			return a.priority < b.priority
		}
		return a.RuleID < b.RuleID
	})
	// One report per group: the best-ranked match wins.
	seen := map[string]bool{}
	kept := out[:0]
	for _, m := range out {
		if m.Group != "" {
			if seen[m.Group] {
				continue
			}
			seen[m.Group] = true
		}
		kept = append(kept, m)
	}
	return kept
}

func (r *Rule) evaluate(o *Observation) (MatchResult, bool) {
	var ev []string
	for i := range r.Match.All {
		ok, e := r.Match.All[i].eval(o)
		if !ok {
			return MatchResult{}, false
		}
		ev = append(ev, e)
	}
	if len(r.Match.Any) > 0 {
		hit := false
		for i := range r.Match.Any {
			if ok, e := r.Match.Any[i].eval(o); ok {
				hit = true
				ev = append(ev, e)
			}
		}
		if !hit {
			return MatchResult{}, false
		}
	}
	for i := range r.Match.None {
		if ok, _ := r.Match.None[i].eval(o); ok {
			return MatchResult{}, false
		}
	}
	conf := r.Confidence.Base
	for i := range r.Confidence.Boosts {
		b := &r.Confidence.Boosts[i]
		if ok, e := b.When.eval(o); ok {
			conf += b.Add
			ev = append(ev, e+" ("+b.Why+")")
		}
	}
	conf = math.Min(0.99, math.Round(conf*100)/100)
	fixes := make([]Fix, len(r.Fixes))
	for i, f := range r.Fixes {
		f.Step, f.Verify, f.Why = o.render(f.Step), o.render(f.Verify), o.render(f.Why)
		if len(f.Snippets) > 0 {
			sn := map[string]string{}
			for k, v := range f.Snippets {
				sn[k] = o.render(v)
			}
			f.Snippets = sn
		}
		fixes[i] = f
	}
	return MatchResult{
		RuleID: r.ID, Title: r.Title, Layer: r.Layer, Severity: r.Severity,
		Confidence: conf, Level: level(conf), Verdict: o.render(r.Verdict), Evidence: dedupe(ev),
		Causes: r.Causes, Fixes: fixes, CannotDetermine: r.CannotDetermine, Warnings: r.Warnings,
		Group: r.Group, priority: r.Priority,
	}, true
}

func level(c float64) string {
	switch {
	case c >= 0.8:
		return "high"
	case c >= 0.5:
		return "medium"
	}
	return "low"
}

func (o *Observation) render(t string) string {
	vars := map[string]string{
		"cdn": o.name(o.CDN), "server": o.name(o.Server), "platform": o.name(o.Platform),
		"status": fmt.Sprint(o.Status), "host": o.Host, "url": o.URL, "error_kind": o.ErrorKind,
	}
	if o.CDN == "" {
		vars["cdn"] = "the CDN"
	}
	if o.Server == "" {
		vars["server"] = "the web server"
	}
	vars["cf_code"] = "see the code on the error page"
	for k, v := range o.Values {
		vars[k] = v
	}
	return templateRe.ReplaceAllStringFunc(t, func(m string) string {
		if v, ok := vars[m[1:len(m)-1]]; ok && v != "" {
			return v
		}
		return m
	})
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ObservationFromGiven builds an Observation from a rule test fixture.
func ObservationFromGiven(g Given) *Observation {
	o := &Observation{Host: "example.com", URL: "https://example.com/", Request: "GET https://example.com/ (browser)",
		Status: g.Status, ErrorKind: g.ErrorKind, Headers: map[string][]string{}, Body: g.Body,
		CDN: g.CDN, Server: g.Server, Platform: g.Platform, Names: map[string]string{}, Signals: map[string]string{}, Values: map[string]string{}}
	if o.CDN == "none" {
		o.CDN = ""
	}
	if o.Server == "unknown" {
		o.Server = ""
	}
	for k, v := range g.Headers {
		o.Headers[strings.ToLower(k)] = v
	}
	for _, s := range g.Signals {
		o.Signals[s] = "fixture signal " + s
	}
	return o
}
