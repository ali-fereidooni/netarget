package probe

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

// Resource-check limits (enforced by the agent).
const (
	MaxResources      = 30
	maxPageHTML       = 512 << 10
	maxCSSForFonts    = 128 << 10
	resourceTimeout   = 8 * time.Second
	resourcesTotal    = 40 * time.Second
	resourceParallel  = 6
	slowResourceMS    = 2000
	resourceReadLimit = 256 << 10 // bytes read per subresource (size beyond this comes from Content-Length)
)

type ResourceRequest struct {
	PageURL string                  `json:"page_url"`
	Pinned  map[string][]netip.Addr `json:"pinned"`
	Max     int                     `json:"max"`
	// Site is the checked registrable domain. Subresources are only checked
	// when the page itself is on this site (a redirect to another site
	// must not turn the agent into a fetcher for attacker-chosen pages).
	Site string `json:"site,omitempty"`
}

type Resource struct {
	URL          string   `json:"url"`
	Host         string   `json:"host"`
	Kind         string   `json:"kind"` // stylesheet, script, image, font, icon, preload
	ThirdParty   bool     `json:"third_party"`
	Status       int      `json:"status,omitempty"`
	ErrorKind    string   `json:"error_kind,omitempty"`
	TTFBms       float64  `json:"ttfb_ms"`
	TotalMS      float64  `json:"total_ms"`
	Size         int64    `json:"size"`
	ContentType  string   `json:"content_type,omitempty"`
	Encoding     string   `json:"encoding,omitempty"`
	CacheControl string   `json:"cache_control,omitempty"`
	Issues       []string `json:"issues,omitempty"` // failed, slow, mixed_content, wrong_mime, blocked_mime, uncompressed, weak_cache, cors, blocked
}

type PageInfo struct {
	URL         string  `json:"url"`
	Status      int     `json:"status,omitempty"`
	ErrorKind   string  `json:"error_kind,omitempty"`
	Size        int64   `json:"size"`
	Truncated   bool    `json:"truncated,omitempty"`
	ContentType string  `json:"content_type,omitempty"`
	TTFBms      float64 `json:"ttfb_ms"`
	Found       int     `json:"found"` // subresources referenced
	Skipped     string  `json:"skipped,omitempty"`
	Checked     int     `json:"checked"` // subresources fetched (capped)
}

type ResourceResponse struct {
	Page      PageInfo   `json:"page"`
	Resources []Resource `json:"resources"`
}

type ref struct {
	url, kind   string
	crossorigin bool
}

var cssURL = regexp.MustCompile(`url\(\s*['"]?([^'")]+\.(?:woff2?|ttf|otf|eot)(?:\?[^'")]*)?)['"]?\s*\)`)

// extractRefs parses HTML and returns resolved subresource references.
func extractRefs(base *url.URL, doc string) []ref {
	z := html.NewTokenizer(strings.NewReader(doc))
	var out []ref
	seen := map[string]bool{}
	add := func(raw, kind string, co bool) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "blob:") || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "#") {
			return
		}
		u, err := base.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		u.Fragment = ""
		s := u.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, ref{url: s, kind: kind, crossorigin: co})
		}
	}
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		t := z.Token()
		a := map[string]string{}
		hasCO := false
		for _, at := range t.Attr {
			a[strings.ToLower(at.Key)] = at.Val
			if strings.EqualFold(at.Key, "crossorigin") {
				hasCO = true
			}
		}
		switch t.Data {
		case "link":
			rel := strings.ToLower(a["rel"])
			switch {
			case strings.Contains(rel, "stylesheet"):
				add(a["href"], "stylesheet", hasCO)
			case strings.Contains(rel, "preload") || strings.Contains(rel, "modulepreload"):
				kind := "preload"
				if a["as"] == "font" {
					kind = "font"
				}
				add(a["href"], kind, hasCO || a["as"] == "font")
			case strings.Contains(rel, "icon"):
				add(a["href"], "icon", hasCO)
			}
		case "script":
			add(a["src"], "script", hasCO)
		case "img", "source":
			add(a["src"], "image", hasCO)
			if ss := a["srcset"]; ss != "" {
				first := strings.Fields(strings.Split(ss, ",")[0])
				if len(first) > 0 {
					add(first[0], "image", hasCO)
				}
			}
		}
	}
	return out
}

// prioritise keeps the most diagnostic resources when over the cap.
func prioritise(refs []ref, max int) []ref {
	rank := map[string]int{"stylesheet": 0, "script": 1, "font": 2, "preload": 3, "image": 4, "icon": 5}
	sort.SliceStable(refs, func(i, j int) bool { return rank[refs[i].kind] < rank[refs[j].kind] })
	if len(refs) > max {
		refs = refs[:max]
	}
	return refs
}

func expectedType(kind string) []string {
	switch kind {
	case "stylesheet":
		return []string{"text/css"}
	case "script":
		return []string{"javascript", "ecmascript"}
	case "font":
		return []string{"font/", "application/font", "application/x-font", "application/vnd.ms-fontobject", "application/octet-stream"}
	case "image", "icon":
		return []string{"image/"}
	}
	return nil
}

func acceptFor(kind string) string {
	switch kind {
	case "stylesheet":
		return "text/css,*/*;q=0.1"
	case "script":
		return "*/*"
	case "image", "icon":
		return "image/avif,image/webp,image/*,*/*;q=0.8"
	case "font":
		return "font/woff2,font/*;q=0.9,*/*;q=0.5"
	}
	return "*/*"
}

func origin(u *url.URL) string { return u.Scheme + "://" + u.Host }

// CheckResources fetches the page and tests its subresources.
func (p *HTTPProber) CheckResources(ctx context.Context, req ResourceRequest) *ResourceResponse {
	ctx, cancel := context.WithTimeout(ctx, resourcesTotal)
	defer cancel()
	max := req.Max
	if max <= 0 || max > MaxResources {
		max = MaxResources
	}
	out := &ResourceResponse{Page: PageInfo{URL: req.PageURL}, Resources: []Resource{}}
	ch := p.chain(ctx, req.PageURL, req.Pinned, 5, HopOpts{UA: "browser", Sample: true, SampleLimit: maxPageHTML, Compress: boolp(true)})
	f := ch.Final()
	if f == nil {
		return out
	}
	out.Page = PageInfo{URL: f.URL, Status: f.Status, ErrorKind: f.ErrorKind, Size: f.BodySize, Truncated: f.BodyTruncated,
		ContentType: first(f.AllHeaders["content-type"]), TTFBms: f.Timing.TTFBms}
	if f.ErrorKind != "" || f.Status >= 400 || !strings.Contains(strings.ToLower(out.Page.ContentType), "html") {
		return out
	}
	page, _ := url.Parse(f.URL)
	if req.Site != "" && !SameSite(page.Hostname(), req.Site) {
		out.Page.Skipped = "the page redirected to another site; its resources were not checked"
		return out
	}
	refs := extractRefs(page, f.BodySample)
	out.Page.Found = len(refs)

	// Fonts referenced from the first same-origin stylesheet.
	for _, r := range refs {
		if r.kind != "stylesheet" {
			continue
		}
		cu, _ := url.Parse(r.url)
		if cu == nil || cu.Host != page.Host {
			continue
		}
		css := p.chain(ctx, r.url, req.Pinned, 3, HopOpts{UA: "browser", Sample: true, SampleLimit: maxCSSForFonts, Compress: boolp(true), Accept: acceptFor("stylesheet")})
		if cf := css.Final(); cf != nil && cf.Status == 200 {
			for i, m := range cssURL.FindAllStringSubmatch(cf.BodySample, -1) {
				if i >= 4 {
					break
				}
				if fu, err := cu.Parse(m[1]); err == nil {
					refs = append(refs, ref{url: fu.String(), kind: "font", crossorigin: true})
				}
			}
		}
		break
	}
	refs = prioritise(refs, max)
	out.Page.Checked = len(refs)
	out.Resources = make([]Resource, len(refs))

	var wg sync.WaitGroup
	sem := make(chan struct{}, resourceParallel)
	rp := *p
	rp.Timeout = resourceTimeout
	for i, r := range refs {
		wg.Add(1)
		go func(i int, r ref) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out.Resources[i] = rp.checkOne(ctx, page, r, req.Pinned)
		}(i, r)
	}
	wg.Wait()
	return out
}

func (p *HTTPProber) checkOne(ctx context.Context, page *url.URL, r ref, pinned map[string][]netip.Addr) Resource {
	u, _ := url.Parse(r.url)
	res := Resource{URL: r.url, Host: u.Hostname(), Kind: r.kind, ThirdParty: !SameSite(u.Hostname(), page.Hostname())}
	issue := func(s string) { res.Issues = append(res.Issues, s) }
	if page.Scheme == "https" && u.Scheme == "http" {
		issue("mixed_content")
	}
	o := HopOpts{UA: "browser", Sample: true, SampleLimit: 1, CountLimit: resourceReadLimit, Compress: boolp(true), Accept: acceptFor(r.kind)}
	target := r.url
	if res.ThirdParty {
		// Third-party hosts get a HEAD without the query string: enough for
		// status, type and caching, and never a GET with page-supplied
		// parameters to someone else's endpoint.
		o.Method = "HEAD"
		q := *u
		q.RawQuery = ""
		target = q.String()
	}
	crossOrigin := origin(u) != origin(page)
	if crossOrigin && (r.crossorigin || r.kind == "font") {
		o.Origin = origin(page)
	}
	ch := p.chain(ctx, target, pinned, 3, o)
	f := ch.Final()
	if f == nil {
		issue("failed")
		return res
	}
	res.Status, res.ErrorKind = f.Status, f.ErrorKind
	res.TTFBms, res.TotalMS = f.Timing.TTFBms, f.Timing.TotalMS
	res.Size, res.Encoding = f.BodySize, f.ContentEncoding
	res.ContentType = first(f.AllHeaders["content-type"])
	res.CacheControl = first(f.AllHeaders["cache-control"])
	switch {
	case f.ErrorKind == "blocked":
		issue("blocked")
		return res
	case o.Method == "HEAD" && (f.Status == 405 || f.Status == 501):
		return res // the host does not support HEAD; we cannot tell, so do not report a failure
	case f.ErrorKind != "" || ch.Loop || f.Status >= 400:
		issue("failed")
		return res
	}
	if res.TotalMS > slowResourceMS {
		issue("slow")
	}
	ct := strings.ToLower(res.ContentType)
	if exp := expectedType(r.kind); exp != nil && f.Status == 200 {
		match := false
		for _, e := range exp {
			if strings.Contains(ct, e) {
				match = true
			}
		}
		if !match {
			issue("wrong_mime")
			if (r.kind == "script" || r.kind == "stylesheet") && strings.EqualFold(first(f.AllHeaders["x-content-type-options"]), "nosniff") {
				issue("blocked_mime")
			}
		}
	}
	textual := strings.Contains(ct, "css") || strings.Contains(ct, "javascript") || strings.Contains(ct, "svg") || strings.Contains(ct, "json")
	if textual && res.Encoding == "" && res.Size > 1024 {
		issue("uncompressed")
	}
	cc := strings.ToLower(res.CacheControl)
	if r.kind != "preload" && f.Status == 200 && (cc == "" && first(f.AllHeaders["expires"]) == "" || strings.Contains(cc, "no-store") || strings.Contains(cc, "max-age=0") || strings.Contains(cc, "no-cache")) {
		issue("weak_cache")
	}
	if o.Origin != "" {
		acao := first(f.AllHeaders["access-control-allow-origin"])
		if acao != "*" && !strings.EqualFold(acao, o.Origin) {
			issue("cors")
		}
	}
	return res
}

// SameSite reports whether two host names belong to the same registrable
// domain (eTLD+1), e.g. www.example.co.uk and cdn.example.co.uk.
func SameSite(a, b string) bool {
	return siteOf(a) == siteOf(b)
}

func siteOf(h string) string {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if s, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
		return s
	}
	return h
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func boolp(b bool) *bool { return &b }

// Summary counts issues across resources (used for signals and the UI).
func (r *ResourceResponse) Summary() map[string]int {
	m := map[string]int{}
	for _, x := range r.Resources {
		for _, i := range x.Issues {
			m[i]++
		}
	}
	return m
}

func (r Resource) String() string {
	return fmt.Sprintf("%s %s %d %s", r.Kind, r.URL, r.Status, strings.Join(r.Issues, ","))
}
