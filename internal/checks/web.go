package checks

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"domaindoctor/internal/fingerprint"
	"domaindoctor/internal/kb"
	"domaindoctor/internal/nodes"
	"domaindoctor/internal/probe"
)

// Website load (step 5). Go code only collects facts — the request matrix
// from every node, subresources from the primary node, fingerprints and
// derived signals. All verdicts and advice come from the knowledge base
// (rules/kb/*.yaml), evaluated against the canonical request.

type WebNodeRow struct {
	Node      string  `json:"node"`
	Location  string  `json:"location"`
	URL       string  `json:"url"`
	FinalURL  string  `json:"final_url,omitempty"`
	Status    int     `json:"status,omitempty"`
	ErrorKind string  `json:"error_kind,omitempty"`
	Hops      int     `json:"hops"`
	TotalMS   float64 `json:"total_ms"`
	OK        bool    `json:"ok"`
}

// Verdict is the one-line answer plus everything needed to act on it.
type Verdict struct {
	Text            string     `json:"text"`
	Layer           string     `json:"layer"` // dns, cdn, network, tls, server, application, content, none
	Confidence      float64    `json:"confidence"`
	Level           string     `json:"level"`
	RuleID          string     `json:"rule_id,omitempty"`
	Evidence        []string   `json:"evidence"`
	Causes          []kb.Cause `json:"causes,omitempty"`
	Fixes           []kb.Fix   `json:"fixes,omitempty"`
	CannotDetermine []string   `json:"cannot_determine,omitempty"`
	Warnings        []string   `json:"warnings,omitempty"`
	SymptomOf       string     `json:"symptom_of,omitempty"` // set by the orchestrator when an earlier layer explains it
}

type WebDetails struct {
	PrimaryNode  string                    `json:"primary_node"`
	Canonical    string                    `json:"canonical"` // request the verdict is based on
	Verdict      *Verdict                  `json:"verdict,omitempty"`
	Matches      []kb.MatchResult          `json:"matches,omitempty"`
	Fingerprints *fingerprint.Result       `json:"fingerprints,omitempty"`
	Signals      []Signal                  `json:"signals,omitempty"`
	Matrix       []MatrixRow               `json:"matrix,omitempty"`
	Resources    *probe.ResourceResponse   `json:"resources,omitempty"`
	OriginIP     string                    `json:"origin_ip,omitempty"`
	Chains       []probe.Chain             `json:"chains"` // baseline chains of the primary node
	Nodes        []WebNodeRow              `json:"nodes"`
	TLS          map[string]*probe.TLSInfo `json:"tls,omitempty"`
}

func chainOK(c *probe.Chain) bool {
	f := c.Final()
	return f != nil && !c.Loop && f.ErrorKind == "" && f.Status > 0 && f.Status < 400
}

type nodeMatrix struct {
	node *nodes.Node
	resp *probe.HTTPResponse
	err  error
	view matrixView
}

// Web runs the Website Load troubleshooter.
func Web(ctx context.Context, st *State, ns []*nodes.Node, now time.Time) *Result {
	if len(ns) == 0 {
		return Skipped(LayerWeb, "no measurement nodes are available")
	}
	host := strings.TrimSuffix(st.Domain, ".")
	apex := strings.TrimSuffix(st.Apex, ".")
	pinned := map[string][]netip.Addr{}
	hosts := []string{}
	if len(st.ApexV4)+len(st.ApexV6) > 0 {
		pinned[host] = pinList(st.ApexV4, st.ApexV6)
		hosts = append(hosts, host)
	}
	www := "www." + apex
	if host == apex && len(st.WWWV4)+len(st.WWWV6) > 0 {
		pinned[www] = pinList(st.WWWV4, st.WWWV6)
		hosts = append(hosts, www)
	}
	if len(hosts) == 0 {
		return Skipped(LayerWeb, "the domain has no A/AAAA records to test")
	}
	main := hosts[0]
	hasWWW := len(hosts) == 2
	specs := buildSpecs(hosts, st.OriginIP)

	r := NewResult(LayerWeb)
	det := &WebDetails{TLS: map[string]*probe.TLSInfo{}, Nodes: []WebNodeRow{}, Matrix: []MatrixRow{}, Canonical: "GET https://" + main + "/ (browser)"}
	if st.OriginIP.IsValid() {
		det.OriginIP = st.OriginIP.String()
	}
	r.Details = det

	results := nodes.Fanout(ctx, ns, 8, func(ctx context.Context, n *nodes.Node) nodeMatrix {
		cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		resp, err := n.P.HTTP(cctx, probe.HTTPRequest{Pinned: pinned, Specs: specs})
		if err == nil && (resp == nil || len(resp.Results) != len(specs)) {
			err = fmt.Errorf("agent unreachable")
		}
		nm := nodeMatrix{node: n, resp: resp, err: err, view: matrixView{}}
		if err == nil {
			for _, sr := range resp.Results {
				nm.view[sr.Spec.ID] = sr
			}
		}
		return nm
	})

	var primary *nodeMatrix
	var others []matrixView
	for i := range results {
		nm := &results[i]
		if nm.err != nil {
			for _, s := range specs {
				if strings.HasPrefix(s.ID, "base:") {
					det.Nodes = append(det.Nodes, WebNodeRow{Node: nm.node.Name, Location: nm.node.Location, URL: s.URL, ErrorKind: "agent_unreachable"})
				}
			}
			continue
		}
		if primary == nil {
			primary = nm
		} else {
			others = append(others, nm.view)
		}
		for _, sr := range nm.resp.Results {
			row := rowFrom(nm.node.Name, sr)
			det.Matrix = append(det.Matrix, row)
			if strings.HasPrefix(sr.Spec.ID, "base:") {
				c := sr.Chain
				wr := WebNodeRow{Node: nm.node.Name, Location: nm.node.Location, URL: sr.Spec.URL, Hops: len(c.Hops), OK: chainOK(&c)}
				if f := c.Final(); f != nil {
					wr.FinalURL, wr.Status, wr.ErrorKind = f.URL, f.Status, f.ErrorKind
					for _, h := range c.Hops {
						wr.TotalMS += h.Timing.TotalMS
					}
				}
				if c.Loop {
					wr.ErrorKind = "redirect_loop"
				}
				det.Nodes = append(det.Nodes, wr)
			}
		}
	}
	if primary == nil {
		r.Add("web.no_data", Warning, "No measurement node could run the website checks.", "all agents unreachable")
		return r.Finish("No measurements")
	}
	det.PrimaryNode = primary.node.Name
	markDiffs(det.Matrix, primary.node.Name)
	for _, s := range specs {
		if strings.HasPrefix(s.ID, "base:") {
			det.Chains = append(det.Chains, primary.view[s.ID].Chain)
		}
	}
	for _, h := range hosts {
		if sr, ok := primary.view["base:https:"+h]; ok && len(sr.Chain.Hops) > 0 && sr.Chain.Hops[0].TLS != nil {
			det.TLS[h] = sr.Chain.Hops[0].TLS
		}
	}

	// Subresources from the primary node, when the page itself loads.
	canonical, _ := primary.view.final("base:https:" + main)
	signals := deriveSignals(primary.view, main, hasWWW, others)
	if canonical != nil && canonical.ErrorKind == "" && canonical.Status > 0 && canonical.Status < 400 {
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		res, err := primary.node.P.Resources(cctx, probe.ResourceRequest{PageURL: canonical.URL, Pinned: pinned, Max: probe.MaxResources, Site: apex})
		cancel()
		if err == nil && res != nil {
			det.Resources = res
			signals = append(signals, resourceSignals(res)...)
		}
	}

	// Fingerprints from every sampled response of the primary node.
	fp := fingerprintAll(primary.view, st, pinned)
	det.Fingerprints = fp
	if c := fp.Primary("cdn"); c != nil {
		signals = append(signals, Signal{Name: "cdn_detected", Evidence: fmt.Sprintf("%s (%s confidence)", c.Name, c.Level)})
	} else {
		signals = append(signals, Signal{Name: "no_cdn", Evidence: "no CDN or WAF detected with at least medium confidence"})
	}
	sort.SliceStable(signals, func(i, j int) bool { return signals[i].Name < signals[j].Name })
	det.Signals = dedupeSignals(signals)

	obs := observation(main, canonical, fp, det.Signals)
	base := kb.MustDefault()
	matches := base.Evaluate(obs)
	det.Matches = matches

	sevMap := map[string]Severity{"fail": Critical, "warn": Warning, "info": Info}
	for _, m := range matches {
		r.Add("load."+m.RuleID, sevMap[m.Severity], m.Verdict, strings.Join(firstN(m.Evidence, 3), "; "))
	}
	det.Verdict = verdictFrom(matches, canonical, primary.view, main)
	summary := det.Verdict.Text
	if canonical != nil && canonical.ErrorKind == "" && canonical.Status > 0 {
		summary = fmt.Sprintf("%s → %d in %.0f ms — %s", "https://"+main+"/", canonical.Status, canonical.Timing.TotalMS, det.Verdict.Text)
	}
	// Raw page bodies were only needed for fingerprints and signals; they
	// never go into reports (size, and no "fetch any page for me" proxy).
	for i := range det.Chains {
		for j := range det.Chains[i].Hops {
			det.Chains[i].Hops[j].BodySample = ""
		}
	}
	return r.Finish(summary)
}

// fingerprintAll feeds every sampled response (all hops with headers) to the detector.
func fingerprintAll(v matrixView, st *State, pinned map[string][]netip.Addr) *fingerprint.Result {
	sigs, err := fingerprint.Signatures()
	if err != nil {
		return &fingerprint.Result{NoCDN: true}
	}
	in := fingerprint.Input{CNAMEs: st.CNAMEs}
	for _, ips := range pinned {
		in.IPs = append(in.IPs, ips...)
	}
	ids := make([]string, 0, len(v))
	for id := range v {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		sr := v[id]
		for _, h := range sr.Chain.Hops {
			if h.AllHeaders == nil && h.Server == "" {
				continue
			}
			s := fingerprint.Sample{Source: fmt.Sprintf("%s %s", sr.Spec.Method, h.URL), Status: h.Status, Headers: h.AllHeaders, Cookies: h.Cookies, Body: h.BodySample}
			if s.Headers == nil {
				s.Headers = map[string][]string{"server": {h.Server}}
			}
			if strings.HasPrefix(id, "origin:") {
				s.Source += " (origin direct)"
			}
			if h.TLS != nil {
				s.TLSIssuer = h.TLS.Issuer
			}
			in.Samples = append(in.Samples, s)
		}
	}
	return fingerprint.Detect(sigs, in)
}

func observation(host string, h *probe.Hop, fp *fingerprint.Result, signals []Signal) *kb.Observation {
	o := &kb.Observation{Host: host, URL: "https://" + host + "/", Request: "GET https://" + host + "/ (browser UA)",
		Headers: map[string][]string{}, Names: map[string]string{}, Signals: map[string]string{}, Values: map[string]string{}}
	if h != nil {
		o.Status, o.ErrorKind, o.Body = h.Status, h.ErrorKind, h.BodySample
		if h.AllHeaders != nil {
			o.Headers = h.AllHeaders
		}
		if h.URL != o.URL {
			o.Request += " → " + h.URL
		}
		if m := reCFCode.FindStringSubmatch(h.BodySample); m != nil {
			o.Values["cf_code"] = "error " + firstNonEmpty(m[1], m[2])
		}
	}
	for _, list := range [][]fingerprint.Detection{fp.CDN, fp.Server, fp.Platform} {
		for _, d := range list {
			o.Names[d.ID] = d.Name
		}
	}
	if d := fp.Primary("cdn"); d != nil {
		o.CDN = d.ID
	}
	if d := fp.Primary("server"); d != nil {
		o.Server = d.ID
	}
	if d := fp.Primary("platform"); d != nil {
		o.Platform = d.ID
	}
	for _, s := range signals {
		o.Signals[s.Name] = s.Evidence
	}
	return o
}

func verdictFrom(ms []kb.MatchResult, canonical *probe.Hop, v matrixView, host string) *Verdict {
	for _, m := range ms {
		if m.Severity == "info" {
			continue
		}
		return &Verdict{Text: m.Verdict, Layer: m.Layer, Confidence: m.Confidence, Level: m.Level, RuleID: m.RuleID,
			Evidence: m.Evidence, Causes: m.Causes, Fixes: m.Fixes, CannotDetermine: m.CannotDetermine, Warnings: m.Warnings}
	}
	ev := []string{describeHop("base:https:"+host, v)}
	if canonical != nil && canonical.ErrorKind == "" && canonical.Status >= 200 && canonical.Status < 400 {
		return &Verdict{Text: "The website loads normally from every measurement node", Layer: "none", Confidence: 0.9, Level: "high", Evidence: ev,
			CannotDetermine: []string{"Problems that only appear for logged-in users, specific pages or after JavaScript runs."}}
	}
	return &Verdict{Text: "The website did not load, and no knowledge-base rule matched the response", Layer: "server", Confidence: 0.3, Level: "low", Evidence: ev,
		CannotDetermine: []string{"The server-side reason (check the web server and application logs)."}}
}

func resourceSignals(res *probe.ResourceResponse) []Signal {
	var out []Signal
	byIssue := map[string][]string{}
	thirdFail := []string{}
	for _, x := range res.Resources {
		for _, i := range x.Issues {
			byIssue[i] = append(byIssue[i], x.URL)
		}
		if x.ThirdParty && contains(x.Issues, "failed") {
			thirdFail = append(thirdFail, x.Host)
		}
	}
	add := func(name, issue, what string) {
		if urls := byIssue[issue]; len(urls) > 0 {
			out = append(out, Signal{Name: name, Evidence: fmt.Sprintf("%d %s: %s", len(urls), what, strings.Join(firstN(urls, 3), ", "))})
		}
	}
	add("res_failed", "failed", "resource(s) failed to load")
	add("res_slow", "slow", "resource(s) took over 2 s")
	add("res_mixed_content", "mixed_content", "HTTP resource(s) on the HTTPS page")
	add("res_wrong_mime", "wrong_mime", "resource(s) with an unexpected Content-Type")
	add("res_blocked_mime", "blocked_mime", "script/style(s) blocked by nosniff + wrong Content-Type")
	add("res_uncompressed", "uncompressed", "text resource(s) sent uncompressed")
	add("res_weak_cache", "weak_cache", "static resource(s) without useful caching")
	add("res_cors", "cors", "cross-origin resource(s) without Access-Control-Allow-Origin")
	if len(thirdFail) > 0 {
		out = append(out, Signal{Name: "res_third_party_failed", Evidence: "third-party hosts failing: " + strings.Join(firstN(thirdFail, 3), ", ")})
	}
	return out
}

// markDiffs flags matrix rows whose outcome differs from the node's baseline browser request.
func markDiffs(rows []MatrixRow, _ string) {
	base := map[string]MatrixRow{}
	for _, r := range rows {
		if strings.HasPrefix(r.SpecID, "base:https:") && !strings.Contains(r.SpecID, ":www.") {
			base[r.Node] = r
		}
	}
	for i := range rows {
		b, ok := base[rows[i].Node]
		if !ok || strings.HasPrefix(rows[i].SpecID, "base:") {
			continue
		}
		if rows[i].Status/100 != b.Status/100 || rows[i].ErrorKind != b.ErrorKind || rows[i].Loop != b.Loop {
			rows[i].Diff = true
		}
	}
}

// pinList keeps up to 2 IPv4 + 2 IPv6 addresses (agents accept at most 8 per host).
func pinList(v4, v6 []netip.Addr) []netip.Addr {
	out := append([]netip.Addr{}, v4[:min(2, len(v4))]...)
	return append(out, v6[:min(2, len(v6))]...)
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
