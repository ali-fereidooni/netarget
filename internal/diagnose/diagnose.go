// Package diagnose turns layer results into a short diagnosis: the most
// likely root cause, its evidence, which other failures are only symptoms
// of it, and a prioritized fix list.
//
// Model: layers run in dependency order (registration → name servers →
// zone → reachability → web). A critical finding in an earlier layer
// explains critical findings and skipped layers after it, so it is the
// cause and they are symptoms. Within one layer, codes listed in
// sameLayerSymptoms are explained by a sibling cause.
package diagnose

import (
	"fmt"

	"domaindoctor/internal/checks"
)

type Cause struct {
	Code        string `json:"code"`
	Layer       string `json:"layer"`
	Title       string `json:"title"`
	Explanation string `json:"explanation"`
	Evidence    string `json:"evidence,omitempty"`
}

type Symptom struct {
	Code        string `json:"code"`
	Layer       string `json:"layer"`
	Message     string `json:"message"`
	ExplainedBy string `json:"explained_by"`
}

type Fix struct {
	Priority int    `json:"priority"` // 1 = do first
	Title    string `json:"title"`
	Action   string `json:"action"`
	Code     string `json:"code"`
	Layer    string `json:"layer"`
}

type Diagnosis struct {
	Healthy   bool      `json:"healthy"`
	Headline  string    `json:"headline"`
	RootCause *Cause    `json:"root_cause,omitempty"`
	Causes    []Cause   `json:"other_causes"`
	Symptoms  []Symptom `json:"symptoms"`
	Fixes     []Fix     `json:"fixes"`
}

// Codes explained by another code in the same layer when both are present.
var sameLayerSymptoms = map[string][]string{
	"ns.lame":               {"ns.none_usable"},
	"ns.unreachable":        {"ns.none_usable"},
	"ns.no_address":         {"ns.missing_glue"},
	"dns.resolver_servfail": {"dnssec.broken"},
	"dns.propagation":       {"dnssec.broken"},
	"dns.no_address_apex":   {"dns.cname_at_apex"},
	"reg.expired":           {"reg.redemption", "reg.pending_delete"},
}

// precedenceOrder ranks critical codes within one layer by the order a
// client runs into them (lower first). Unlisted codes rank after these.
var precedenceOrder = []string{
	"reg.not_registered", "reg.pending_delete", "reg.redemption", "reg.server_hold", "reg.client_hold", "reg.expired",
	"ns.checker_dns_blocked", "ns.parent_unreachable", "ns.no_delegation", "ns.none_usable", "ns.missing_glue", "ns.no_address",
	"dnssec.broken", "dns.nxdomain", "dns.cname_at_apex", "dns.no_address", "dns.dangling_cname",
	"reach.down_all",
	"web.timeout", "web.refused", "web.reset", "tls.handshake_failed", "tls.expired", "tls.not_yet_valid",
	"tls.hostname_mismatch", "tls.untrusted", "web.redirect_loop", "web.cdn_error", "web.5xx",
}

func precedence(code string) int {
	for i, c := range precedenceOrder {
		if c == code {
			return i
		}
	}
	return len(precedenceOrder)
}

type item struct {
	f     checks.Finding
	layer string
	idx   int // layer index
}

// Diagnose builds the diagnosis from layer results in execution order.
func Diagnose(results []*checks.Result) *Diagnosis {
	d := &Diagnosis{Causes: []Cause{}, Symptoms: []Symptom{}, Fixes: []Fix{}}
	layerIdx := map[string]int{}
	for i, l := range checks.LayerOrder {
		layerIdx[l] = i
	}
	present := map[string]bool{}
	var crit, warn []item
	for _, r := range results {
		for _, f := range r.Findings {
			present[f.Code] = true
			it := item{f: f, layer: r.Layer, idx: layerIdx[r.Layer]}
			switch f.Severity {
			case checks.Critical:
				crit = append(crit, it)
			case checks.Warning:
				warn = append(warn, it)
			}
		}
	}
	explainedBy := func(it item) string {
		for _, by := range sameLayerSymptoms[it.f.Code] {
			if present[by] {
				return by
			}
		}
		return ""
	}

	// Root cause: earliest layer first; within a layer, the failure a client
	// hits first (see precedence); never one explained by a sibling.
	var root *item
	for i := range crit {
		if explainedBy(crit[i]) != "" {
			continue
		}
		if root == nil || crit[i].idx < root.idx ||
			(crit[i].idx == root.idx && precedence(crit[i].f.Code) < precedence(root.f.Code)) {
			root = &crit[i]
		}
	}

	if root == nil && len(warn) == 0 {
		d.Healthy = true
		d.Headline = "No problems found: the domain is registered, delegated, resolves, and the website responds."
		return d
	}

	if root != nil {
		rule, _ := RuleFor(root.f.Code)
		title := rule.Title
		if title == "" {
			title = root.f.Message
		}
		d.RootCause = &Cause{Code: root.f.Code, Layer: root.layer, Title: title, Explanation: root.f.Message, Evidence: root.f.Evidence}
		d.Headline = title
	} else {
		d.Headline = "No blocking problem found, but there are warnings worth fixing."
	}

	// Classify remaining critical findings.
	for _, it := range crit {
		if root != nil && it.f.Code == root.f.Code && it.layer == root.layer {
			continue
		}
		if by := explainedBy(it); by != "" {
			d.Symptoms = append(d.Symptoms, Symptom{Code: it.f.Code, Layer: it.layer, Message: it.f.Message, ExplainedBy: by})
			continue
		}
		if root != nil && it.idx > root.idx {
			d.Symptoms = append(d.Symptoms, Symptom{Code: it.f.Code, Layer: it.layer, Message: it.f.Message, ExplainedBy: root.f.Code})
			continue
		}
		rule, _ := RuleFor(it.f.Code)
		d.Causes = append(d.Causes, Cause{Code: it.f.Code, Layer: it.layer, Title: firstNonEmpty(rule.Title, it.f.Message), Explanation: it.f.Message, Evidence: it.f.Evidence})
	}
	// Skipped layers are symptoms of whatever blocked them.
	for _, r := range results {
		if r.Status == checks.SKIPPED && root != nil && layerIdx[r.Layer] > root.idx {
			d.Symptoms = append(d.Symptoms, Symptom{Code: "skipped", Layer: r.Layer,
				Message: fmt.Sprintf("%s was not checked: %s", r.Title, r.SkipReason), ExplainedBy: root.f.Code})
		}
	}

	// Fixes: root cause, then independent causes, then warnings (deduped by code).
	seen := map[string]bool{}
	add := func(prio int, it item) {
		if seen[it.f.Code] {
			return
		}
		seen[it.f.Code] = true
		rule, ok := RuleFor(it.f.Code)
		action := rule.Fix
		if !ok || action == "" {
			action = it.f.Message
		}
		d.Fixes = append(d.Fixes, Fix{Priority: prio, Title: firstNonEmpty(rule.Title, it.f.Message), Action: action, Code: it.f.Code, Layer: it.layer})
	}
	if root != nil {
		add(1, *root)
	}
	for _, c := range crit {
		isSymptom := false
		for _, s := range d.Symptoms {
			if s.Code == c.f.Code {
				isSymptom = true
			}
		}
		if !isSymptom {
			add(2, c)
		}
	}
	for _, w := range warn {
		if by := explainedBy(w); by != "" || (root != nil && w.idx > root.idx && isNetworkSymptom(w.f.Code)) {
			continue
		}
		add(3, w)
	}
	return d
}

// isNetworkSymptom: warnings that are meaningless once an earlier layer failed hard.
func isNetworkSymptom(code string) bool {
	switch code {
	case "reach.partial", "reach.no_data", "web.partial", "web.no_data", "dns.propagation", "dns.resolver_servfail":
		return true
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
