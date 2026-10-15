package orchestrator

import (
	"fmt"
	"sort"
	"strings"

	"domaindoctor/internal/checks"
	"domaindoctor/internal/fingerprint"
)

var statusIcon = map[checks.Status]string{checks.OK: "✅", checks.WARN: "⚠️", checks.FAIL: "❌", checks.SKIPPED: "⏭️"}

// Markdown renders a report for export.
func Markdown(rep *Report) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	name := rep.Domain.Name
	if rep.Domain.Unicode != "" && rep.Domain.Unicode != rep.Domain.Name {
		name = fmt.Sprintf("%s (%s)", rep.Domain.Unicode, rep.Domain.Name)
	}
	w("# Domain Doctor report: %s\n\n", name)
	w("- Checked: %s UTC\n- Request ID: `%s`\n", rep.StartedAt.Format("2006-01-02 15:04:05"), rep.ID)
	if len(rep.Nodes) > 0 {
		var ns []string
		for _, n := range rep.Nodes {
			ns = append(ns, fmt.Sprintf("%s (%s)", n.Name, n.Location))
		}
		w("- Measurement nodes: %s\n", strings.Join(ns, ", "))
	}
	w("\n## Diagnosis\n\n")
	if d := rep.Diagnosis; d != nil {
		w("**%s**\n\n", d.Headline)
		if d.RootCause != nil {
			w("- Root cause (%s): %s\n", d.RootCause.Layer, d.RootCause.Explanation)
			if d.RootCause.Evidence != "" {
				w("- Evidence: `%s`\n", mdEscape(d.RootCause.Evidence))
			}
		}
		for _, c := range d.Causes {
			w("- Also a cause (%s): %s\n", c.Layer, c.Explanation)
		}
		if len(d.Symptoms) > 0 {
			w("\nSymptoms explained by the cause:\n\n")
			for _, s := range d.Symptoms {
				w("- %s — explained by `%s`\n", s.Message, s.ExplainedBy)
			}
		}
		if len(d.Fixes) > 0 {
			w("\n### Fixes (in priority order)\n\n")
			for i, f := range d.Fixes {
				w("%d. **%s** — %s\n", i+1, f.Title, f.Action)
			}
		}
	}
	w("\n## Checks\n\n| Step | Status | Summary |\n|---|---|---|\n")
	for _, l := range rep.Layers {
		w("| %s | %s %s | %s |\n", l.Title, statusIcon[l.Status], l.Status, mdEscape(l.Summary))
	}
	for _, l := range rep.Layers {
		w("\n### %s %s — %s\n\n", statusIcon[l.Status], l.Title, l.Status)
		if l.Status == checks.SKIPPED {
			w("Skipped: %s\n", l.SkipReason)
			continue
		}
		for _, f := range l.Findings {
			w("- **%s** `%s` %s", strings.ToUpper(string(f.Severity)), f.Code, f.Message)
			if f.Evidence != "" {
				w(" (`%s`)", mdEscape(f.Evidence))
			}
			w("\n")
		}
		switch det := l.Details.(type) {
		case *checks.NSDetails:
			if len(det.Servers) > 0 {
				w("\n| Name server | IP | Status | AA | Serial | RTT ms |\n|---|---|---|---|---|---|\n")
				for _, s := range det.Servers {
					for _, p := range s.Probes {
						w("| %s | %s | %s | %v | %d | %.1f |\n", s.Name, p.IP, p.Status, p.AA, p.Serial, p.RTTms)
					}
				}
			}
		case *checks.ZoneDetails:
			if len(det.Records) > 0 {
				w("\n| Name | Type | TTL | Value |\n|---|---|---|---|\n")
				for _, r := range det.Records {
					w("| %s | %s | %d | %s |\n", r.Name, r.Type, r.TTL, mdEscape(r.Value))
				}
			}
		case *checks.ReachDetails:
			w("\n| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |\n|---|---|---|---|---|---|---|---|---|\n")
			for _, r := range det.Rows {
				if r.Status == "n/a" || r.Status == "error" {
					w("| %s | %s | — | — | — | %s | — | — | %s |\n", r.Node, r.IP, mdEscape(r.Note), r.Status)
					continue
				}
				w("| %s | %s | %d | %d | %.0f%% | %.1f/%.1f/%.1f | %s | %s | %s |\n", r.Node, r.IP, r.Sent, r.Received, r.Loss, r.RTTMin, r.RTTAvg, r.RTTMax, r.TCP80, r.TCP443, r.Status)
			}
		case *checks.WebDetails:
			webMarkdown(w, det)
		}
	}
	return b.String()
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "`", "'")
}

// webMarkdown renders the Website load section: verdict, evidence, fixes
// (snippets for the detected server, or all of them), what could not be
// determined, fingerprints, the request matrix and the resources.
func webMarkdown(w func(string, ...any), det *checks.WebDetails) {
	if v := det.Verdict; v != nil {
		w("\n**Verdict:** %s\n\n", v.Text)
		w("- Layer at fault: **%s** (confidence %s, %.0f%%)\n", v.Layer, v.Level, v.Confidence*100)
		if v.SymptomOf != "" {
			w("- This is a symptom of `%s`, found in an earlier step; fix that first.\n", v.SymptomOf)
		}
		if det.OriginIP != "" {
			w("- Origin-direct test against %s was included.\n", det.OriginIP)
		}
		if len(v.Evidence) > 0 {
			w("\nEvidence:\n\n")
			for _, e := range v.Evidence {
				w("- `%s`\n", mdEscape(e))
			}
		}
		if len(v.Causes) > 0 {
			w("\nLikely causes:\n\n")
			for _, c := range v.Causes {
				w("- (%s) %s\n", c.Likelihood, c.Text)
			}
		}
		server := ""
		if det.Fingerprints != nil {
			if s := det.Fingerprints.Primary("server"); s != nil {
				server = s.ID
			}
		}
		if len(v.Fixes) > 0 {
			w("\nFix steps:\n\n")
			for i, f := range v.Fixes {
				w("%d. %s\n", i+1, f.Step)
				if f.Why != "" {
					w("   - Why: %s\n", f.Why)
				}
				keys := snippetKeys(f.Snippets, server)
				for _, k := range keys {
					w("\n   %s:\n\n   ```\n", k)
					for _, line := range strings.Split(f.Snippets[k], "\n") {
						w("   %s\n", line)
					}
					w("   ```\n\n")
				}
				w("   - Verify: %s\n", f.Verify)
				if f.Warning != "" {
					w("   - Warning: %s\n", f.Warning)
				}
			}
		}
		for _, x := range v.Warnings {
			w("\n> Warning: %s\n", x)
		}
		if len(v.CannotDetermine) > 0 {
			w("\nCould not determine from outside:\n\n")
			for _, x := range v.CannotDetermine {
				w("- %s\n", x)
			}
		}
	}
	if fp := det.Fingerprints; fp != nil {
		var rows []string
		for _, list := range [][]fingerprint.Detection{fp.CDN, fp.Server, fp.Platform} {
			for _, d := range list {
				rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s |", d.Kind, d.Name, d.Level, mdEscape(strings.Join(d.Evidence, "; "))))
			}
		}
		if len(rows) > 0 {
			w("\n| Kind | Detected | Confidence | Evidence |\n|---|---|---|---|\n%s\n", strings.Join(rows, "\n"))
		}
	}
	if len(det.Matrix) > 0 {
		w("\n| Node | Request | Final | Result | Proto | TTFB ms | Total ms | Differs |\n|---|---|---|---|---|---|---|---|\n")
		for _, r := range det.Matrix {
			res := fmt.Sprint(r.Status)
			if r.ErrorKind != "" {
				res = r.ErrorKind
			}
			if r.Loop {
				res = "redirect loop"
			}
			diff := ""
			if r.Diff {
				diff = "yes"
			}
			w("| %s | %s | %s | %s | %s | %.0f | %.0f | %s |\n", r.Node, mdEscape(r.Label), r.FinalURL, res, r.Proto, r.TTFBms, r.TotalMS, diff)
		}
	}
	if res := det.Resources; res != nil && len(res.Resources) > 0 {
		w("\nResources (%d found, %d checked):\n\n| Kind | URL | Status | ms | Size | Issues |\n|---|---|---|---|---|---|\n", res.Page.Found, res.Page.Checked)
		for _, x := range res.Resources {
			st := fmt.Sprint(x.Status)
			if x.ErrorKind != "" {
				st = x.ErrorKind
			}
			w("| %s | %s | %s | %.0f | %d | %s |\n", x.Kind, mdEscape(x.URL), st, x.TotalMS, x.Size, strings.Join(x.Issues, ", "))
		}
	}
	for _, m := range det.Matches {
		if det.Verdict != nil && m.RuleID == det.Verdict.RuleID {
			continue
		}
		w("\n- Also: **%s** — %s (%s, %s)\n", m.Title, m.Verdict, m.Severity, m.Level)
	}
}

// snippetKeys returns the snippet for the detected server (plus generic
// targets) when known, otherwise every snippet, in a stable order.
func snippetKeys(sn map[string]string, server string) []string {
	var keys []string
	for k := range sn {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if server == "" {
		return keys
	}
	var out []string
	serverKinds := map[string]bool{"apache": true, "nginx": true, "litespeed": true, "iis": true, "caddy": true}
	for _, k := range keys {
		if k == server || !serverKinds[k] {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return keys
	}
	return out
}
