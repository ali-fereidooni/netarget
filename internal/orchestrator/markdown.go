package orchestrator

import (
	"fmt"
	"strings"

	"domaindoctor/internal/checks"
	"domaindoctor/internal/probe"
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
			for _, c := range det.Chains {
				w("\n`%s`%s\n\n", c.Start, map[bool]string{true: " (redirect loop)", false: ""}[c.Loop])
				for _, h := range c.Hops {
					w("- %s → %s\n", h.URL, hopSummary(h))
				}
			}
			if len(det.Nodes) > 1 {
				w("\n| Node | URL | Final | Status | Total ms |\n|---|---|---|---|---|\n")
				for _, n := range det.Nodes {
					st := fmt.Sprint(n.Status)
					if n.ErrorKind != "" {
						st = n.ErrorKind
					}
					w("| %s | %s | %s | %s | %.0f |\n", n.Node, n.URL, n.FinalURL, st, n.TotalMS)
				}
			}
		}
	}
	return b.String()
}

func hopSummary(h probe.Hop) string {
	if h.ErrorKind != "" {
		return "error: " + h.ErrorKind
	}
	s := fmt.Sprintf("%d %s (%.0f ms)", h.Status, h.StatusText, h.Timing.TotalMS)
	if h.Location != "" {
		s += " Location: " + h.Location
	}
	return s
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "`", "'")
}
