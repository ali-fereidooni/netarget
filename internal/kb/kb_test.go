package kb

import (
	"strings"
	"testing"
	"testing/fstest"
)

// TestEmbeddedRulesLoad fails on any malformed rule file.
func TestEmbeddedRulesLoad(t *testing.T) {
	k, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Rules) < 10 {
		t.Fatalf("only %d rules loaded", len(k.Rules))
	}
}

// TestRuleFixtures runs every rule's own fixtures against that rule alone.
func TestRuleFixtures(t *testing.T) {
	k, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	for i := range k.Rules {
		r := &k.Rules[i]
		for _, tc := range r.Tests {
			t.Run(r.ID+"/"+tc.Name, func(t *testing.T) {
				m, ok := r.evaluate(ObservationFromGiven(tc.Given))
				switch tc.Expect {
				case "match":
					if !ok {
						t.Fatalf("expected %s to match %+v", r.ID, tc.Given)
					}
					if m.Confidence < tc.MinConfidence {
						t.Fatalf("confidence %.2f < %.2f", m.Confidence, tc.MinConfidence)
					}
					if strings.Contains(m.Verdict, "{") && strings.Contains(m.Verdict, "}") && !strings.Contains(r.Verdict, "%{") {
						for _, v := range TemplateVars {
							if strings.Contains(m.Verdict, "{"+v+"}") {
								t.Fatalf("unrendered template in verdict: %s", m.Verdict)
							}
						}
					}
				case "no_match":
					if ok {
						t.Fatalf("expected %s not to match %+v", r.ID, tc.Given)
					}
				}
			})
		}
	}
}

// TestEveryRuleHasPositiveFixture is enforced by Validate; double-check here.
func TestEveryRuleHasPositiveFixture(t *testing.T) {
	for _, r := range MustDefault().Rules {
		pos := 0
		for _, tc := range r.Tests {
			if tc.Expect == "match" {
				pos++
			}
		}
		if pos == 0 {
			t.Errorf("%s has no positive fixture", r.ID)
		}
	}
}

const goodRule = `
- id: test.ok
  title: T
  layer: server
  severity: fail
  match: {all: [{status: [500]}]}
  confidence: {base: 0.5}
  verdict: "v {host}"
  causes: [{text: c, likelihood: high}]
  fixes: [{step: s, verify: v}]
  cannot_determine: [logs]
  tests: [{name: t, given: {status: 500}, expect: match}]
`

func TestValidateRejectsMalformedRules(t *testing.T) {
	if _, err := Parse([]byte(goodRule), "good.yaml"); err != nil {
		t.Fatalf("good rule rejected: %v", err)
	}
	bad := map[string]string{
		"unknown field":         strings.Replace(goodRule, "severity: fail", "severity: fail\n  colour: red", 1),
		"bad layer":             strings.Replace(goodRule, "layer: server", "layer: kernel", 1),
		"bad severity":          strings.Replace(goodRule, "severity: fail", "severity: panic", 1),
		"bad id":                strings.Replace(goodRule, "id: test.ok", "id: Test OK", 1),
		"two fields in a cond":  strings.Replace(goodRule, "{status: [500]}", "{status: [500], signal: https_ok}", 1),
		"unknown signal":        strings.Replace(goodRule, "{status: [500]}", "{signal: made_up}", 1),
		"bad regex":             strings.Replace(goodRule, "{status: [500]}", "{body: '('}", 1),
		"bad status range":      strings.Replace(goodRule, "{status: [500]}", "{status_range: '599-500'}", 1),
		"unknown template":      strings.Replace(goodRule, "v {host}", "v {password}", 1),
		"no fixes":              strings.Replace(goodRule, "fixes: [{step: s, verify: v}]", "fixes: []", 1),
		"fix without verify":    strings.Replace(goodRule, "fixes: [{step: s, verify: v}]", "fixes: [{step: s}]", 1),
		"no cannot_determine":   strings.Replace(goodRule, "cannot_determine: [logs]", "cannot_determine: []", 1),
		"no positive test":      strings.Replace(goodRule, "expect: match", "expect: no_match", 1),
		"bad likelihood":        strings.Replace(goodRule, "likelihood: high", "likelihood: sure", 1),
		"unknown snippet key":   strings.Replace(goodRule, "{step: s, verify: v}", "{step: s, verify: v, snippets: {cpanel: x}}", 1),
		"chmod 777":             strings.Replace(goodRule, "{step: s, verify: v}", "{step: 'chmod -R 777 /var/www', verify: v}", 1),
		"chmod 777 with warn":   strings.Replace(goodRule, "{step: s, verify: v}", "{step: s, verify: v}, {step: 'chmod 777 x', verify: v, warning: w}", 1),
		"disable WAF first fix": strings.Replace(goodRule, "{step: s, verify: v}", "{step: 'Disable ModSecurity', verify: v}", 1),
		"SecRuleEngine Off":     strings.Replace(goodRule, "{step: s, verify: v}", "{step: s, verify: v, snippets: {apache: 'SecRuleEngine Off'}}", 1),
		"boost without why":     strings.Replace(goodRule, "{base: 0.5}", "{base: 0.5, boosts: [{when: {status: [500]}, add: 0.1}]}", 1),
	}
	for name, src := range bad {
		if _, err := Parse([]byte(src), name+".yaml"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A risky step is allowed only as a later fix with a warning.
	ok := strings.Replace(goodRule, "{step: s, verify: v}", "{step: s, verify: v}, {step: 'If nothing else works, disable mod_security for this path only', verify: v, warning: 'lowers protection'}", 1)
	if _, err := Parse([]byte(ok), "ok.yaml"); err != nil {
		t.Errorf("warned later fix rejected: %v", err)
	}
}

func TestLoadRejectsDuplicates(t *testing.T) {
	fsys := fstest.MapFS{"kb/a.yaml": {Data: []byte(goodRule)}, "kb/b.yaml": {Data: []byte(goodRule)}}
	if _, err := Load(fsys, "kb"); err == nil {
		t.Fatal("duplicate ids accepted")
	}
}

func TestEvaluateRankingAndGroups(t *testing.T) {
	k := MustDefault()
	o := ObservationFromGiven(Given{Status: 525, CDN: "cloudflare", Signals: []string{"origin_https_fail"}})
	o.Names["cloudflare"] = "Cloudflare"
	ms := k.Evaluate(o)
	if len(ms) == 0 || ms[0].RuleID != "cf.525" {
		t.Fatalf("top match %+v", ms)
	}
	groups := map[string]int{}
	for _, m := range ms {
		if m.Group != "" {
			groups[m.Group]++
		}
	}
	for g, n := range groups {
		if n > 1 {
			t.Errorf("group %s reported %d times", g, n)
		}
	}
	if !strings.Contains(ms[0].Verdict, "Cloudflare") || strings.Contains(ms[0].Fixes[0].Snippets["nginx"], "{host}") {
		t.Errorf("templates not rendered: %q / %q", ms[0].Verdict, ms[0].Fixes[0].Snippets["nginx"])
	}
}
