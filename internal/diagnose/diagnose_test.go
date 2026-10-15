package diagnose

import (
	"strings"
	"testing"

	"domaindoctor/internal/checks"
)

func res(layer string, status checks.Status, fs ...checks.Finding) *checks.Result {
	r := checks.NewResult(layer)
	r.Findings = fs
	r.Status = status
	return r
}

func f(code string, sev checks.Severity) checks.Finding {
	return checks.Finding{Code: code, Severity: sev, Message: code + " message"}
}

func TestHealthy(t *testing.T) {
	d := Diagnose([]*checks.Result{
		res(checks.LayerRegistration, checks.OK, f("reg.ok", checks.Info)),
		res(checks.LayerWeb, checks.OK),
	})
	if !d.Healthy || d.RootCause != nil || len(d.Fixes) != 0 {
		t.Fatalf("%+v", d)
	}
}

func TestExpiredExplainsEverything(t *testing.T) {
	skipped := checks.Skipped(checks.LayerReach, "no A/AAAA records")
	d := Diagnose([]*checks.Result{
		res(checks.LayerRegistration, checks.FAIL, f("reg.expired", checks.Critical)),
		res(checks.LayerNameservers, checks.FAIL, f("ns.lame", checks.Critical), f("ns.none_usable", checks.Critical)),
		res(checks.LayerZone, checks.FAIL, f("dns.no_address", checks.Critical), f("mail.dmarc_missing", checks.Warning)),
		skipped,
		res(checks.LayerWeb, checks.FAIL, f("load.conn.timeout", checks.Critical), f("load.site.regional", checks.Warning)),
	})
	if d.RootCause == nil || d.RootCause.Code != "reg.expired" {
		t.Fatalf("root %+v", d.RootCause)
	}
	if len(d.Causes) != 0 {
		t.Fatalf("other causes should be empty: %+v", d.Causes)
	}
	want := map[string]string{"ns.lame": "ns.none_usable", "ns.none_usable": "reg.expired", "dns.no_address": "reg.expired", "load.conn.timeout": "reg.expired", "skipped": "reg.expired"}
	got := map[string]string{}
	for _, s := range d.Symptoms {
		got[s.Code] = s.ExplainedBy
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("symptom %s explained by %q, want %q", k, got[k], v)
		}
	}
	if d.Fixes[0].Code != "reg.expired" || d.Fixes[0].Priority != 1 {
		t.Fatalf("first fix %+v", d.Fixes[0])
	}
	for _, fx := range d.Fixes {
		if fx.Code == "load.site.regional" || fx.Code == "load.conn.timeout" {
			t.Errorf("symptom %s should not get its own fix", fx.Code)
		}
	}
}

func TestLameDelegationRoot(t *testing.T) {
	d := Diagnose([]*checks.Result{
		res(checks.LayerRegistration, checks.OK, f("reg.ok", checks.Info)),
		res(checks.LayerNameservers, checks.FAIL, f("ns.lame", checks.Critical), f("ns.unreachable", checks.Critical), f("ns.none_usable", checks.Critical)),
		checks.Skipped(checks.LayerZone, "no authoritative name server answered"),
	})
	if d.RootCause.Code != "ns.none_usable" {
		t.Fatalf("root %+v", d.RootCause)
	}
}

func TestWarningsOnly(t *testing.T) {
	d := Diagnose([]*checks.Result{
		res(checks.LayerZone, checks.WARN, f("mail.spf_missing", checks.Warning)),
		res(checks.LayerWeb, checks.WARN, f("web.no_hsts", checks.Warning)),
	})
	if d.Healthy || d.RootCause != nil || len(d.Fixes) != 2 || d.Fixes[0].Priority != 3 {
		t.Fatalf("%+v", d)
	}
}

func TestIndependentCauses(t *testing.T) {
	// Two unrelated critical findings in the same layer: the one clients hit
	// first (broken DNSSEC → SERVFAIL everywhere) is root; the other stays an
	// independent cause with its own fix.
	d := Diagnose([]*checks.Result{
		res(checks.LayerZone, checks.FAIL, f("dns.cname_at_apex", checks.Critical), f("dnssec.broken", checks.Critical), f("dns.resolver_servfail", checks.Warning)),
	})
	if d.RootCause.Code != "dnssec.broken" || len(d.Causes) != 1 || d.Causes[0].Code != "dns.cname_at_apex" {
		t.Fatalf("%+v", d)
	}
	for _, fx := range d.Fixes {
		if fx.Code == "dns.resolver_servfail" {
			t.Fatal("servfail explained by dnssec.broken should not get a fix")
		}
	}
}

func TestPrecedenceWithinWeb(t *testing.T) {
	// Website-load findings arrive in the knowledge base's ranked order
	// (expired certificate before the 502); diagnosis keeps that order and
	// takes title/fix text from the knowledge base.
	d := Diagnose([]*checks.Result{
		res(checks.LayerWeb, checks.FAIL, f("load.tls.expired", checks.Critical), f("load.http.502.origin", checks.Critical)),
	})
	if d.RootCause.Code != "load.tls.expired" || d.Causes[0].Code != "load.http.502.origin" || d.Fixes[0].Code != "load.tls.expired" {
		t.Fatalf("%+v", d)
	}
	if d.RootCause.Title != "Expired TLS certificate" || !strings.Contains(d.Fixes[0].Action, "Renew the certificate") {
		t.Fatalf("KB text not used: %+v / %+v", d.RootCause, d.Fixes[0])
	}
}

func TestEveryRuleHasFix(t *testing.T) {
	for code, r := range rules {
		if r.Title == "" || r.Fix == "" {
			t.Errorf("rule %s incomplete", code)
		}
	}
}
