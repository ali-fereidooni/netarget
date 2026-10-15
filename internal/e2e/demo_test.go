package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"domaindoctor/internal/api"
	"domaindoctor/internal/checks"
	"domaindoctor/internal/clientip"
	"domaindoctor/internal/input"
	"domaindoctor/internal/nodes"
	"domaindoctor/internal/orchestrator"
	"domaindoctor/internal/report"
	"domaindoctor/web"
)

type expectation struct {
	domain   string
	statuses []checks.Status
	root     string // "" = healthy
	codes    []string
}

var scenarios = []expectation{
	{"healthy-shop.com", []checks.Status{checks.OK, checks.OK, checks.OK, checks.OK, checks.OK}, "", []string{"dnssec.valid"}},
	{"https://WWW.Expired-Shop.com/cart", []checks.Status{checks.FAIL, checks.FAIL, checks.SKIPPED, checks.SKIPPED, checks.SKIPPED}, "reg.expired", []string{"ns.lame", "ns.none_usable"}},
	{"lame-shop.com", []checks.Status{checks.OK, checks.FAIL, checks.SKIPPED, checks.SKIPPED, checks.SKIPPED}, "ns.none_usable", []string{"ns.lame", "ns.unreachable"}},
	{"broken-web.com", []checks.Status{checks.OK, checks.OK, checks.OK, checks.OK, checks.FAIL}, "load.tls.expired", []string{"load.http.502.origin", "dnssec.unsigned"}},
}

// TestDemo runs every scenario end to end. With DEMO_WRITE=1 it writes the
// Markdown and JSON reports to docs/demo/.
func TestDemo(t *testing.T) {
	w := buildWorld(t)
	for _, sc := range scenarios {
		d, err := input.Normalize(sc.domain)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		rep := orchestrator.Run(ctx, w.deps, d, report.NewID(), func(orchestrator.Event) {})
		cancel()
		var got []checks.Status
		present := map[string]bool{}
		for _, l := range rep.Layers {
			got = append(got, l.Status)
			for _, f := range l.Findings {
				present[f.Code] = true
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(sc.statuses) {
			t.Errorf("%s: statuses %v, want %v", d.Name, got, sc.statuses)
			for _, l := range rep.Layers {
				t.Logf("  %s %s: %s", l.Layer, l.Status, l.Summary)
				for _, f := range l.Findings {
					t.Logf("    %s %s %s | %s", f.Severity, f.Code, f.Message, f.Evidence)
				}
			}
		}
		rootCode := ""
		if rep.Diagnosis.RootCause != nil {
			rootCode = rep.Diagnosis.RootCause.Code
		}
		if rootCode != sc.root {
			t.Errorf("%s: root cause %q, want %q (%s)", d.Name, rootCode, sc.root, rep.Diagnosis.Headline)
		}
		if sc.root == "" && !rep.Diagnosis.Healthy {
			t.Errorf("%s: not healthy: %+v", d.Name, rep.Diagnosis.Fixes)
		}
		for _, c := range sc.codes {
			if !present[c] {
				t.Errorf("%s: missing finding %s", d.Name, c)
			}
		}
		if os.Getenv("DEMO_WRITE") == "1" {
			dir := filepath.Join("..", "..", "docs", "demo")
			os.MkdirAll(dir, 0o755)
			os.WriteFile(filepath.Join(dir, d.Name+".md"), []byte(orchestrator.Markdown(rep)), 0o644)
			b, _ := json.MarshalIndent(rep, "", "  ")
			os.WriteFile(filepath.Join(dir, d.Name+".json"), b, 0o644)
		}
	}
}

// TestDemoServe starts the real master API + UI against the mock world and
// blocks, for manual/UI testing:  DEMO_SERVE=127.0.0.1:8099 go test ./internal/e2e -run TestDemoServe -timeout 0
func TestDemoServe(t *testing.T) {
	addr := os.Getenv("DEMO_SERVE")
	if addr == "" {
		t.Skip("set DEMO_SERVE=host:port to run the demo server")
	}
	w := buildWorld(t)
	store, err := report.OpenStore(t.TempDir(), 100, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := api.New(api.Config{Deps: w.deps, Registry: nodes.New(w.nodes...), ClientIP: clientip.Extractor{},
		Store: store, UI: web.Static(), Log: log.New(os.Stderr, "demo ", log.LstdFlags)})
	t.Logf("demo server on http://%s", addr)
	if err := http.ListenAndServe(addr, s.Handler()); err != nil {
		t.Fatal(err)
	}
}
