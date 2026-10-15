package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"domaindoctor/internal/agent"
	"domaindoctor/internal/checks"
	"domaindoctor/internal/dnsx"
	"domaindoctor/internal/dnsx/dnstest"
	"domaindoctor/internal/input"
	"domaindoctor/internal/nodes"
	"domaindoctor/internal/orchestrator"
	"domaindoctor/internal/probe"
	"domaindoctor/internal/rdap"
	"domaindoctor/internal/report"
)

// The Docker demo (deploy/demo) serves these hosts on 127.0.0.1:18080/18443.
var loadDemo = []struct {
	host string
	rule string // expected verdict rule; "" = healthy
}{
	{"healthy.ddemo-site.com", ""},
	{"apache-403.ddemo-site.com", "http.403.apache"},
	{"apache-500.ddemo-site.com", "http.500.htaccess"},
	{"nginx-502.ddemo-site.com", "http.502.origin"},
	{"nginx-503.ddemo-site.com", "http.503.maintenance"},
	{"waf-403.ddemo-site.com", "http.ua-block-origin"},
	{"mixed.ddemo-site.com", "content.mixed"},
	{"cdn-525.ddemo-site.com", "cf.525"},
	{"cdn-521.ddemo-site.com", "cf.521"},
	{"cdn-loop.ddemo-site.com", "cf.flexible-loop"},
}

func demoDir() string { return filepath.Join("..", "..", "deploy", "demo") }

// TestDemoCerts writes a demo CA and a *.ddemo-site.com certificate for the
// edge container (run before `docker compose up`).
func TestDemoCerts(t *testing.T) {
	if os.Getenv("DEMO_CERTS") != "1" {
		t.Skip("set DEMO_CERTS=1 to (re)generate deploy/demo/certs")
	}
	dir := filepath.Join(demoDir(), "certs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "netarget Demo CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "*.ddemo-site.com"},
		DNSNames: []string{"*.ddemo-site.com", "ddemo-site.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	write := func(name string, blocks ...*pem.Block) {
		var b []byte
		for _, bl := range blocks {
			b = append(b, pem.EncodeToMemory(bl)...)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("demo.crt", &pem.Block{Type: "CERTIFICATE", Bytes: der}, &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	write("demo.key", &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	write("ca.crt", &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	t.Logf("wrote %s", dir)
}

// TestLoadDemo runs the full pipeline against the Docker demo sites.
func TestLoadDemo(t *testing.T) {
	if os.Getenv("DEMO_DOCKER") != "1" {
		t.Skip("set DEMO_DOCKER=1 with deploy/demo running (see deploy/demo/docker-compose.demo.yml)")
	}
	caPEM, err := os.ReadFile(filepath.Join(demoDir(), "certs", "ca.crt"))
	if err != nil {
		t.Fatalf("demo CA missing (run TestDemoCerts first): %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	deps, ns := loadDemoWorld(t, pool)

	for _, sc := range loadDemo {
		t.Run(sc.host, func(t *testing.T) {
			d, err := input.Normalize(sc.host)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			rep := orchestrator.Run(ctx, deps, d, report.NewID(), func(orchestrator.Event) {})
			web := rep.Layers[len(rep.Layers)-1]
			det, ok := web.Details.(*checks.WebDetails)
			if !ok || det.Verdict == nil {
				t.Fatalf("no website-load verdict: %s %s", web.Status, web.Summary)
			}
			t.Logf("%s → [%s] %s (%s, %s)", sc.host, web.Status, det.Verdict.Text, det.Verdict.Layer, det.Verdict.Level)
			if det.Verdict.RuleID != sc.rule {
				var got []string
				for _, m := range det.Matches {
					got = append(got, m.RuleID)
				}
				var sig []string
				for _, s := range det.Signals {
					sig = append(sig, s.Name)
				}
				t.Errorf("verdict rule %q, want %q; matches %v; signals %v", det.Verdict.RuleID, sc.rule, got, sig)
			}
			if sc.rule == "" && web.Status == checks.FAIL {
				t.Errorf("healthy site failed: %s", web.Summary)
			}
			if os.Getenv("DEMO_WRITE") == "1" {
				out := filepath.Join("..", "..", "docs", "demo", "load")
				os.MkdirAll(out, 0o755)
				os.WriteFile(filepath.Join(out, sc.host+".md"), []byte(orchestrator.Markdown(rep)), 0o644)
				b, _ := json.MarshalIndent(rep, "", "  ")
				os.WriteFile(filepath.Join(out, sc.host+".json"), b, 0o644)
			}
		})
	}
	_ = ns
}

// loadDemoWorld: mock root/com/ddemo-site.com DNS (all hosts → 127.0.0.1),
// a mock RDAP registry, and two real agents over HTTP whose loopback hooks
// map ports 80/443 to the demo edge on 18080/18443.
func loadDemoWorld(t *testing.T, pool *x509.CertPool) (orchestrator.Deps, []*nodes.Node) {
	n := dnstest.NewNet(t)
	var recs []string
	recs = append(recs,
		"ddemo-site.com. 3600 IN SOA ns1.ddemo-site.com. hostmaster.ddemo-site.com. 1 7200 3600 1209600 300",
		"ddemo-site.com. 3600 IN NS ns1.ddemo-site.com.",
		"ddemo-site.com. 3600 IN NS ns2.ddemo-dns.net.",
		"ns1.ddemo-site.com. 3600 IN A 3.0.0.1",
		`ddemo-site.com. 3600 IN TXT "v=spf1 -all"`,
		`_dmarc.ddemo-site.com. 3600 IN TXT "v=DMARC1; p=reject"`)
	var rec []string
	for _, sc := range loadDemo {
		recs = append(recs, sc.host+". 300 IN A 127.0.0.1")
		rec = append(rec, sc.host+". 300 IN A 127.0.0.1")
	}
	zone := &dnstest.Zone{Origin: "ddemo-site.com.", Authoritative: true, Records: dnstest.RRs(t, recs...)}
	n.Add("3.0.0.1", zone)
	n.Add("3.0.1.1", zone)
	n.Add("1.0.0.1", &dnstest.Zone{Origin: ".", Authoritative: true, Delegations: map[string][]dns.RR{
		"com.": dnstest.RRs(t, "com. 172800 IN NS a.gtld-servers.net.", "a.gtld-servers.net. 172800 IN A 2.0.0.1"),
	}})
	n.Add("2.0.0.1", &dnstest.Zone{Origin: "com.", Authoritative: true,
		Records: dnstest.RRs(t, "com. 900 IN SOA a.gtld-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400"),
		Delegations: map[string][]dns.RR{"ddemo-site.com.": dnstest.RRs(t,
			"ddemo-site.com. 172800 IN NS ns1.ddemo-site.com.", "ddemo-site.com. 172800 IN NS ns2.ddemo-dns.net.",
			"ns1.ddemo-site.com. 172800 IN A 3.0.0.1")}})
	n.Add("9.9.9.9", &dnstest.Zone{Origin: ".", Records: dnstest.RRs(t, append(rec,
		"ns2.ddemo-dns.net. 300 IN A 3.0.1.1",
		"ddemo-site.com. 3600 IN NS ns1.ddemo-site.com.",
		"ddemo-site.com. 3600 IN NS ns2.ddemo-dns.net.")...)})
	c := dnsx.New()
	c.Roots = []netip.Addr{netip.MustParseAddr("1.0.0.1")}
	c.Resolvers = []dnsx.Resolver{{Name: "Resolver (mock)", IP: netip.MustParseAddr("9.9.9.9")}}
	c.AddrOverride, c.AllowPrivate, c.Timeout = n.Map, true, 400*time.Millisecond

	now := time.Now()
	var rdapSrv *httptest.Server
	rdapSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dns.json" {
			fmt.Fprintf(w, `{"services":[[["com"],["%s/com/"]]]}`, rdapSrv.URL)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/ddemo-site.com") {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(rdapDoc("ddemo-site.com", now.Add(-400*24*time.Hour), now.Add(200*24*time.Hour), "client transfer prohibited"))
	}))
	t.Cleanup(rdapSrv.Close)

	var ns []*nodes.Node
	for _, nd := range []struct{ id, name, loc string }{{"fra1", "Frankfurt", "DE (demo)"}, {"thr1", "Tehran", "IR (demo)"}} {
		local := &probe.Local{
			AllowLoopback: true, PortMap: map[int]int{80: 18080, 443: 18443},
			HTTPProber: probe.HTTPProber{Roots: pool, Timeout: 5 * time.Second},
			PingFunc: func(context.Context, netip.Addr, int) (*probe.PingResult, error) {
				return &probe.PingResult{Sent: 4, Received: 4, RTTMin: 0.1, RTTAvg: 0.2, RTTMax: 0.3}, nil
			},
			HasIPv6: func() bool { return false },
		}
		srv := httptest.NewServer((&agent.Server{Secret: agentSecret, P: local}).Handler())
		t.Cleanup(srv.Close)
		ns = append(ns, &nodes.Node{ID: nd.id, Name: nd.name, Location: nd.loc, P: agent.NewClient(srv.URL, agentSecret, 60*time.Second)})
	}
	deps := orchestrator.Deps{DNS: c, RDAP: &rdap.Client{HTTP: rdapSrv.Client(), BootstrapURL: rdapSrv.URL + "/dns.json"},
		Nodes: func() []*nodes.Node { return ns }, Now: time.Now}
	return deps, ns
}
