// Package e2e runs the whole pipeline (orchestrator → real agents over HTTP
// → real web servers) against a mock Internet: root/TLD/authoritative DNS
// servers, an RDAP registry, and TLS sites signed by a test CA. It doubles
// as the reproducible demo (see TestDemo / TestDemoServe).
package e2e

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"domaindoctor/internal/agent"
	"domaindoctor/internal/dnsx"
	"domaindoctor/internal/dnsx/dnstest"
	"domaindoctor/internal/nodes"
	"domaindoctor/internal/orchestrator"
	"domaindoctor/internal/probe"
	"domaindoctor/internal/rdap"
)

const agentSecret = "e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0e2e0"

// Scenario domains (all under the mocked com. TLD):
//
//	healthy-shop.com  everything correct, DNSSEC signed
//	expired-shop.com  registration expired 12 days ago; registrar removed the zone → lame NS
//	lame-shop.com     registered, but neither delegated name server serves the zone
//	broken-web.com    DNS fine; HTTPS cert expired and the backend returns 502
type world struct {
	deps  orchestrator.Deps
	nodes []*nodes.Node
}

func soa(origin string, serial int) string {
	return fmt.Sprintf("%s 3600 IN SOA ns1.dns-host.net. hostmaster.%s %d 7200 3600 1209600 300", origin, origin, serial)
}

func buildWorld(t testing.TB) *world {
	now := time.Now()
	n := dnstest.NewNet(t)

	// --- authoritative zones ---
	healthy := &dnstest.Zone{Origin: "healthy-shop.com.", Authoritative: true, Records: dnstest.RRs(t,
		soa("healthy-shop.com.", 2026101401),
		"healthy-shop.com. 3600 IN NS ns1.healthy-shop.com.",
		"healthy-shop.com. 3600 IN NS ns2.dns-host.net.",
		"ns1.healthy-shop.com. 3600 IN A 3.0.0.1",
		"healthy-shop.com. 300 IN A 127.0.0.1",
		"www.healthy-shop.com. 300 IN CNAME healthy-shop.com.",
		"healthy-shop.com. 3600 IN MX 10 mail.healthy-shop.com.",
		"mail.healthy-shop.com. 3600 IN A 127.0.0.1",
		`healthy-shop.com. 3600 IN TXT "v=spf1 mx include:_spf.mailer.net -all"`,
		`_dmarc.healthy-shop.com. 3600 IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@healthy-shop.com"`,
		`selector1._domainkey.healthy-shop.com. 3600 IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx"`,
		`healthy-shop.com. 3600 IN CAA 0 issue "letsencrypt.org"`,
	)}
	ds := signZone(t, healthy, now)
	brokenWeb := &dnstest.Zone{Origin: "broken-web.com.", Authoritative: true, Records: dnstest.RRs(t,
		soa("broken-web.com.", 7),
		"broken-web.com. 3600 IN NS ns1.dns-host.net.",
		"broken-web.com. 3600 IN NS ns2.dns-host.net.",
		"broken-web.com. 300 IN A 127.0.0.1",
		`broken-web.com. 3600 IN TXT "v=spf1 -all"`,
		`_dmarc.broken-web.com. 3600 IN TXT "v=DMARC1; p=reject"`,
	)}
	// ns1.healthy-shop.com (3.0.0.1) and ns1/ns2.dns-host.net (3.0.1.1, 3.0.2.1)
	n.AddHandler("3.0.0.1", dnstest.Multi{"healthy-shop.com.": healthy})
	n.AddHandler("3.0.1.1", dnstest.Multi{"healthy-shop.com.": healthy, "broken-web.com.": brokenWeb})
	n.AddHandler("3.0.2.1", dnstest.Multi{"healthy-shop.com.": healthy, "broken-web.com.": brokenWeb})
	// Parking host (expired-shop.com): zone deleted → REFUSED. lame-shop.com: one refuses, one never answers.
	n.Add("4.0.0.1", &dnstest.Zone{Rcode: dns.RcodeRefused})
	n.Add("4.0.1.1", &dnstest.Zone{Rcode: dns.RcodeRefused})
	n.Add("5.0.0.1", &dnstest.Zone{Rcode: dns.RcodeRefused})
	n.Add("5.0.1.1", &dnstest.Zone{Drop: true})

	// --- root and TLD ---
	n.Add("1.0.0.1", &dnstest.Zone{Origin: ".", Authoritative: true, Delegations: map[string][]dns.RR{
		"com.": dnstest.RRs(t, "com. 172800 IN NS a.gtld-servers.net.", "a.gtld-servers.net. 172800 IN A 2.0.0.1"),
	}})
	tld := &dnstest.Zone{Origin: "com.", Authoritative: true,
		Records: append(dnstest.RRs(t, "com. 900 IN SOA a.gtld-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400"), ds),
		Delegations: map[string][]dns.RR{
			"healthy-shop.com.": dnstest.RRs(t, "healthy-shop.com. 172800 IN NS ns1.healthy-shop.com.", "healthy-shop.com. 172800 IN NS ns2.dns-host.net.",
				"ns1.healthy-shop.com. 172800 IN A 3.0.0.1"),
			"broken-web.com.":   dnstest.RRs(t, "broken-web.com. 172800 IN NS ns1.dns-host.net.", "broken-web.com. 172800 IN NS ns2.dns-host.net."),
			"expired-shop.com.": dnstest.RRs(t, "expired-shop.com. 172800 IN NS ns1.parking-host.net.", "expired-shop.com. 172800 IN NS ns2.parking-host.net."),
			"lame-shop.com.": dnstest.RRs(t, "lame-shop.com. 172800 IN NS ns1.lame-shop.com.", "lame-shop.com. 172800 IN NS ns2.lame-shop.com.",
				"ns1.lame-shop.com. 172800 IN A 5.0.0.1", "ns2.lame-shop.com. 172800 IN A 5.0.1.1"),
		}}
	n.Add("2.0.0.1", tld)

	// --- public resolver mock (what 1.1.1.1 etc. would return) ---
	n.Add("9.9.9.9", &dnstest.Zone{Origin: ".", Records: dnstest.RRs(t,
		"ns1.dns-host.net. 300 IN A 3.0.1.1",
		"ns2.dns-host.net. 300 IN A 3.0.2.1",
		"ns1.parking-host.net. 300 IN A 4.0.0.1",
		"ns2.parking-host.net. 300 IN A 4.0.1.1",
		"healthy-shop.com. 300 IN A 127.0.0.1",
		"healthy-shop.com. 3600 IN MX 10 mail.healthy-shop.com.",
		"healthy-shop.com. 3600 IN NS ns1.healthy-shop.com.",
		"healthy-shop.com. 3600 IN NS ns2.dns-host.net.",
		"mail.healthy-shop.com. 3600 IN A 127.0.0.1",
		`_spf.mailer.net. 300 IN TXT "v=spf1 ip4:198.51.100.0/24 -all"`,
		"broken-web.com. 300 IN A 127.0.0.1",
		"broken-web.com. 3600 IN NS ns1.dns-host.net.",
		"broken-web.com. 3600 IN NS ns2.dns-host.net.",
	)})
	c := dnsx.New()
	c.Roots = []netip.Addr{netip.MustParseAddr("1.0.0.1")}
	c.Resolvers = []dnsx.Resolver{{Name: "Cloudflare (mock)", IP: netip.MustParseAddr("9.9.9.9")}}
	c.AddrOverride, c.AllowPrivate, c.Timeout = n.Map, true, 400*time.Millisecond

	// --- RDAP registry ---
	day := 24 * time.Hour
	reg := map[string]map[string]any{
		"healthy-shop.com": rdapDoc("healthy-shop.com", now.Add(-900*day), now.Add(210*day), "client transfer prohibited"),
		"broken-web.com":   rdapDoc("broken-web.com", now.Add(-400*day), now.Add(95*day), "client transfer prohibited"),
		"lame-shop.com":    rdapDoc("lame-shop.com", now.Add(-60*day), now.Add(305*day), "active"),
		"expired-shop.com": rdapDoc("expired-shop.com", now.Add(-377*day), now.Add(-12*day), "auto renew period", "client transfer prohibited"),
	}
	var rdapSrv *httptest.Server
	rdapSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dns.json" {
			fmt.Fprintf(w, `{"services":[[["com"],["%s/com/"]]]}`, rdapSrv.URL)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/com/domain/")
		doc, ok := reg[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(rdapSrv.Close)
	rd := &rdap.Client{HTTP: rdapSrv.Client(), BootstrapURL: rdapSrv.URL + "/dns.json"}

	// --- web servers (ports 80/443 mapped to these) ---
	ca, caKey, pool := newCA(t)
	certs := map[string]*tls.Certificate{
		"healthy-shop.com":     leaf(t, ca, caKey, []string{"healthy-shop.com", "www.healthy-shop.com"}, now.Add(-30*day), now.Add(60*day)),
		"www.healthy-shop.com": nil,
		"broken-web.com":       leaf(t, ca, caKey, []string{"broken-web.com"}, now.Add(-120*day), now.Add(-3*day)),
	}
	certs["www.healthy-shop.com"] = certs["healthy-shop.com"]
	site := func(w http.ResponseWriter, r *http.Request) {
		host := strings.Split(r.Host, ":")[0]
		https := r.TLS != nil
		switch {
		case host == "www.healthy-shop.com":
			http.Redirect(w, r, "https://healthy-shop.com/", http.StatusMovedPermanently)
		case !https:
			http.Redirect(w, r, "https://"+host+"/", http.StatusMovedPermanently)
		case host == "healthy-shop.com":
			h := w.Header()
			h.Set("Server", "nginx")
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			fmt.Fprint(w, "<h1>Healthy Shop</h1>")
		case host == "broken-web.com":
			w.Header().Set("Server", "nginx/1.24.0")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, "<html><body><center><h1>502 Bad Gateway</h1></center></body></html>")
		default:
			http.NotFound(w, r)
		}
	}
	httpSrv := httptest.NewServer(http.HandlerFunc(site))
	t.Cleanup(httpSrv.Close)
	httpsSrv := httptest.NewUnstartedServer(http.HandlerFunc(site))
	httpsSrv.TLS = &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if c := certs[h.ServerName]; c != nil {
			return c, nil
		}
		return nil, fmt.Errorf("no certificate for %q", h.ServerName)
	}}
	// TCP port probes open and close without a handshake; don't log that.
	httpsSrv.Config.ErrorLog = log.New(io.Discard, "", 0)
	httpsSrv.StartTLS()
	t.Cleanup(httpsSrv.Close)
	portMap := map[int]int{80: port(httpSrv.URL), 443: port(httpsSrv.URL)}

	// --- two real agents over HTTP ---
	var ns []*nodes.Node
	for _, nd := range []struct{ id, name, loc string }{{"fra1", "Frankfurt", "DE (demo)"}, {"thr1", "Tehran", "IR (demo)"}} {
		local := &probe.Local{
			AllowLoopback: true, PortMap: portMap,
			HTTPProber: probe.HTTPProber{Roots: pool, Timeout: 3 * time.Second},
			PingFunc: func(_ context.Context, ip netip.Addr, count int) (*probe.PingResult, error) {
				return &probe.PingResult{Sent: 4, Received: 4, RTTMin: 0.04, RTTAvg: 0.05, RTTMax: 0.07}, nil
			},
			TraceFunc: func(_ context.Context, ip netip.Addr, _ int, line func(string)) error {
				line(fmt.Sprintf(" 1  %s  0.050 ms", ip))
				return nil
			},
		}
		srv := httptest.NewServer((&agent.Server{Secret: agentSecret, P: local}).Handler())
		t.Cleanup(srv.Close)
		ns = append(ns, &nodes.Node{ID: nd.id, Name: nd.name, Location: nd.loc, P: agent.NewClient(srv.URL, agentSecret, 30*time.Second)})
	}

	w := &world{nodes: ns}
	w.deps = orchestrator.Deps{DNS: c, RDAP: rd, Nodes: func() []*nodes.Node { return ns }, Now: time.Now}
	return w
}

func port(u string) int {
	_, p, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://"))
	var n int
	fmt.Sscan(p, &n)
	return n
}

func rdapDoc(name string, created, expires time.Time, status ...string) map[string]any {
	return map[string]any{
		"objectClassName": "domain", "ldhName": strings.ToUpper(name), "status": status,
		"events": []map[string]string{
			{"eventAction": "registration", "eventDate": created.UTC().Format(time.RFC3339)},
			{"eventAction": "expiration", "eventDate": expires.UTC().Format(time.RFC3339)},
		},
		"entities": []map[string]any{{"roles": []string{"registrar"}, "handle": "9999",
			"vcardArray": []any{"vcard", [][]any{{"version", map[string]any{}, "text", "4.0"}, {"fn", map[string]any{}, "text", "Demo Registrar Ltd."}}}}},
	}
}

func signZone(t testing.TB, z *dnstest.Zone, now time.Time) dns.RR {
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: z.Origin, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(rrs []dns.RR) *dns.RRSIG {
		s := &dns.RRSIG{Hdr: dns.RR_Header{Name: z.Origin, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			KeyTag: key.KeyTag(), SignerName: z.Origin, Algorithm: key.Algorithm,
			Inception: uint32(now.Add(-24 * time.Hour).Unix()), Expiration: uint32(now.Add(14 * 24 * time.Hour).Unix())}
		if err := s.Sign(priv.(crypto.Signer), rrs); err != nil {
			t.Fatal(err)
		}
		return s
	}
	z.Records = append(z.Records, key, sign([]dns.RR{key}), sign([]dns.RR{z.Records[0]}))
	return key.ToDS(dns.SHA256)
}

func newCA(t testing.TB) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "netarget Demo CA"},
		NotBefore: time.Now().Add(-365 * 24 * time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return ca, k, pool
}

func leaf(t testing.TB, ca *x509.Certificate, caKey *ecdsa.PrivateKey, names []string, nb, na time.Time) *tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		Issuer: ca.Subject, DNSNames: names, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &k.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	// Serve leaf + intermediate (here: the CA) so the chain is complete.
	return &tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: k}
}
