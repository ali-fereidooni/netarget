package checks

import (
	"context"
	"crypto"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"domaindoctor/internal/dnsx/dnstest"
)

var testNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// signZone adds a DNSKEY and RRSIGs (over DNSKEY and SOA) to z and returns the DS.
func signZone(t *testing.T, z *dnstest.Zone, inception, expiration time.Time) *dns.DS {
	t.Helper()
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(rrs []dns.RR) *dns.RRSIG {
		sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			KeyTag: key.KeyTag(), SignerName: "example.com.", Algorithm: key.Algorithm,
			Inception: uint32(inception.Unix()), Expiration: uint32(expiration.Unix())}
		if err := sig.Sign(priv.(crypto.Signer), rrs); err != nil {
			t.Fatal(err)
		}
		return sig
	}
	var soa dns.RR
	for _, rr := range z.Records {
		if rr.Header().Rrtype == dns.TypeSOA {
			soa = rr
		}
	}
	z.Records = append(z.Records, key, sign([]dns.RR{key}), sign([]dns.RR{soa}))
	return key.ToDS(dns.SHA256)
}

func zoneCheck(t *testing.T, deleg []string, child *dnstest.Zone, rec ...string) (*Result, *State) {
	t.Helper()
	c := buildWorld(t, deleg, map[string]*dnstest.Zone{"3.0.0.1": child}, rec...)
	st := &State{Domain: "example.com", Apex: "example.com",
		AuthServers:  []AuthServer{{Name: "ns1.example.com.", IP: netip.MustParseAddr("3.0.0.1")}},
		ParentServer: netip.MustParseAddr("2.0.0.1")}
	return Zone(context.Background(), st, c, testNow), st
}

func TestZoneHealthy(t *testing.T) {
	child := childZone(t, 5, []string{"ns1.example.com."},
		"example.com. 300 IN A 5.0.0.1",
		"www.example.com. 300 IN CNAME example.com.",
		"example.com. 300 IN MX 10 mail.example.com.",
		"mail.example.com. 300 IN A 5.0.0.2",
		`example.com. 300 IN TXT "v=spf1 include:_spf.mail.test ~all"`,
		`_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject; rua=mailto:d@example.com"`,
		`selector1._domainkey.example.com. 300 IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBg"`,
		`example.com. 300 IN CAA 0 issue "letsencrypt.org"`,
	)
	ds := signZone(t, child, testNow.Add(-24*time.Hour), testNow.Add(30*24*time.Hour))
	deleg := append([]string{
		"example.com. 172800 IN NS ns1.example.com.",
		"ns1.example.com. 172800 IN A 3.0.0.1",
	}, ds.String())
	r, st := zoneCheck(t, deleg, child,
		"example.com. 300 IN A 5.0.0.1",
		"example.com. 300 IN MX 10 mail.example.com.",
		"example.com. 300 IN NS ns1.example.com.",
		"mail.example.com. 300 IN A 5.0.0.2",
		`_spf.mail.test. 300 IN TXT "v=spf1 ip4:5.0.0.0/24 -all"`,
	)
	if r.Status != OK {
		t.Fatalf("status %s [%s]\n%+v", r.Status, codes(r), r.Findings)
	}
	wantCodes(t, r, "dnssec.valid", "dns.no_ipv6")
	if len(st.ApexV4) != 1 || st.ApexV4[0] != netip.MustParseAddr("5.0.0.1") || len(st.WWWV4) != 1 {
		t.Fatalf("addrs apex=%v www=%v", st.ApexV4, st.WWWV4)
	}
	det := r.Details.(*ZoneDetails)
	if det.Email.DMARC.Policy != "reject" || len(det.Email.DKIM) != 1 || det.Email.SPF.Lookups != 1 {
		t.Fatalf("email %+v", det.Email)
	}
	foundTTL := false
	for _, row := range det.Records {
		if row.Type == "A" && row.Name == "example.com" && row.TTL == 300 {
			foundTTL = true
		}
	}
	if !foundTTL {
		t.Fatalf("records table missing A with TTL: %+v", det.Records)
	}
}

func TestZoneBroken(t *testing.T) {
	child := childZone(t, 5, []string{"ns1.example.com."},
		"example.com. 300 IN CNAME host.example.net.",
		"www.example.com. 300 IN CNAME gone.example.net.",
		"example.com. 300 IN MX 10 mx.example.com.",
		`example.com. 300 IN TXT "v=spf1 a -all"`,
		`example.com. 300 IN TXT "v=spf1 mx +all"`,
	)
	signZone(t, child, testNow.Add(-time.Hour), testNow.Add(time.Hour))
	// DS for a different (old) key: the classic "changed provider, left DS" break.
	oldKey := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	if _, err := oldKey.Generate(256); err != nil {
		t.Fatal(err)
	}
	deleg := []string{
		"example.com. 172800 IN NS ns1.example.com.",
		"ns1.example.com. 172800 IN A 3.0.0.1",
		oldKey.ToDS(dns.SHA256).String(),
	}
	r, _ := zoneCheck(t, deleg, child,
		"host.example.net. 300 IN A 5.0.0.9",
		"mx.example.com. 300 IN CNAME mailhost.example.net.",
		"mailhost.example.net. 300 IN A 5.0.0.3",
		"example.com. 300 IN A 6.6.6.6",
	)
	wantCodes(t, r, "dns.cname_at_apex", "dns.dangling_cname", "dns.mx_cname",
		"mail.spf_multiple", "mail.dmarc_missing", "dnssec.broken", "dns.propagation")
	if r.Status != FAIL {
		t.Fatalf("status %s", r.Status)
	}
}

func TestZoneExpiredSignature(t *testing.T) {
	child := childZone(t, 5, []string{"ns1.example.com."}, "example.com. 300 IN A 5.0.0.1")
	ds := signZone(t, child, testNow.Add(-60*24*time.Hour), testNow.Add(-24*time.Hour))
	deleg := []string{"example.com. 172800 IN NS ns1.example.com.", "ns1.example.com. 172800 IN A 3.0.0.1", ds.String()}
	r, _ := zoneCheck(t, deleg, child, "example.com. 300 IN A 5.0.0.1")
	wantCodes(t, r, "dnssec.broken")
	if !strings.Contains(fmt.Sprint(r.Findings), "expired") {
		t.Fatalf("expected 'expired' in findings: %+v", r.Findings)
	}
}

func TestSigExpiringSoon(t *testing.T) {
	sig := func(inc, exp time.Duration) *dns.RRSIG {
		return &dns.RRSIG{Inception: uint32(testNow.Add(inc).Unix()), Expiration: uint32(testNow.Add(exp).Unix())}
	}
	cases := []struct {
		name     string
		s        *dns.RRSIG
		expiring bool
	}{
		{"online signer: 1h old, 47h left of 48h", sig(-time.Hour, 47*time.Hour), false},
		{"30-day signature with 2 days left", sig(-28*24*time.Hour, 48*time.Hour), true},
		{"30-day signature with 10 days left", sig(-20*24*time.Hour, 10*24*time.Hour), false},
		{"already expired", sig(-30*24*time.Hour, -time.Hour), false},
	}
	for _, c := range cases {
		if got := sigExpiringSoon(c.s, testNow); got != c.expiring {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestZoneNoAddress(t *testing.T) {
	child := childZone(t, 5, []string{"ns1.example.com."})
	r, _ := zoneCheck(t, []string{"example.com. 172800 IN NS ns1.example.com.", "ns1.example.com. 172800 IN A 3.0.0.1"}, child)
	wantCodes(t, r, "dns.no_address", "dnssec.unsigned", "dns.no_mx")
	if !r.Blocking || r.Status != FAIL {
		t.Fatalf("blocking %v status %s", r.Blocking, r.Status)
	}
}

func TestZoneSkippedWithoutAuth(t *testing.T) {
	r := Zone(context.Background(), &State{Apex: "example.com", Domain: "example.com"}, nil, testNow)
	if r.Status != SKIPPED {
		t.Fatal(r.Status)
	}
}

func TestAnalyzeSPF(t *testing.T) {
	db := map[string]string{
		"a.test": "v=spf1 include:b.test include:c.test",
		"b.test": "v=spf1 a mx ptr exists:x.test include:d.test",
		"c.test": "v=spf1 a mx a:foo.test mx:bar.test",
		"d.test": "v=spf1 include:a.test", // loop back to a.test
		"e.test": "not spf",
	}
	fetch := func(_ context.Context, name string) ([]string, error) {
		if v, ok := db[name]; ok {
			return []string{v}, nil
		}
		return nil, fmt.Errorf("nx")
	}
	res := AnalyzeSPF(context.Background(), "v=spf1 include:a.test redirect=e.test bogus +all", fetch)
	// include:a(1) -> include:b(1) a mx ptr exists(4) include:d(1) -> include:a(1, loop)
	//               include:c(1) a mx a mx(4); redirect(1)
	if res.Lookups != 14 {
		t.Errorf("lookups = %d, want 14", res.Lookups)
	}
	if res.AllQual != "+" {
		t.Errorf("all qualifier %q", res.AllQual)
	}
	joined := strings.Join(res.Errors, "|")
	for _, want := range []string{"unknown mechanism bogus", "include loop via a.test", "redirect:e.test has no SPF record"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing error %q in %q", want, joined)
		}
	}
	ok := AnalyzeSPF(context.Background(), "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a/24 -all", fetch)
	if len(ok.Errors) != 0 || ok.Lookups != 1 || ok.AllQual != "-" {
		t.Errorf("simple record: %+v", ok)
	}
}
