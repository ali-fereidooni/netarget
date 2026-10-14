package checks

import (
	"context"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"domaindoctor/internal/dnsx"
	"domaindoctor/internal/dnsx/dnstest"
)

// resolverWorld builds a DoH-mode client whose single resolver is served by h.
func resolverWorld(t *testing.T, h dns.Handler) *dnsx.Client {
	srv := dnstest.DoH(t, h)
	c := dnsx.New()
	c.DoH, c.DoHHTTP = true, srv.Client()
	c.Resolvers = []dnsx.Resolver{{Name: "Mock", IP: netip.MustParseAddr("1.1.1.1"), DoH: srv.URL}}
	return c
}

// servfail answers SERVFAIL unless CD is set and cdWorks (DNSSEC-broken zone).
func servfail(t *testing.T, cdWorks bool) dns.HandlerFunc {
	z := &dnstest.Zone{Origin: ".", Records: dnstest.RRs(t,
		"example.com. 3600 IN NS ns1.host.net.", "ns1.host.net. 300 IN A 4.0.0.1")}
	return func(w dns.ResponseWriter, req *dns.Msg) {
		if req.CheckingDisabled && cdWorks || req.Question[0].Name != "example.com." {
			z.ServeDNS(w, req)
			return
		}
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(m)
	}
}

func TestNameserversViaResolvers(t *testing.T) {
	healthy := &dnstest.Zone{Origin: ".", Records: dnstest.RRs(t,
		"example.com. 3600 IN NS ns1.host.net.", "example.com. 3600 IN NS ns2.other.org.",
		"ns1.host.net. 300 IN A 4.0.0.1", "ns2.other.org. 300 IN A 5.0.0.1")}
	cases := []struct {
		name     string
		h        dns.Handler
		status   Status
		blocking bool
		codes    []string
	}{
		{"healthy", healthy, OK, false, []string{"ns.limited_mode"}},
		{"nxdomain", &dnstest.Zone{Origin: "."}, FAIL, true, []string{"ns.no_delegation"}},
		{"dnssec broken", servfail(t, true), WARN, false, []string{"dns.resolver_servfail", "ns.too_few"}},
		{"name servers dead", servfail(t, false), FAIL, true, []string{"ns.none_usable"}},
	}
	for _, c := range cases {
		st := &State{Domain: "example.com", Apex: "example.com"}
		r := Nameservers(context.Background(), st, resolverWorld(t, c.h), nil)
		if r.Status != c.status || r.Blocking != c.blocking || !st.ViaResolvers {
			t.Errorf("%s: status %s blocking %v via %v [%s]", c.name, r.Status, r.Blocking, st.ViaResolvers, codes(r))
		}
		for _, code := range c.codes {
			if !r.Has(code) {
				t.Errorf("%s: missing %s in [%s]", c.name, code, codes(r))
			}
		}
	}
}

// TestZoneViaResolvers: in DoH mode the zone layer reads records (with CD,
// so broken DNSSEC still shows data) from the resolvers.
func TestZoneViaResolvers(t *testing.T) {
	c := resolverWorld(t, &dnstest.Zone{Origin: ".", Records: dnstest.RRs(t,
		"example.com. 3600 IN SOA ns1.host.net. h.example.com. 1 7200 3600 1209600 300",
		"example.com. 300 IN A 93.184.215.14",
		"www.example.com. 300 IN CNAME example.com.",
		`example.com. 300 IN TXT "v=spf1 -all"`,
		`_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject"`)})
	st := &State{Domain: "example.com", Apex: "example.com", ViaResolvers: true}
	r := Zone(context.Background(), st, c, testNow)
	if r.Status == SKIPPED || len(st.ApexV4) != 1 || len(st.WWWV4) != 1 {
		t.Fatalf("status %s apex %v www %v [%s]", r.Status, st.ApexV4, st.WWWV4, codes(r))
	}
	dontWant(t, r, "dns.propagation", "mail.spf_missing", "mail.dmarc_missing")
}
