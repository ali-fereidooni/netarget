package checks

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"domaindoctor/internal/dnsx"
	"domaindoctor/internal/dnsx/dnstest"
)

// Test topology (logical IPs mapped to mock servers):
//   1.0.0.1 root  -> com. at 2.0.0.1
//   2.0.0.1 com.  -> example.com. per `deleg`
//   9.9.9.9 recursive resolver mock (records given by test)
//   other IPs: child (authoritative) servers given by test

var defaultDeleg = []string{
	"example.com. 172800 IN NS ns1.example.com.",
	"example.com. 172800 IN NS ns2.other.net.",
	"ns1.example.com. 172800 IN A 3.0.0.1",
}

func buildWorld(t *testing.T, deleg []string, children map[string]*dnstest.Zone, rec ...string) *dnsx.Client {
	t.Helper()
	n := dnstest.NewNet(t)
	n.Add("1.0.0.1", &dnstest.Zone{Origin: ".", Authoritative: true, Delegations: map[string][]dns.RR{
		"com.": dnstest.RRs(t, "com. 172800 IN NS a.gtld.test.", "a.gtld.test. 172800 IN A 2.0.0.1"),
	}})
	tld := &dnstest.Zone{Origin: "com.", Authoritative: true,
		Records:     dnstest.RRs(t, "com. 900 IN SOA a.gtld.test. nstld. 1 1800 900 604800 86400"),
		Delegations: map[string][]dns.RR{}}
	if deleg != nil {
		for _, rr := range dnstest.RRs(t, deleg...) {
			if rr.Header().Rrtype == dns.TypeDS {
				tld.Records = append(tld.Records, rr) // parent answers DS itself
			} else {
				tld.Delegations["example.com."] = append(tld.Delegations["example.com."], rr)
			}
		}
	}
	n.Add("2.0.0.1", tld)
	for ip, z := range children {
		n.Add(ip, z)
	}
	// Recursive mock: anything not listed is NXDOMAIN.
	n.Add("9.9.9.9", &dnstest.Zone{Origin: ".", Records: dnstest.RRs(t, rec...)})
	c := dnsx.New()
	c.Roots = []netip.Addr{netip.MustParseAddr("1.0.0.1")}
	c.Resolvers = []dnsx.Resolver{{Name: "Mock", IP: netip.MustParseAddr("9.9.9.9")}}
	c.AddrOverride, c.AllowPrivate, c.Timeout = n.Map, true, dnstest.ShortTimeout
	return c
}

// childZone builds an authoritative example.com zone.
func childZone(t *testing.T, serial uint32, ns []string, extra ...string) *dnstest.Zone {
	recs := []string{fmt.Sprintf("example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. %d 7200 3600 1209600 300", serial)}
	for _, n := range ns {
		recs = append(recs, "example.com. 3600 IN NS "+n)
	}
	recs = append(recs, extra...)
	return &dnstest.Zone{Origin: "example.com.", Authoritative: true, Records: dnstest.RRs(t, recs...)}
}

var defaultNS = []string{"ns1.example.com.", "ns2.other.net."}

func codes(r *Result) string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Code)
	}
	return strings.Join(out, ",")
}

func wantCodes(t *testing.T, r *Result, want ...string) {
	t.Helper()
	for _, w := range want {
		if !r.Has(w) {
			t.Errorf("missing finding %s; got [%s]", w, codes(r))
		}
	}
}

func dontWant(t *testing.T, r *Result, codes_ ...string) {
	t.Helper()
	for _, w := range codes_ {
		if r.Has(w) {
			t.Errorf("unexpected finding %s; got [%s]", w, codes(r))
		}
	}
}
