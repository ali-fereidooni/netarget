package checks

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"domaindoctor/internal/dnsx/dnstest"
)

func nsCheck(t *testing.T, deleg []string, children map[string]*dnstest.Zone, rec ...string) (*Result, *State) {
	t.Helper()
	c := buildWorld(t, deleg, children, rec...)
	st := &State{Domain: "example.com", Apex: "example.com"}
	return Nameservers(context.Background(), st, c, nil), st
}

const ns1A = "ns1.example.com. 3600 IN A 3.0.0.1"
const ns2Rec = "ns2.other.net. 300 IN A 4.0.0.1"

func TestNameserversHealthy(t *testing.T) {
	r, st := nsCheck(t, defaultDeleg, map[string]*dnstest.Zone{
		"3.0.0.1": childZone(t, 5, defaultNS, ns1A),
		"4.0.0.1": childZone(t, 5, defaultNS, ns1A),
	}, ns2Rec)
	if r.Status != OK || r.Blocking {
		t.Fatalf("status %s findings [%s]", r.Status, codes(r))
	}
	if len(st.AuthServers) != 2 {
		t.Fatalf("auth servers %v", st.AuthServers)
	}
}

func TestNameserversLame(t *testing.T) {
	r, _ := nsCheck(t, defaultDeleg, map[string]*dnstest.Zone{
		"3.0.0.1": childZone(t, 5, defaultNS, ns1A),
		"4.0.0.1": {Rcode: dns.RcodeRefused},
	}, ns2Rec)
	if r.Status != WARN {
		t.Fatalf("status %s [%s]", r.Status, codes(r))
	}
	wantCodes(t, r, "ns.lame")
}

func TestNameserversNotAuthoritative(t *testing.T) {
	z := childZone(t, 5, defaultNS, ns1A)
	z.Authoritative = false // answers, but without AA: lame
	r, _ := nsCheck(t, defaultDeleg, map[string]*dnstest.Zone{
		"3.0.0.1": childZone(t, 5, defaultNS, ns1A),
		"4.0.0.1": z,
	}, ns2Rec)
	wantCodes(t, r, "ns.lame")
}

func TestNameserversAllBroken(t *testing.T) {
	r, st := nsCheck(t, defaultDeleg, map[string]*dnstest.Zone{
		"3.0.0.1": {Rcode: dns.RcodeRefused},
		"4.0.0.1": {Drop: true},
	}, ns2Rec)
	if r.Status != FAIL || !r.Blocking {
		t.Fatalf("status %s blocking %v", r.Status, r.Blocking)
	}
	wantCodes(t, r, "ns.lame", "ns.unreachable", "ns.none_usable")
	if len(st.AuthServers) != 0 {
		t.Fatal("auth servers should be empty")
	}
}

func TestNameserversSerialAndChildMismatch(t *testing.T) {
	child := []string{"ns1.example.com.", "ns2.other.net.", "ns3.other.net."}
	r, _ := nsCheck(t, defaultDeleg, map[string]*dnstest.Zone{
		"3.0.0.1": childZone(t, 5, child, ns1A),
		"4.0.0.1": childZone(t, 4, child, ns1A),
	}, ns2Rec)
	wantCodes(t, r, "ns.serial_mismatch", "ns.parent_child_mismatch")
	if r.Status != WARN {
		t.Fatalf("status %s", r.Status)
	}
}

func TestNameserversMissingGlue(t *testing.T) {
	deleg := []string{
		"example.com. 172800 IN NS ns1.example.com.",
		"example.com. 172800 IN NS ns2.other.net.",
	}
	r, _ := nsCheck(t, deleg, map[string]*dnstest.Zone{
		"4.0.0.1": childZone(t, 5, defaultNS, ns1A),
	}, ns2Rec)
	wantCodes(t, r, "ns.missing_glue", "ns.no_address")
}

func TestNameserversGlueMismatchSingleNS(t *testing.T) {
	deleg := []string{
		"example.com. 172800 IN NS ns1.example.com.",
		"ns1.example.com. 172800 IN A 3.0.0.1",
	}
	r, _ := nsCheck(t, deleg, map[string]*dnstest.Zone{
		"3.0.0.1": childZone(t, 5, []string{"ns1.example.com."}, "ns1.example.com. 3600 IN A 3.0.0.9"),
	})
	wantCodes(t, r, "ns.too_few", "ns.glue_mismatch")
	dontWant(t, r, "ns.single_network")
}

func TestNameserversSingleNetwork(t *testing.T) {
	deleg := []string{
		"example.com. 172800 IN NS ns1.example.com.",
		"example.com. 172800 IN NS ns2.example.com.",
		"ns1.example.com. 172800 IN A 3.0.0.1",
		"ns2.example.com. 172800 IN A 3.0.0.2",
	}
	ns := []string{"ns1.example.com.", "ns2.example.com."}
	extra := []string{ns1A, "ns2.example.com. 3600 IN A 3.0.0.2"}
	r, _ := nsCheck(t, deleg, map[string]*dnstest.Zone{
		"3.0.0.1": childZone(t, 5, ns, extra...),
		"3.0.0.2": childZone(t, 5, ns, extra...),
	})
	wantCodes(t, r, "ns.single_network")
}

// TestCheckerDNSBlocked separates "our network blocks DNS" (root silent)
// from "the TLD is unreachable" (root answers, TLD silent).
func TestCheckerDNSBlocked(t *testing.T) {
	for _, tc := range []struct {
		rootDrop bool
		want     string
	}{{true, "ns.checker_dns_blocked"}, {false, "ns.parent_unreachable"}} {
		n := dnstest.NewNet(t)
		n.Add("1.0.0.1", &dnstest.Zone{Origin: ".", Authoritative: true, Drop: tc.rootDrop, Delegations: map[string][]dns.RR{
			"com.": dnstest.RRs(t, "com. 172800 IN NS a.gtld.test.", "a.gtld.test. 172800 IN A 2.0.0.1"),
		}})
		n.Add("2.0.0.1", &dnstest.Zone{Drop: true})
		c := buildWorld(t, nil, nil)
		c.Roots = []netip.Addr{netip.MustParseAddr("1.0.0.1")}
		c.AddrOverride = n.Map
		r := Nameservers(context.Background(), &State{Domain: "example.com", Apex: "example.com"}, c, nil)
		if !r.Has(tc.want) || !r.Blocking {
			t.Errorf("rootDrop=%v: want %s, got [%s]", tc.rootDrop, tc.want, codes(r))
		}
	}
}

// TestNameserverAddressCap: an NS name with many A records only gets
// maxAddrsPerNS probes (bounds attacker-driven query fan-out).
func TestNameserverAddressCap(t *testing.T) {
	rec := []string{}
	for i := 1; i <= 20; i++ {
		rec = append(rec, fmt.Sprintf("ns2.other.net. 300 IN A 4.0.0.%d", i))
	}
	r, _ := nsCheck(t, defaultDeleg, map[string]*dnstest.Zone{
		"3.0.0.1": childZone(t, 5, defaultNS, ns1A),
	}, rec...)
	for _, s := range r.Details.(*NSDetails).Servers {
		if len(s.Probes) > maxAddrsPerNS {
			t.Fatalf("%s probed %d addresses", s.Name, len(s.Probes))
		}
	}
}

func TestNameserversNotDelegated(t *testing.T) {
	r, _ := nsCheck(t, nil, nil)
	if r.Status != FAIL || !r.Blocking {
		t.Fatalf("status %s", r.Status)
	}
	wantCodes(t, r, "ns.no_delegation")
}
