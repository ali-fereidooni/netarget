package dnsx

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"domaindoctor/internal/dnsx/dnstest"
)

// testHierarchy builds root -> com -> example.com with mock servers at
// logical public IPs, returning a Client wired to them.
func testHierarchy(t *testing.T) (*Client, *dnstest.Net) {
	n := dnstest.NewNet(t)
	n.Add("1.0.0.1", &dnstest.Zone{Origin: ".", Authoritative: true, Delegations: map[string][]dns.RR{
		"com.": dnstest.RRs(t,
			"com. 172800 IN NS a.gtld.test.",
			"a.gtld.test. 172800 IN A 2.0.0.1"),
	}})
	n.Add("2.0.0.1", &dnstest.Zone{Origin: "com.", Authoritative: true,
		Records: dnstest.RRs(t, "com. 900 IN SOA a.gtld.test. nstld. 1 1800 900 604800 86400"),
		Delegations: map[string][]dns.RR{
			"example.com.": dnstest.RRs(t,
				"example.com. 172800 IN NS ns1.example.com.",
				"example.com. 172800 IN NS ns2.other.net.",
				"ns1.example.com. 172800 IN A 3.0.0.1"),
		}})
	c := New()
	c.Roots = []netip.Addr{netip.MustParseAddr("1.0.0.1")}
	c.AddrOverride = n.Map
	c.AllowPrivate = true
	c.Timeout = dnstest.ShortTimeout
	c.Resolvers = nil
	return c, n
}

func TestFindDelegation(t *testing.T) {
	c, _ := testHierarchy(t)
	d, err := c.FindDelegation(context.Background(), "Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if d.Parent != "com." || len(d.NS) != 2 || d.NS[0] != "ns1.example.com." || d.NS[1] != "ns2.other.net." {
		t.Fatalf("delegation = %+v", d)
	}
	if g := d.Glue["ns1.example.com."]; len(g) != 1 || g[0] != netip.MustParseAddr("3.0.0.1") {
		t.Fatalf("glue = %v", d.Glue)
	}
}

func TestFindDelegationNXDomain(t *testing.T) {
	c, _ := testHierarchy(t)
	d, err := c.FindDelegation(context.Background(), "unregistered.com")
	if err != nil {
		t.Fatal(err)
	}
	if !d.NXDomain || d.Parent != "com." {
		t.Fatalf("want NXDOMAIN at com., got %+v", d)
	}
}

func TestFindDelegationUnreachable(t *testing.T) {
	c := New()
	n := dnstest.NewNet(t)
	n.Add("1.0.0.1", &dnstest.Zone{Drop: true})
	c.Roots = []netip.Addr{netip.MustParseAddr("1.0.0.1")}
	c.AddrOverride, c.AllowPrivate, c.Timeout = n.Map, true, 200*time.Millisecond
	if _, err := c.FindDelegation(context.Background(), "example.com"); !errors.Is(err, ErrParentUnreachable) {
		t.Fatalf("err = %v", err)
	}
}

func TestBlockedServerRefused(t *testing.T) {
	c := New()
	_, _, err := c.Query(context.Background(), netip.MustParseAddr("127.0.0.1"), "example.com", dns.TypeA, false, false)
	if !errors.Is(err, ErrBlockedServer) {
		t.Fatalf("err = %v, want ErrBlockedServer", err)
	}
}
