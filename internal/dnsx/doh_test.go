package dnsx

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"domaindoctor/internal/dnsx/dnstest"
)

func TestDoHMode(t *testing.T) {
	srv := dnstest.DoH(t, &dnstest.Zone{Origin: ".", Records: dnstest.RRs(t,
		"example.com. 300 IN A 93.184.215.14",
		"example.com. 300 IN AAAA 2606:2800:21f:cb07:6820:80da:af6b:8b2c")})
	c := New()
	c.DoH, c.DoHHTTP = true, srv.Client()
	c.Resolvers = []Resolver{{Name: "Mock", IP: netip.MustParseAddr("1.1.1.1"), DoH: srv.URL}}

	addrs, nx, err := c.LookupAddrs(context.Background(), "example.com")
	if err != nil || nx || len(addrs) != 2 {
		t.Fatalf("addrs %v nx %v err %v", addrs, nx, err)
	}
	if _, nx, _ := c.LookupAddrs(context.Background(), "missing.example.com"); !nx {
		t.Fatal("NXDOMAIN not propagated over DoH")
	}
	// Direct queries fail fast instead of timing out.
	if _, _, err := c.Query(context.Background(), netip.MustParseAddr("198.41.0.4"), ".", dns.TypeSOA, false, false); !errors.Is(err, ErrDirectUnavailable) {
		t.Fatalf("direct query err %v", err)
	}
	if !c.ProbeDoH(context.Background()) {
		t.Fatal("ProbeDoH false")
	}
}
