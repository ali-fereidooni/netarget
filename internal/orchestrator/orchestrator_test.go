package orchestrator

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"domaindoctor/internal/checks"
	"domaindoctor/internal/dnsx"
	"domaindoctor/internal/dnsx/dnstest"
	"domaindoctor/internal/input"
	"domaindoctor/internal/nodes"
	"domaindoctor/internal/probe"
	"domaindoctor/internal/rdap"
)

type fakeReg struct {
	info *rdap.Info
	err  error
}

func (f fakeReg) Lookup(context.Context, string) (*rdap.Info, error) { return f.info, f.err }

type fakeProber struct{}

func (fakeProber) Health(context.Context) error { return nil }
func (fakeProber) Probe(_ context.Context, r probe.ProbeRequest) (*probe.ProbeResponse, error) {
	out := &probe.ProbeResponse{}
	for _, ip := range r.IPs {
		out.Results = append(out.Results, probe.IPProbe{IP: ip, Ping: &probe.PingResult{Sent: 4, Received: 4, RTTAvg: 9},
			TCP: []probe.TCPResult{{Port: 80, Status: "open"}, {Port: 443, Status: "open"}}})
	}
	return out, nil
}
func (fakeProber) HTTP(_ context.Context, r probe.HTTPRequest) (*probe.HTTPResponse, error) {
	out := &probe.HTTPResponse{}
	for _, u := range r.URLs {
		out.Chains = append(out.Chains, probe.Chain{Start: u, Hops: []probe.Hop{{URL: u, Status: 200, StatusText: "OK"}}})
	}
	return out, nil
}
func (fakeProber) Traceroute(context.Context, netip.Addr, int, func(string)) error { return nil }

// lameWorld: com. delegates example.com to two servers that both refuse.
func lameWorld(t *testing.T) *dnsx.Client {
	n := dnstest.NewNet(t)
	n.Add("1.0.0.1", &dnstest.Zone{Origin: ".", Authoritative: true, Delegations: map[string][]dns.RR{
		"com.": dnstest.RRs(t, "com. 172800 IN NS a.gtld.test.", "a.gtld.test. 172800 IN A 2.0.0.1"),
	}})
	n.Add("2.0.0.1", &dnstest.Zone{Origin: "com.", Authoritative: true,
		Records: dnstest.RRs(t, "com. 900 IN SOA a.gtld.test. nstld. 1 1800 900 604800 86400"),
		Delegations: map[string][]dns.RR{"example.com.": dnstest.RRs(t,
			"example.com. 172800 IN NS ns1.example.com.", "example.com. 172800 IN NS ns2.example.com.",
			"ns1.example.com. 172800 IN A 3.0.0.1", "ns2.example.com. 172800 IN A 3.0.1.1")}})
	n.Add("3.0.0.1", &dnstest.Zone{Rcode: dns.RcodeRefused})
	n.Add("3.0.1.1", &dnstest.Zone{Rcode: dns.RcodeRefused})
	c := dnsx.New()
	c.Roots = []netip.Addr{netip.MustParseAddr("1.0.0.1")}
	c.Resolvers = nil
	c.AddrOverride, c.AllowPrivate, c.Timeout = n.Map, true, dnstest.ShortTimeout
	return c
}

func TestRunExpiredAndLame(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	exp := now.AddDate(0, 0, -5)
	d, _ := input.Normalize("https://www.example.com/")
	deps := Deps{
		DNS:   lameWorld(t),
		RDAP:  fakeReg{info: &rdap.Info{Registrar: "Test", Expires: &exp, Status: []string{"autoRenewPeriod"}}},
		Nodes: func() []*nodes.Node { return []*nodes.Node{{ID: "a", Name: "A", P: fakeProber{}}} },
		Now:   func() time.Time { return now },
	}
	var events []string
	rep := Run(context.Background(), deps, d, "id", func(e Event) { events = append(events, e.Type+":"+e.Layer) })
	statuses := []checks.Status{}
	for _, l := range rep.Layers {
		statuses = append(statuses, l.Status)
	}
	want := []checks.Status{checks.FAIL, checks.FAIL, checks.SKIPPED, checks.SKIPPED, checks.SKIPPED}
	for i := range want {
		if statuses[i] != want[i] {
			t.Fatalf("statuses %v want %v", statuses, want)
		}
	}
	if rep.Diagnosis.RootCause.Code != "reg.expired" {
		t.Fatalf("root %+v", rep.Diagnosis.RootCause)
	}
	if events[len(events)-1] != "done:" || events[0] != "layer_start:registration" {
		t.Fatalf("events %v", events)
	}
	// Markdown and JSON round-trip.
	md := Markdown(rep)
	if !strings.Contains(md, "The domain registration has expired") || !strings.Contains(md, "| Name server |") {
		t.Fatalf("markdown:\n%s", md)
	}
	b, _ := json.Marshal(rep)
	var back Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if _, ok := back.Layers[1].Details.(*checks.NSDetails); !ok {
		t.Fatalf("details type after round-trip: %T", back.Layers[1].Details)
	}
	if Markdown(&back) != md {
		t.Fatal("markdown differs after JSON round-trip")
	}
}

func TestRunNotRegisteredSkipsAll(t *testing.T) {
	d, _ := input.Normalize("example.com")
	deps := Deps{DNS: lameWorld(t), RDAP: fakeReg{err: rdap.ErrNotFound}}
	rep := Run(context.Background(), deps, d, "id", func(Event) {})
	for _, l := range rep.Layers[1:] {
		if l.Status != checks.SKIPPED {
			t.Fatalf("%s not skipped", l.Layer)
		}
	}
	if rep.Diagnosis.RootCause.Code != "reg.not_registered" || len(rep.Diagnosis.Symptoms) != 4 {
		t.Fatalf("%+v", rep.Diagnosis)
	}
}
