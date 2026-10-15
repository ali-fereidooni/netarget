package checks

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"domaindoctor/internal/nodes"
	"domaindoctor/internal/probe"
)

// cannedProber returns fixed responses.
type cannedProber struct {
	probe *probe.ProbeResponse
	http  *probe.HTTPResponse
	res   *probe.ResourceResponse
	err   error
}

func (c *cannedProber) Health(context.Context) error { return c.err }
func (c *cannedProber) Probe(context.Context, probe.ProbeRequest) (*probe.ProbeResponse, error) {
	return c.probe, c.err
}
func (c *cannedProber) HTTP(_ context.Context, req probe.HTTPRequest) (*probe.HTTPResponse, error) {
	return c.http, c.err
}
func (c *cannedProber) Traceroute(context.Context, netip.Addr, int, func(string)) error { return c.err }
func (c *cannedProber) Resources(context.Context, probe.ResourceRequest) (*probe.ResourceResponse, error) {
	if c.res == nil {
		return &probe.ResourceResponse{}, c.err
	}
	return c.res, c.err
}

func node(id string, p probe.Prober) *nodes.Node {
	return &nodes.Node{ID: id, Name: id, Location: id, P: p}
}

func ipProbe(ip string, recv int, p80, p443 string) probe.IPProbe {
	r := probe.IPProbe{IP: netip.MustParseAddr(ip), TCP: []probe.TCPResult{{Port: 80, Status: p80}, {Port: 443, Status: p443}}}
	if recv >= 0 {
		r.Ping = &probe.PingResult{Sent: 4, Received: recv, Loss: float64(4-recv) * 25, RTTAvg: 10}
	} else {
		r.PingError = "ping not available"
	}
	return r
}

func reachState() *State {
	return &State{Domain: "example.com", Apex: "example.com",
		ApexV4: []netip.Addr{netip.MustParseAddr("5.0.0.1")}, ApexV6: []netip.Addr{netip.MustParseAddr("2a00::1")}}
}

func TestReach(t *testing.T) {
	ok := &probe.ProbeResponse{Results: []probe.IPProbe{ipProbe("5.0.0.1", 4, "open", "open"), ipProbe("2a00::1", 4, "open", "open")}}
	icmpBlocked := &probe.ProbeResponse{Results: []probe.IPProbe{ipProbe("5.0.0.1", 0, "open", "open"), ipProbe("2a00::1", 0, "open", "open")}}
	down := &probe.ProbeResponse{Results: []probe.IPProbe{ipProbe("5.0.0.1", 0, "filtered", "filtered"), ipProbe("2a00::1", 0, "filtered", "filtered")}}
	v6bad := &probe.ProbeResponse{Results: []probe.IPProbe{ipProbe("5.0.0.1", 4, "open", "open"), ipProbe("2a00::1", 0, "filtered", "filtered")}}

	noV6 := &probe.ProbeResponse{Results: []probe.IPProbe{ipProbe("5.0.0.1", 4, "open", "open"), {IP: netip.MustParseAddr("2a00::1"), Skipped: "this node has no IPv6 connectivity"}}}
	cases := []struct {
		name     string
		ns       []*nodes.Node
		status   Status
		blocking bool
		codes    []string
	}{
		{"healthy", []*nodes.Node{node("a", &cannedProber{probe: ok}), node("b", &cannedProber{probe: ok})}, OK, false, nil},
		{"icmp blocked", []*nodes.Node{node("a", &cannedProber{probe: icmpBlocked})}, OK, false, []string{"reach.icmp_blocked"}},
		{"down", []*nodes.Node{node("a", &cannedProber{probe: down}), node("b", &cannedProber{probe: down})}, FAIL, true, []string{"reach.down_all"}},
		{"partial", []*nodes.Node{node("a", &cannedProber{probe: ok}), node("b", &cannedProber{probe: down})}, WARN, false, []string{"reach.partial"}},
		{"v6 broken", []*nodes.Node{node("a", &cannedProber{probe: v6bad})}, WARN, false, []string{"reach.v6_broken"}},
		// A node without IPv6 must not make the target look IPv6-broken.
		{"node without ipv6", []*nodes.Node{node("a", &cannedProber{probe: noV6})}, OK, false, nil},
		{"agent error", []*nodes.Node{node("a", &cannedProber{err: errors.New("x")})}, WARN, false, []string{"reach.no_data"}},
	}
	for _, c := range cases {
		r := Reach(context.Background(), reachState(), c.ns)
		if r.Status != c.status || r.Blocking != c.blocking {
			t.Errorf("%s: status %s blocking %v [%s]", c.name, r.Status, r.Blocking, codes(r))
		}
		for _, code := range c.codes {
			if !r.Has(code) {
				t.Errorf("%s: missing %s in [%s]", c.name, code, codes(r))
			}
		}
	}
	if r := Reach(context.Background(), &State{Domain: "x.com"}, nil); r.Status != SKIPPED {
		t.Error("no targets should skip")
	}
}
