package serveraccess

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"domaindoctor/internal/asn"
	"domaindoctor/internal/nodes"
	"domaindoctor/internal/probe"
	"domaindoctor/internal/rdap"
)

// --- mocks -------------------------------------------------------------

// fakeResolver returns fixed addresses per name (no network).
type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, &net2err{}
}

type net2err struct{}

func (*net2err) Error() string { return "no such host" }

type fakePTR map[string]string

func (f fakePTR) LookupPTR(_ context.Context, ip netip.Addr) (string, error) {
	return f[ip.String()], nil
}

type fakeRDAP map[string]*rdap.IPInfo

func (f fakeRDAP) LookupIP(_ context.Context, ip netip.Addr) (*rdap.IPInfo, error) {
	if i, ok := f[ip.String()]; ok {
		return i, nil
	}
	return nil, rdap.ErrNotFound
}

type fakeASN map[string]*asn.Record

func (f fakeASN) Lookup(ip netip.Addr) (*asn.Record, bool) {
	r, ok := f[ip.String()]
	return r, ok
}

// mockProber returns scripted probe results and records what it was asked.
type mockProber struct {
	probe.Prober
	results  map[netip.Addr]probe.IPProbe
	httpResp *probe.HTTPResponse
	gotPorts []int
}

func (m *mockProber) Probe(_ context.Context, req probe.ProbeRequest) (*probe.ProbeResponse, error) {
	m.gotPorts = req.Ports
	resp := &probe.ProbeResponse{}
	for _, ip := range req.IPs {
		if r, ok := m.results[ip]; ok {
			r.IP = ip
			resp.Results = append(resp.Results, r)
		} else {
			resp.Results = append(resp.Results, probe.IPProbe{IP: ip, Skipped: "no data"})
		}
	}
	return resp, nil
}

func (m *mockProber) HTTP(_ context.Context, _ probe.HTTPRequest) (*probe.HTTPResponse, error) {
	if m.httpResp != nil {
		return m.httpResp, nil
	}
	return &probe.HTTPResponse{}, nil
}

func (m *mockProber) Health(context.Context) error { return nil }

// --- tests -------------------------------------------------------------

func TestParseTarget(t *testing.T) {
	res := fakeResolver{"host.example.com": {netip.MustParseAddr("93.184.215.14")}}
	cases := []struct {
		in      string
		wantErr error
		host    string
		ip      string
	}{
		{"93.184.215.14", nil, "", "93.184.215.14"},
		{"[2606:2800:21f:cb07:6820:80da:af6b:8b2c]", nil, "", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"},
		{"https://host.example.com/path", nil, "host.example.com", "93.184.215.14"},
		{"host.example.com:8443", nil, "host.example.com", "93.184.215.14"},
		{"", ErrEmpty, "", ""},
		{"127.0.0.1", ErrPrivate, "", ""},
		{"10.0.0.5", ErrPrivate, "", ""},
		{"169.254.169.254", ErrPrivate, "", ""},
		{"localhost", ErrReserved, "", ""},
		{"not a host", ErrInvalid, "", ""},
		{"nope.example.org", ErrNoIP, "", ""},
	}
	for _, c := range cases {
		tg, err := ParseTarget(context.Background(), res, c.in)
		if c.wantErr != nil {
			if err != c.wantErr {
				t.Errorf("%q: err = %v, want %v", c.in, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected err %v", c.in, err)
			continue
		}
		if tg.Host != c.host {
			t.Errorf("%q: host = %q, want %q", c.in, tg.Host, c.host)
		}
		if len(tg.IPs) == 0 || tg.IPs[0].String() != c.ip {
			t.Errorf("%q: ips = %v, want %s", c.in, tg.IPs, c.ip)
		}
	}
}

func node(p probe.Prober) *nodes.Node { return nodes.LocalNode("n1", "test", p) }

func TestRunReachable(t *testing.T) {
	ip := netip.MustParseAddr("93.184.215.14")
	mp := &mockProber{results: map[netip.Addr]probe.IPProbe{
		ip: {
			Ping: &probe.PingResult{Sent: 4, Received: 4, RTTMin: 1, RTTAvg: 2, RTTMax: 3},
			TCP: []probe.TCPResult{
				{Port: 22, Status: "open", LatencyMS: 5},
				{Port: 80, Status: "closed"},
				{Port: 443, Status: "open", LatencyMS: 7},
			},
		},
	}}
	deps := Deps{
		PTR:   fakePTR{"93.184.215.14": "host.example.com"},
		RDAP:  fakeRDAP{"93.184.215.14": {Network: "93.184.215.0/24", Name: "EXAMPLE-NET", Org: "Example Org", Country: "US", Abuse: "abuse@example.com"}},
		ASN:   fakeASN{"93.184.215.14": {ASN: "AS64500", Name: "EXAMPLE", Domain: "example.com"}},
		Ports: []int{22, 80, 443},
		Now:   func() time.Time { return time.Unix(0, 0).UTC() },
	}
	tg := Target{Input: "93.184.215.14", IPs: []netip.Addr{ip}}

	var events []string
	rep := Run(context.Background(), deps, tg, []*nodes.Node{node(mp)}, "id1", func(e Event) { events = append(events, e.Type) })

	if rep.Status != StatusDone {
		t.Fatalf("status = %q", rep.Status)
	}
	wantEvents := []string{"start", "identity", "ping", "services", "done"}
	if len(events) != len(wantEvents) {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
	id := rep.Identity.IPs[0]
	if id.PTR != "host.example.com" || id.ASN != "AS64500" || id.Org != "Example Org" || id.Abuse != "abuse@example.com" {
		t.Errorf("identity = %+v", id)
	}
	if rep.Ping.ReachableNodes != 1 || rep.Ping.TotalNodes != 1 {
		t.Errorf("ping summary nodes = %d/%d", rep.Ping.ReachableNodes, rep.Ping.TotalNodes)
	}
	// Ports: 22 open, 80 closed, 443 open.
	byPort := map[int]string{}
	for _, r := range rep.Services.Rows {
		byPort[r.Port] = r.State
	}
	if byPort[22] != "open" || byPort[80] != "closed" || byPort[443] != "open" {
		t.Errorf("port states = %v", byPort)
	}
}

func TestRunUnreachable(t *testing.T) {
	ip := netip.MustParseAddr("93.184.215.20")
	mp := &mockProber{results: map[netip.Addr]probe.IPProbe{
		ip: {
			Ping: &probe.PingResult{Sent: 4, Received: 0, Loss: 100},
			TCP:  []probe.TCPResult{{Port: 443, Status: "filtered"}},
		},
	}}
	deps := Deps{Ports: []int{443}, Now: time.Now}
	tg := Target{Input: ip.String(), IPs: []netip.Addr{ip}}
	rep := Run(context.Background(), deps, tg, []*nodes.Node{node(mp)}, "id2", nil)
	if rep.Ping.ReachableNodes != 0 {
		t.Errorf("reachable = %d, want 0", rep.Ping.ReachableNodes)
	}
	if rep.Services.Rows[0].State != "filtered" {
		t.Errorf("state = %q, want filtered", rep.Services.Rows[0].State)
	}
}

func TestRunNodeError(t *testing.T) {
	ip := netip.MustParseAddr("93.184.215.30")
	// A node with no scripted result returns Skipped("no data"); ensure the
	// run still completes and marks the port state unknown (no measurement).
	mp := &mockProber{results: map[netip.Addr]probe.IPProbe{}}
	deps := Deps{Ports: []int{80}, Now: time.Now}
	tg := Target{Input: ip.String(), IPs: []netip.Addr{ip}}
	rep := Run(context.Background(), deps, tg, []*nodes.Node{node(mp)}, "id3", nil)
	if rep.Status != StatusDone {
		t.Fatalf("status = %q", rep.Status)
	}
	if rep.Services.Rows[0].State != "unknown" {
		t.Errorf("state = %q, want unknown", rep.Services.Rows[0].State)
	}
}

func TestWithCustomPort(t *testing.T) {
	base := Deps{Ports: []int{22, 80, 443, 8443}, CustomPortAllowed: true}
	cases := []struct {
		port    int
		allowed bool
		want    []int
		wantErr error
	}{
		{0, true, []int{22, 80, 443, 8443}, nil},
		{2053, true, []int{22, 80, 443, 2053, 8443}, nil},
		{443, true, []int{22, 80, 443, 8443}, nil}, // already listed: not added twice
		{70000, true, nil, ErrBadPort},
		{-1, true, nil, ErrBadPort},
		{2053, false, nil, ErrCustomPortOff},
	}
	for _, c := range cases {
		d := base
		d.CustomPortAllowed = c.allowed
		got, err := d.WithCustomPort(c.port)
		if err != c.wantErr {
			t.Errorf("port %d: err %v, want %v", c.port, err, c.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if fmt.Sprint(got.Ports) != fmt.Sprint(c.want) {
			t.Errorf("port %d: ports %v, want %v", c.port, got.Ports, c.want)
		}
	}
	// The shared config slice must never be modified.
	if fmt.Sprint(base.Ports) != "[22 80 443 8443]" {
		t.Errorf("base ports mutated: %v", base.Ports)
	}
}
