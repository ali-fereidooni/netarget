package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"domaindoctor/internal/probe"
)

const secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newAgent(t *testing.T) (*httptest.Server, *probe.Local) {
	l := &probe.Local{
		PingFunc: func(context.Context, netip.Addr, int) (*probe.PingResult, error) {
			return &probe.PingResult{Sent: 4, Received: 4, RTTAvg: 1.5}, nil
		},
		TraceFunc: func(_ context.Context, _ netip.Addr, _ int, line func(string)) error {
			line(" 1  10.0.0.1  0.5 ms")
			line(" 2  1.1.1.1  3.1 ms")
			return nil
		},
	}
	srv := httptest.NewServer((&Server{Secret: secret, P: l}).Handler())
	t.Cleanup(srv.Close)
	return srv, l
}

func TestAuth(t *testing.T) {
	srv, _ := newAgent(t)
	for _, s := range []string{"", "wrong", secret[:63]} {
		req, _ := http.NewRequest("GET", srv.URL+"/health", nil)
		if s != "" {
			req.Header.Set(SecretHeader, s)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("secret %q: status %d", s, resp.StatusCode)
		}
	}
	c := NewClient(srv.URL, secret, 2*time.Second)
	if err := c.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	bad := NewClient(srv.URL, "nope", 2*time.Second)
	if err := bad.Health(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("bad secret err %v", err)
	}
}

func TestProbeRoundTrip(t *testing.T) {
	srv, _ := newAgent(t)
	c := NewClient(srv.URL, secret, 10*time.Second)
	resp, err := c.Probe(context.Background(), probe.ProbeRequest{Host: "example.com",
		IPs: []netip.Addr{netip.MustParseAddr("192.0.2.200")}, PingCount: 4, Ports: []int{80}})
	// 192.0.2.0/24 is TEST-NET: the agent must refuse it even though the master sent it.
	if !errors.Is(err, ErrUnreachable) || resp == nil {
		t.Fatalf("blocked IP: err=%v", err)
	}
	// The agent rejects private IPs sent by a (compromised or buggy) master.
	_, err = c.Probe(context.Background(), probe.ProbeRequest{IPs: []netip.Addr{netip.MustParseAddr("169.254.169.254")}, Ports: []int{80}})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("metadata accepted: %v", err)
	}
}

func TestTracerouteSSE(t *testing.T) {
	srv, _ := newAgent(t)
	c := NewClient(srv.URL, secret, 10*time.Second)
	var lines []string
	err := c.Traceroute(context.Background(), netip.MustParseAddr("1.1.1.1"), 30, func(l string) { lines = append(lines, l) })
	if err != nil || len(lines) != 2 || !strings.Contains(lines[1], "1.1.1.1") {
		t.Fatalf("err %v lines %v", err, lines)
	}
	resp, err := http.Get(srv.URL + "/v1/traceroute?ip=1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("unauthenticated traceroute allowed")
	}
	// Private targets are refused by the agent.
	err = c.Traceroute(context.Background(), netip.MustParseAddr("10.1.1.1"), 30, func(string) {})
	if err == nil {
		t.Fatal("private traceroute allowed")
	}
}

// TestClientDoesNotFollowRedirects: a malicious agent redirecting the master
// elsewhere must not receive (or relay) the secret.
func TestClientDoesNotFollowRedirects(t *testing.T) {
	leaked := make(chan string, 1)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked <- r.Header.Get(SecretHeader)
	}))
	defer sink.Close()
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer evil.Close()
	c := NewClient(evil.URL, secret, 2*time.Second)
	if err := c.Health(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err %v", err)
	}
	select {
	case s := <-leaked:
		t.Fatalf("redirect followed, secret %q sent", s)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestUnreachableIsGeneric(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", secret, 500*time.Millisecond)
	_, err := c.Probe(context.Background(), probe.ProbeRequest{})
	if err == nil || err.Error() != "agent unreachable" {
		t.Fatalf("err %v", err)
	}
}
