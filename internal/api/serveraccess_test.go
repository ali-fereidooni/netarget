package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"domaindoctor/internal/clientip"
	"domaindoctor/internal/dnsx"
	"domaindoctor/internal/nodes"
	"domaindoctor/internal/orchestrator"
	"domaindoctor/internal/probe"
	"domaindoctor/internal/report"
	"domaindoctor/internal/serveraccess"
)

// (netip imported indirectly via probe types in other files)

// reachProber reports the target reachable on port 80.
type reachProber struct{ nopProber }

func (reachProber) Probe(_ context.Context, req probe.ProbeRequest) (*probe.ProbeResponse, error) {
	resp := &probe.ProbeResponse{}
	for _, ip := range req.IPs {
		r := probe.IPProbe{IP: ip, Ping: &probe.PingResult{Sent: 4, Received: 4}}
		for _, p := range req.Ports {
			st := "closed"
			if p == 80 {
				st = "open"
			}
			r.TCP = append(r.TCP, probe.TCPResult{Port: p, Status: st})
		}
		resp.Results = append(resp.Results, r)
	}
	return resp, nil
}

func newSAServer(t *testing.T, ports []int) *httptest.Server {
	return newSAServerWith(t, serveraccess.Deps{Ports: ports, Now: time.Now, CustomPortAllowed: true})
}

func newSAServerWith(t *testing.T, sa serveraccess.Deps) *httptest.Server {
	store, _ := report.OpenStore(t.TempDir(), 10, 24*time.Hour)
	s := New(Config{
		Deps:         orchestrator.Deps{DNS: dnsx.New(), RDAP: blockingReg{}},
		Registry:     nodes.New(nodes.LocalNode("n1", "test", reachProber{})),
		ClientIP:     clientip.Extractor{Hops: 1},
		Store:        store,
		ServerAccess: sa,
	})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func saGet(t *testing.T, url, clientIP string) (int, string) {
	req, _ := http.NewRequest("GET", url, nil)
	if clientIP != "" {
		req.Header.Set("X-Forwarded-For", clientIP)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestServerAccessStream(t *testing.T) {
	ts := newSAServer(t, []int{80, 443})
	code, body := saGet(t, ts.URL+"/api/server-access?target=93.184.215.14&authorized=1", "198.51.100.10")
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	for _, want := range []string{"event: meta", "event: identity", "event: ping", "event: services", "event: done"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in stream:\n%s", want, body)
		}
	}
	if !strings.Contains(body, `"state":"open"`) {
		t.Errorf("expected an open port in stream:\n%s", body)
	}
}

func TestServerAccessAuthorizationRequired(t *testing.T) {
	ts := newSAServer(t, []int{80, 443})
	code, body := saGet(t, ts.URL+"/api/server-access?target=93.184.215.14", "198.51.100.11")
	if code != 400 || !strings.Contains(body, "sa_unauthorized") {
		t.Errorf("want 400 sa_unauthorized, got %d %s", code, body)
	}
}

func TestServerAccessRejectsPrivate(t *testing.T) {
	ts := newSAServer(t, []int{80, 443})
	for _, tgt := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254"} {
		code, body := saGet(t, ts.URL+"/api/server-access?target="+tgt+"&authorized=1", "198.51.100.12")
		if code != 400 || !strings.Contains(body, "sa_private") {
			t.Errorf("%s: want 400 sa_private, got %d %s", tgt, code, body)
		}
	}
}

func TestServerAccessDisabled(t *testing.T) {
	ts := newSAServer(t, nil) // no ports configured => feature off
	code, body := saGet(t, ts.URL+"/api/server-access?target=93.184.215.14&authorized=1", "198.51.100.13")
	if code != 503 || !strings.Contains(body, "sa_disabled") {
		t.Errorf("want 503 sa_disabled, got %d %s", code, body)
	}
}

func TestServerAccessCustomPort(t *testing.T) {
	ts := newSAServer(t, []int{80, 443})
	code, body := saGet(t, ts.URL+"/api/server-access?target=93.184.215.14&authorized=1&port=2053", "198.51.100.20")
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	for _, want := range []string{`"custom_port":2053`, `"ports":[80,443,2053]`, `"port":2053`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in stream:\n%s", want, body)
		}
	}

	for i, bad := range []string{"abc", "0", "70000", "-5", "1e3"} {
		code, body := saGet(t, ts.URL+"/api/server-access?target=93.184.215.14&authorized=1&port="+bad, fmt.Sprintf("198.51.100.%d", 21+i))
		if code != 400 || !strings.Contains(body, "sa_bad_port") {
			t.Errorf("port=%s: want 400 sa_bad_port, got %d %s", bad, code, body)
		}
	}

	off := newSAServerWith(t, serveraccess.Deps{Ports: []int{80, 443}, Now: time.Now})
	code, body = saGet(t, off.URL+"/api/server-access?target=93.184.215.14&authorized=1&port=2053", "198.51.100.30")
	if code != 400 || !strings.Contains(body, "sa_port_off") {
		t.Errorf("custom port disabled: want 400 sa_port_off, got %d %s", code, body)
	}
}
