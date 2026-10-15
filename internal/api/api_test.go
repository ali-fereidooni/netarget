package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"domaindoctor/internal/clientip"
	"domaindoctor/internal/dnsx"
	"domaindoctor/internal/input"
	"domaindoctor/internal/nodes"
	"domaindoctor/internal/orchestrator"
	"domaindoctor/internal/probe"
	"domaindoctor/internal/rdap"
	"domaindoctor/internal/report"
)

// blockingReg returns not-found after `release` is closed (or immediately if nil).
type blockingReg struct{ release chan struct{} }

func (b blockingReg) Lookup(ctx context.Context, _ string) (*rdap.Info, error) {
	if b.release != nil {
		select {
		case <-b.release:
		case <-ctx.Done():
		}
	}
	return nil, rdap.ErrNotFound
}

type nopProber struct{}

func (nopProber) Health(context.Context) error { return nil }
func (nopProber) Probe(context.Context, probe.ProbeRequest) (*probe.ProbeResponse, error) {
	return nil, nil
}
func (nopProber) HTTP(context.Context, probe.HTTPRequest) (*probe.HTTPResponse, error) {
	return nil, nil
}
func (nopProber) Traceroute(context.Context, netip.Addr, int, func(string)) error { return nil }
func (nopProber) Resources(context.Context, probe.ResourceRequest) (*probe.ResourceResponse, error) {
	return nil, nil
}

func newServer(t *testing.T, reg blockingReg, maxConc int, storeCap int) (*Server, *httptest.Server) {
	store, err := report.OpenStore(t.TempDir(), storeCap, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{
		Deps:          orchestrator.Deps{DNS: dnsx.New(), RDAP: reg},
		Registry:      nodes.New(&nodes.Node{ID: "n1", Name: "Node 1", Location: "Test", P: nopProber{}}),
		ClientIP:      clientip.Extractor{Hops: 1},
		Store:         store,
		MaxConcurrent: maxConc,
	})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func post(t *testing.T, url, clientIP, body string) (int, map[string]any) {
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if clientIP != "" {
		req.Header.Set("X-Forwarded-For", clientIP)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func get(t *testing.T, url string) (int, string) {
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func waitDone(t *testing.T, ts *httptest.Server, id string) {
	for i := 0; i < 100; i++ {
		_, body := get(t, ts.URL+"/api/check/"+id)
		if strings.Contains(body, `"status":"done"`) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("check did not finish")
}

func TestCheckLifecycleAndSSE(t *testing.T) {
	_, ts := newServer(t, blockingReg{}, 30, 10)
	code, m := post(t, ts.URL+"/api/check", "198.51.100.1", `{"domain":"HTTPS://WWW.Example.COM/path"}`)
	if code != http.StatusAccepted {
		t.Fatalf("code %d %v", code, m)
	}
	id := m["request_id"].(string)
	if !report.ValidID(id) || m["domain"].(map[string]any)["name"] != "example.com" {
		t.Fatalf("resp %v", m)
	}
	waitDone(t, ts, id)

	// SSE replay after completion.
	resp, err := http.Get(ts.URL + "/api/check/" + id + "?stream=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Accel-Buffering") != "no" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("headers %v", resp.Header)
	}
	var events []string
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "event: ") {
			events = append(events, strings.TrimPrefix(sc.Text(), "event: "))
		}
	}
	joined := strings.Join(events, ",")
	if !strings.HasPrefix(joined, "request_id,layer_start,layer_done,layer_done") || !strings.HasSuffix(joined, "done") {
		t.Fatalf("events %s", joined)
	}

	// Markdown export.
	code, md := get(t, ts.URL+"/api/check/"+id+"?format=md")
	if code != 200 || !strings.Contains(md, "The domain is not registered") {
		t.Fatalf("md %d %s", code, md)
	}
}

func TestInputErrors(t *testing.T) {
	_, ts := newServer(t, blockingReg{}, 30, 10)
	cases := map[string]string{
		`{"domain":"1.2.3.4"}`:    "IP addresses are not supported",
		`{"domain":"localhost"}`:  "local or reserved",
		`{"domain":"bad domain"}`: "valid domain",
		`not json`:                "invalid request body",
	}
	i := 0
	for body, want := range cases {
		i++
		code, m := post(t, ts.URL+"/api/check", fmt.Sprintf("198.51.100.%d", i), body)
		if code != 400 || !strings.Contains(fmt.Sprint(m["error"]), want) {
			t.Errorf("%s: %d %v", body, code, m)
		}
	}
	for _, p := range []string{"/api/check/../../etc/passwd", "/api/check/ZZZZ", "/api/check/" + strings.Repeat("a", 40)} {
		if code, _ := get(t, ts.URL+p); code != 404 {
			t.Errorf("%s: %d", p, code)
		}
	}
}

func TestRateLimitAndSpoofing(t *testing.T) {
	_, ts := newServer(t, blockingReg{}, 30, 10)
	// Burst of 5 then 429; requests are invalid so no check actually runs.
	for i := 0; i < 5; i++ {
		if code, _ := post(t, ts.URL+"/api/check", "203.0.113.7", `{"domain":"1.1.1.1"}`); code != 400 {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	if code, m := post(t, ts.URL+"/api/check", "203.0.113.7", `{"domain":"1.1.1.1"}`); code != 429 {
		t.Fatalf("6th request: %d %v", code, m)
	}
	// Prepending a forged entry does not create a fresh bucket (Hops=1 trusts only the last entry).
	if code, _ := post(t, ts.URL+"/api/check", "6.6.6.6, 203.0.113.7", `{"domain":"1.1.1.1"}`); code != 429 {
		t.Fatalf("spoofed XFF bypassed the limiter: %d", code)
	}
	// Another client is unaffected.
	if code, _ := post(t, ts.URL+"/api/check", "203.0.113.8", `{"domain":"1.1.1.1"}`); code != 400 {
		t.Fatalf("other client: %d", code)
	}
}

func TestPerIPAndGlobalConcurrency(t *testing.T) {
	release := make(chan struct{})
	_, ts := newServer(t, blockingReg{release: release}, 2, 10)
	defer close(release)
	if code, _ := post(t, ts.URL+"/api/check", "192.0.2.10", `{"domain":"example.com"}`); code != 202 {
		t.Fatal(code)
	}
	if code, m := post(t, ts.URL+"/api/check", "192.0.2.10", `{"domain":"example.org"}`); code != 429 || !strings.Contains(fmt.Sprint(m["error"]), "already running") {
		t.Fatalf("second concurrent check from same IP: %d %v", code, m)
	}
	if code, _ := post(t, ts.URL+"/api/check", "192.0.2.11", `{"domain":"example.org"}`); code != 202 {
		t.Fatalf("other IP: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/check", "192.0.2.12", `{"domain":"example.net"}`); code != 503 {
		t.Fatalf("global cap: %d", code)
	}
}

func TestPromoteAndReport(t *testing.T) {
	_, ts := newServer(t, blockingReg{}, 30, 1)
	code, m := post(t, ts.URL+"/api/check", "192.0.2.20", `{"domain":"example.com"}`)
	if code != 202 {
		t.Fatal(code)
	}
	id := m["request_id"].(string)
	waitDone(t, ts, id)

	if code, _ := post(t, ts.URL+"/api/report/promote", "192.0.2.20", `{"request_id":"../x"}`); code != 400 {
		t.Fatalf("invalid id: %d", code)
	}
	code, m = post(t, ts.URL+"/api/report/promote", "192.0.2.20", `{"request_id":"`+id+`"}`)
	if code != 200 {
		t.Fatalf("promote: %d %v", code, m)
	}
	rid := m["id"].(string)
	if rid == id || !report.ValidID(rid) {
		t.Fatal("promoted report must get a fresh id")
	}
	code, body := get(t, ts.URL+"/api/report?id="+rid)
	if code != 200 || !strings.Contains(body, `"kind":"check"`) || !strings.Contains(body, "reg.not_registered") {
		t.Fatalf("report: %d %s", code, body)
	}
	if code, md := get(t, ts.URL+"/api/report?id="+rid+"&format=md"); code != 200 || !strings.Contains(md, "# netarget report") {
		t.Fatalf("report md: %d", code)
	}
	if code, _ := get(t, ts.URL+"/api/report?id=../../etc/passwd"); code != 404 {
		t.Fatalf("traversal: %d", code)
	}
	// Store cap is 1: rejected, never evicted.
	if code, m := post(t, ts.URL+"/api/report/promote", "192.0.2.20", `{"request_id":"`+id+`"}`); code != 503 {
		t.Fatalf("full store: %d %v", code, m)
	}
	if code, _ := get(t, ts.URL+"/api/report?id="+rid); code != 200 {
		t.Fatal("existing report evicted")
	}
	// Promote limiter: burst 3 per IP per hour (2 used above + 1 invalid = 3).
	if code, _ := post(t, ts.URL+"/api/report/promote", "192.0.2.20", `{"request_id":"`+id+`"}`); code != 429 {
		t.Fatalf("promote limit: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/report/promote", "192.0.2.21", `{"request_id":"`+strings.Repeat("0", 40)+`"}`); code != 404 {
		t.Fatalf("unknown id: %d", code)
	}
}

func TestNodesAndTraceroute(t *testing.T) {
	_, ts := newServer(t, blockingReg{}, 30, 10)
	code, body := get(t, ts.URL+"/api/nodes")
	if code != 200 || body != `[{"id":"n1","name":"Node 1","location":"Test"}]`+"\n" {
		t.Fatalf("nodes: %s", body)
	}
	code, m := post(t, ts.URL+"/api/check", "192.0.2.30", `{"domain":"example.com"}`)
	id := m["request_id"].(string)
	waitDone(t, ts, id)
	if code, body := get(t, ts.URL+"/api/traceroute?id="+id+"&node=n1&ip=8.8.8.8"); code != 400 {
		t.Fatalf("traceroute to an IP outside the report: %d %s", code, body)
	}
	if code, _ := get(t, ts.URL+"/api/traceroute?id="+strings.Repeat("1", 40)+"&node=n1&ip=8.8.8.8"); code != 404 {
		t.Fatal("traceroute without a check allowed")
	}
	_ = code
}

// TestWebDiagnoseOriginIPValidation: the user-supplied origin IP passes the
// same SSRF policy as everything else, on the master (agents check again).
func TestWebDiagnoseOriginIPValidation(t *testing.T) {
	_, ts := newServer(t, blockingReg{}, 30, 10)
	bad := []string{"10.0.0.5", "127.0.0.1", "169.254.169.254", "::1", "fe80::1", "::ffff:127.0.0.1", "0.0.0.0", "192.168.1.10", "100.64.0.1", "203.0.113.10", "example.com", "1.2.3.4:443"}
	for i, ip := range bad {
		code, m := post(t, ts.URL+"/api/web-diagnose", fmt.Sprintf("198.51.100.%d", 50+i), `{"domain":"example.com","originIp":"`+ip+`"}`)
		if code != 400 || !strings.Contains(fmt.Sprint(m["error"]), "originIp") {
			t.Errorf("origin %s: %d %v", ip, code, m)
		}
	}
	if code, m := post(t, ts.URL+"/api/check", "198.51.100.90", `{"domain":"example.com","originIp":"203.0.113.10"}`); code != 400 {
		t.Errorf("/api/check accepted originIp: %d %v", code, m)
	}
	code, m := post(t, ts.URL+"/api/web-diagnose", "198.51.100.91", `{"domain":"example.com","originIp":"93.184.215.14"}`)
	if code != 202 || m["request_id"] == nil {
		t.Fatalf("valid origin: %d %v", code, m)
	}
	waitDone(t, ts, m["request_id"].(string))
	code, m = post(t, ts.URL+"/api/web-diagnose", "198.51.100.92", `{"domain":"example.com"}`)
	if code != 202 {
		t.Fatalf("without origin: %d %v", code, m)
	}
}

func TestParseOriginIP(t *testing.T) {
	if a, err := input.ParseOriginIP(" [2606:4700::1111] "); err != nil || a.String() != "2606:4700::1111" {
		t.Fatalf("%v %v", a, err)
	}
	if a, err := input.ParseOriginIP(""); err != nil || a.IsValid() {
		t.Fatal("empty origin should be no origin")
	}
}
