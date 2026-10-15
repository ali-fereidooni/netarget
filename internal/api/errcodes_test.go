package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every fixed message the API sends has a stable code, and the UI has an EN
// and an FA string for every code (STRINGS err.<code> in app.js).
func TestErrorCodesCoverMessagesAndUI(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	lits := regexp.MustCompile(`writeErr\(w, [\w.]+, "([^"]+)"\)`).FindAllStringSubmatch(string(src), -1)
	if len(lits) < 15 {
		t.Fatalf("found only %d writeErr literals; regexp out of date?", len(lits))
	}
	for _, m := range lits {
		if errorCodes[m[1]] == "" {
			t.Errorf("no error code for %q", m[1])
		}
	}

	js, err := os.ReadFile("../../web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	codes := []string{"domain_empty", "domain_ip", "domain_local", "domain_invalid", "domain_no_tld", "domain_public_suffix", "network", "http"}
	for _, c := range errorCodes {
		codes = append(codes, c)
	}
	for _, c := range codes {
		// one entry in the en block and one in the fa block
		if n := strings.Count(string(js), "\n      "+c+": "); n != 2 {
			t.Errorf("app.js has %d STRINGS entries for err.%s, want 2 (en + fa)", n, c)
		}
	}
}

func TestErrorResponsesCarryCode(t *testing.T) {
	_, ts := newServer(t, blockingReg{}, 30, 10)
	cases := map[string]string{
		`{"domain":"1.2.3.4"}`:    "domain_ip",
		`{"domain":"localhost"}`:  "domain_local",
		`{"domain":"bad domain"}`: "domain_invalid",
		`{"domain":""}`:           "domain_empty",
		`not json`:                "invalid_body",
	}
	i := 0
	for body, want := range cases {
		i++
		code, m := post(t, ts.URL+"/api/check", fmt.Sprintf("198.51.100.%d", 120+i), body)
		if code != 400 || m["code"] != want || m["error"] == "" {
			t.Errorf("%s: %d %v (want code %s)", body, code, m, want)
		}
	}
	code, m := post(t, ts.URL+"/api/web-diagnose", "198.51.100.140", `{"domain":"example.com","originIp":"10.0.0.5"}`)
	if code != 400 || m["code"] != "origin_private" {
		t.Errorf("origin: %d %v", code, m)
	}
}

// With X-Error-Envelope (sent by the UI) errors come back as 200 so a CDN
// cannot swap them for its own error page; without it, normal status codes.
func TestErrorEnvelope(t *testing.T) {
	_, ts := newServer(t, blockingReg{}, 30, 10)
	for _, env := range []bool{true, false} {
		req, _ := http.NewRequest("POST", ts.URL+"/api/check", strings.NewReader(`{"domain":"1.2.3.4"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "198.51.100.150")
		if env {
			req.Header.Set(EnvelopeHeader, "1")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		resp.Body.Close()
		wantStatus, wantHdr := 400, ""
		if env {
			wantStatus, wantHdr = 200, "400"
		}
		if resp.StatusCode != wantStatus || resp.Header.Get("X-Api-Status") != wantHdr || m["code"] != "domain_ip" {
			t.Errorf("envelope=%v: %d %q %v", env, resp.StatusCode, resp.Header.Get("X-Api-Status"), m)
		}
	}
}
