package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"domaindoctor/internal/probe"
)

// newTLSAgent serves the agent API over TLS with a GenerateCert certificate
// and counts requests that reached the handler.
func newTLSAgent(t *testing.T) (srv *httptest.Server, fp string, hits *atomic.Int32) {
	certPEM, keyPEM, fp, err := GenerateCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	l := &probe.Local{TraceFunc: func(_ context.Context, _ netip.Addr, _ int, line func(string)) error {
		line(" 1  1.1.1.1  3.1 ms")
		return nil
	}}
	h := (&Server{Secret: secret, P: l}).Handler()
	hits = &atomic.Int32{}
	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		h.ServeHTTP(w, r)
	}))
	srv.TLS = ServerTLSConfig(cert)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, fp, hits
}

func mustPin(t *testing.T, s string) []byte {
	b, err := ParseFingerprint(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPinnedTLS(t *testing.T) {
	srv, fp, hits := newTLSAgent(t)
	ctx := context.Background()

	c := NewPinnedClient(srv.URL, secret, mustPin(t, fp), 5*time.Second)
	if err := c.Health(ctx); err != nil {
		t.Fatalf("matching pin: %v", err)
	}
	var lines []string
	if err := c.Traceroute(ctx, netip.MustParseAddr("1.1.1.1"), 30, func(l string) { lines = append(lines, l) }); err != nil || len(lines) != 1 {
		t.Fatalf("SSE over TLS: err %v lines %v", err, lines)
	}

	// A wrong pin fails the handshake before any request (and so the
	// secret) is sent, and the error stays generic.
	before := hits.Load()
	wrong := NewPinnedClient(srv.URL, secret, mustPin(t, strings.Repeat("ab", 32)), 5*time.Second)
	err := wrong.Health(ctx)
	if !errors.Is(err, ErrUnreachable) || err.Error() != "agent unreachable" {
		t.Fatalf("wrong pin: err %v", err)
	}
	if _, err := wrong.Probe(ctx, probe.ProbeRequest{}); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("wrong pin probe: err %v", err)
	}
	if hits.Load() != before {
		t.Fatal("request reached the agent despite a pin mismatch")
	}

	// Without a pin a self-signed agent is rejected by normal verification.
	if err := NewClient(srv.URL, secret, 5*time.Second).Health(ctx); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("unpinned self-signed: err %v", err)
	}
}

func TestPlainHTTPStillWorks(t *testing.T) {
	srv, _ := newAgent(t)
	if err := NewPinnedClient(srv.URL, secret, nil, 2*time.Second).Health(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestServerRefusesOldTLS(t *testing.T) {
	srv, _, _ := newTLSAgent(t)
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11})
	if err == nil {
		conn.Close()
		t.Fatal("TLS 1.1 handshake accepted")
	}
}

func TestParseFingerprint(t *testing.T) {
	hex := strings.Repeat("0a", 32)
	colons := strings.ToUpper(strings.TrimSuffix(strings.Repeat("0a:", 32), ":"))
	for _, s := range []string{hex, colons, " " + hex + "\n"} {
		if b, err := ParseFingerprint(s); err != nil || len(b) != 32 || b[0] != 0x0a {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "zz", hex[:62], hex + "00", "sha256:" + hex} {
		if _, err := ParseFingerprint(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestGenerateCert(t *testing.T) {
	certPEM, keyPEM, fp, err := GenerateCert([]string{"203.0.113.7", "agent.example", ""}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(cert.Raw) != fp || len(fp) != 64 {
		t.Fatalf("fingerprint %s", fp)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA || len(cert.IPAddresses) != 1 || len(cert.DNSNames) != 1 {
		t.Fatalf("cert %v %v %v", cert.PublicKeyAlgorithm, cert.IPAddresses, cert.DNSNames)
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Fatal("key not PEM")
	}
}
