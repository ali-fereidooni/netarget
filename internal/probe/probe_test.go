package probe

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const linuxPing = `PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=0.712 ms
--- 1.1.1.1 ping statistics ---
4 packets transmitted, 3 received, 25% packet loss, time 3004ms
rtt min/avg/max/mdev = 0.701/0.812/0.950/0.090 ms`

const linuxDown = `PING 10.255.255.1 (10.255.255.1) 56(84) bytes of data.

--- 10.255.255.1 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3062ms`

const windowsPing = `Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=5ms TTL=58
Reply from 1.1.1.1: bytes=32 time=7ms TTL=58
Reply from 1.1.1.1: bytes=32 time=6ms TTL=58
Request timed out.

Ping statistics for 1.1.1.1:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
Approximate round trip times in milli-seconds:
    Minimum = 5ms, Maximum = 7ms, Average = 6ms`

const windowsUnreach = `Pinging 203.0.113.5 with 32 bytes of data:
Reply from 192.168.1.1: Destination host unreachable.
Reply from 192.168.1.1: Destination host unreachable.

Ping statistics for 203.0.113.5:
    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),`

const macPing = `--- 1.1.1.1 ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 10.1/11.2/12.3/0.5 ms`

func TestParsePing(t *testing.T) {
	cases := []struct {
		name                string
		out                 string
		sent, recv          int
		loss, min, avg, max float64
	}{
		{"linux", linuxPing, 4, 3, 25, 0.701, 0.812, 0.950},
		{"linux down", linuxDown, 4, 0, 100, 0, 0, 0},
		{"windows", windowsPing, 4, 3, 25, 5, 6, 7},
		{"windows unreachable", windowsUnreach, 2, 0, 100, 0, 0, 0},
		{"mac", macPing, 4, 4, 0, 10.1, 11.2, 12.3},
	}
	for _, c := range cases {
		r, err := ParsePing(c.out)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if r.Sent != c.sent || r.Received != c.recv || r.Loss != c.loss || r.RTTMin != c.min || r.RTTAvg != c.avg || r.RTTMax != c.max {
			t.Errorf("%s: got %+v", c.name, r)
		}
	}
	if _, err := ParsePing("ping: unknown host"); err == nil {
		t.Error("garbage parsed")
	}
}

func TestPingArgsNoShell(t *testing.T) {
	ip := netip.MustParseAddr("2606:4700::1111")
	args := pingArgs("linux", ip, 4)
	if args[len(args)-1] != "2606:4700::1111" || !contains(args, "-6") {
		t.Fatalf("args %v", args)
	}
	w := pingArgs("windows", netip.MustParseAddr("1.1.1.1"), 3)
	if strings.Join(w, " ") != "-n 3 -w 2000 -4 1.1.1.1" {
		t.Fatalf("windows args %v", w)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestHopIP(t *testing.T) {
	cases := map[string]string{
		" 1  192.168.1.1  0.512 ms":                "192.168.1.1",
		" 7  2001:db8::1  12.1 ms":                 "2001:db8::1",
		"  3     5 ms     4 ms     4 ms  10.0.0.1": "10.0.0.1",
		"12  * * *": "",
		"traceroute to 1.1.1.1 (1.1.1.1), 30 hops max": "",
	}
	for line, want := range cases {
		_, ip, ok := HopIP(line)
		if want == "" {
			if ok {
				t.Errorf("%q: unexpected %v", line, ip)
			}
			continue
		}
		if !ok || ip.String() != want {
			t.Errorf("%q: got %v %v", line, ip, ok)
		}
	}
}

func TestTCPConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	lo := netip.MustParseAddr("127.0.0.1")
	if r := TCPConnect(context.Background(), lo, port, time.Second, true); r.Status != "open" {
		t.Fatalf("open: %+v", r)
	}
	// Grab a free port and close it -> refused.
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l2.Addr().(*net.TCPAddr).Port
	l2.Close()
	if r := TCPConnect(context.Background(), lo, closed, time.Second, true); r.Status != "closed" {
		t.Fatalf("closed: %+v", r)
	}
	// Without the test hook, loopback is blocked.
	if r := TCPConnect(context.Background(), lo, port, time.Second, false); r.Status != "filtered" || r.Error != "blocked target" {
		t.Fatalf("blocked: %+v", r)
	}
}

// tlsSite starts an httptest TLS server whose handler is h and returns a
// prober that trusts it plus the port.
func tlsSite(t *testing.T, h http.HandlerFunc) (*HTTPProber, string, *httptest.Server) {
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	u, _ := url.Parse(srv.URL)
	return &HTTPProber{AllowLoopback: true, Roots: pool, Timeout: 2 * time.Second}, u.Port(), srv
}

func pinnedLo(hosts ...string) map[string][]netip.Addr {
	m := map[string][]netip.Addr{}
	for _, h := range hosts {
		m[h] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	}
	return m
}

func TestHTTPRedirectChainAndHeaders(t *testing.T) {
	p, port, _ := tlsSite(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/home", http.StatusMovedPermanently)
			return
		}
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("Server", "nginx")
		w.Write([]byte("ok"))
	})
	resp := p.Run(context.Background(), HTTPRequest{URLs: []string{"https://example.com:" + port + "/"}, Pinned: pinnedLo("example.com")})
	ch := resp.Chains[0]
	if len(ch.Hops) != 2 || ch.Hops[0].Status != 301 || ch.Final().Status != 200 {
		t.Fatalf("chain %+v", ch)
	}
	f := ch.Final()
	if f.Server != "nginx" || f.Headers["Strict-Transport-Security"] == "" {
		t.Fatalf("headers %+v", f.Headers)
	}
	if f.TLS == nil || !f.TLS.ChainValid || !f.TLS.HostnameMatch || f.TLS.Version == "" {
		t.Fatalf("tls %+v", f.TLS)
	}
	if f.Timing.TotalMS <= 0 || f.Timing.TTFBms <= 0 {
		t.Fatalf("timing %+v", f.Timing)
	}
}

func TestHTTPLoopAndHostnameMismatch(t *testing.T) {
	p, port, _ := tlsSite(t, func(w http.ResponseWriter, r *http.Request) {
		next := "/a"
		if r.URL.Path == "/a" {
			next = "/b"
		} else if r.URL.Path == "/b" {
			next = "/a"
		}
		http.Redirect(w, r, next, http.StatusFound)
	})
	resp := p.Run(context.Background(), HTTPRequest{URLs: []string{"https://wrong.test:" + port + "/"}, Pinned: pinnedLo("wrong.test")})
	ch := resp.Chains[0]
	if !ch.Loop {
		t.Fatalf("loop not detected: %+v", ch)
	}
	if ch.Hops[0].TLS == nil || ch.Hops[0].TLS.HostnameMatch {
		t.Fatalf("hostname mismatch not detected: %+v", ch.Hops[0].TLS)
	}
}

func TestHTTPErrors(t *testing.T) {
	// Refused.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	p := &HTTPProber{AllowLoopback: true, Timeout: time.Second}
	h := p.Run(context.Background(), HTTPRequest{URLs: []string{"http://example.com:" + port + "/"}, Pinned: pinnedLo("example.com")}).Chains[0].Hops[0]
	if h.ErrorKind != "refused" {
		t.Fatalf("refused: %+v", h)
	}
	// Timeout: server accepts but never responds.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	p.Timeout = 300 * time.Millisecond
	h = p.Run(context.Background(), HTTPRequest{URLs: []string{"http://example.com:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port) + "/"}, Pinned: pinnedLo("example.com")}).Chains[0].Hops[0]
	if h.ErrorKind != "timeout" {
		t.Fatalf("timeout: %+v", h)
	}
	// Cloudflare 522 page.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "abc-FRA")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(522)
		w.Write([]byte("Connection timed out | Cloudflare Ray ID: abc"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	p.Timeout = 2 * time.Second
	h = p.Run(context.Background(), HTTPRequest{URLs: []string{"http://example.com:" + u.Port() + "/"}, Pinned: pinnedLo("example.com")}).Chains[0].Hops[0]
	if h.Status != 522 || h.CDN != "Cloudflare" || !h.CDNError {
		t.Fatalf("cdn: %+v", h)
	}
}

// TestHTTPSSRFGuards: production prober refuses private pinned IPs, private
// redirect targets, and non-standard ports.
func TestHTTPSSRFGuards(t *testing.T) {
	p := &HTTPProber{Timeout: time.Second}
	h := p.Run(context.Background(), HTTPRequest{URLs: []string{"http://example.com/"}, Pinned: pinnedLo("example.com")}).Chains[0].Hops[0]
	if h.ErrorKind != "blocked" {
		t.Fatalf("pinned loopback: %+v", h)
	}
	h = p.Run(context.Background(), HTTPRequest{URLs: []string{"http://169.254.169.254/latest/meta-data/"}}).Chains[0].Hops[0]
	if h.ErrorKind != "blocked" {
		t.Fatalf("metadata: %+v", h)
	}
	h = p.Run(context.Background(), HTTPRequest{URLs: []string{"http://example.com:22/"}}).Chains[0].Hops[0]
	if h.ErrorKind != "bad_url" {
		t.Fatalf("port: %+v", h)
	}
	h = p.Run(context.Background(), HTTPRequest{URLs: []string{"file:///etc/passwd"}}).Chains[0].Hops[0]
	if h.ErrorKind != "bad_url" {
		t.Fatalf("scheme: %+v", h)
	}
}

func TestLocalSkipsIPv6WithoutRoute(t *testing.T) {
	l := &Local{AllowLoopback: true, HasIPv6: func() bool { return false },
		PingFunc: func(context.Context, netip.Addr, int) (*PingResult, error) {
			return &PingResult{Sent: 1, Received: 1}, nil
		}}
	resp, err := l.Probe(context.Background(), ProbeRequest{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, Ports: []int{80}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Results[0].Skipped != "" || resp.Results[1].Skipped == "" || resp.Results[1].Ping != nil {
		t.Fatalf("%+v", resp.Results)
	}
}

func TestLocalValidates(t *testing.T) {
	l := &Local{PingFunc: func(context.Context, netip.Addr, int) (*PingResult, error) { return &PingResult{}, nil }}
	ctx := context.Background()
	if _, err := l.Probe(ctx, ProbeRequest{IPs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, Ports: []int{80}}); err == nil {
		t.Fatal("private IP accepted")
	}
	if _, err := l.Probe(ctx, ProbeRequest{IPs: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, Ports: []int{22}}); err == nil {
		t.Fatal("port 22 accepted")
	}
	if err := l.Traceroute(ctx, netip.MustParseAddr("169.254.169.254"), 30, func(string) {}); err == nil {
		t.Fatal("metadata traceroute accepted")
	}
	if _, err := l.HTTP(ctx, HTTPRequest{URLs: []string{"http://x.com/"}, Pinned: map[string][]netip.Addr{"x.com": {netip.MustParseAddr("127.0.0.1")}}}); err == nil {
		t.Fatal("pinned loopback accepted")
	}
}
