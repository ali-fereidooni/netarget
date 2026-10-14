// Package dnstest runs in-process mock DNS servers for tests.
package dnstest

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Zone is a simple record store: answers are looked up by (name, type).
// Delegations make the server return a referral for names at or below the
// cut. Authoritative controls the AA bit; Rcode forces a response code.
type Zone struct {
	mu            sync.Mutex
	Origin        string
	Records       []dns.RR
	Delegations   map[string][]dns.RR // cut -> NS + glue RRs
	Authoritative bool
	Rcode         int  // if non-zero, every reply uses this rcode (e.g. REFUSED for lame)
	Drop          bool // never reply (timeout)
	Queries       int
}

// RR parses a record string or fails the test.
func RR(t testing.TB, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("bad RR %q: %v", s, err)
	}
	return rr
}

// RRs parses many records.
func RRs(t testing.TB, ss ...string) []dns.RR {
	out := make([]dns.RR, 0, len(ss))
	for _, s := range ss {
		out = append(out, RR(t, s))
	}
	return out
}

func (z *Zone) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	z.mu.Lock()
	z.Queries++
	drop := z.Drop
	z.mu.Unlock()
	if drop {
		return
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = z.Authoritative
	if z.Rcode != 0 {
		m.Rcode = z.Rcode
		m.Authoritative = false
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	qname := strings.ToLower(q.Name)

	// Referral for delegated names.
	for cut, rrs := range z.Delegations {
		cut = strings.ToLower(dns.Fqdn(cut))
		// The parent answers DS for the cut itself authoritatively.
		if q.Qtype == dns.TypeDS && qname == cut {
			continue
		}
		if dns.IsSubDomain(cut, qname) && !(z.Authoritative && cut == strings.ToLower(dns.Fqdn(z.Origin))) {
			m.Authoritative = false
			for _, rr := range rrs {
				if rr.Header().Rrtype == dns.TypeNS {
					m.Ns = append(m.Ns, rr)
				} else {
					m.Extra = append(m.Extra, rr)
				}
			}
			_ = w.WriteMsg(m)
			return
		}
	}

	nameExists := false
	for _, rr := range z.Records {
		h := rr.Header()
		if strings.ToLower(h.Name) != qname {
			continue
		}
		nameExists = true
		if h.Rrtype == q.Qtype || q.Qtype == dns.TypeANY {
			m.Answer = append(m.Answer, rr)
		} else if h.Rrtype == dns.TypeCNAME && q.Qtype != dns.TypeCNAME {
			m.Answer = append(m.Answer, rr)
		} else if h.Rrtype == dns.TypeRRSIG && req.IsEdns0() != nil && req.IsEdns0().Do() {
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == q.Qtype {
				m.Answer = append(m.Answer, rr)
			}
		}
	}
	// Chase CNAMEs within this server's data, as real servers do.
	for hops := 0; hops < 8 && q.Qtype != dns.TypeCNAME && len(m.Answer) > 0; hops++ {
		last, ok := m.Answer[len(m.Answer)-1].(*dns.CNAME)
		if !ok {
			break
		}
		target := strings.ToLower(last.Target)
		added := false
		for _, rr := range z.Records {
			h := rr.Header()
			if strings.ToLower(h.Name) == target && (h.Rrtype == q.Qtype || h.Rrtype == dns.TypeCNAME) {
				m.Answer = append(m.Answer, rr)
				added = true
			}
		}
		if !added {
			break
		}
	}
	if !nameExists && z.Origin != "" && dns.IsSubDomain(dns.Fqdn(z.Origin), qname) {
		// Empty non-terminal check: any record below qname?
		for _, rr := range z.Records {
			if dns.IsSubDomain(qname, strings.ToLower(rr.Header().Name)) {
				nameExists = true
				break
			}
		}
		if !nameExists {
			m.Rcode = dns.RcodeNameError
		}
	}
	if len(m.Answer) == 0 {
		for _, rr := range z.Records {
			if rr.Header().Rrtype == dns.TypeSOA {
				m.Ns = append(m.Ns, rr)
				break
			}
		}
	}
	_ = w.WriteMsg(m)
}

// Multi serves several zones from one server, dispatching on the longest
// matching origin; names outside every zone get REFUSED.
type Multi map[string]*Zone

func (mz Multi) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	q := strings.ToLower(req.Question[0].Name)
	var best *Zone
	bestLen := -1
	for origin, z := range mz {
		o := strings.ToLower(dns.Fqdn(origin))
		if dns.IsSubDomain(o, q) && len(o) > bestLen {
			best, bestLen = z, len(o)
		}
	}
	if best == nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}
	best.ServeDNS(w, req)
}

// Start serves z on 127.0.0.1 (UDP+TCP on the same port) and returns host:port.
func Start(t testing.TB, z dns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// Port taken for TCP; UDP-only is fine for most tests.
		ln = nil
	}
	udp := &dns.Server{PacketConn: pc, Handler: z}
	started := make(chan struct{})
	udp.NotifyStartedFunc = func() { close(started) }
	go func() { _ = udp.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = udp.Shutdown() })
	if ln != nil {
		tcp := &dns.Server{Listener: ln, Handler: z}
		go func() { _ = tcp.ActivateAndServe() }()
		t.Cleanup(func() { _ = tcp.Shutdown() })
	}
	return addr
}

// Net maps logical public IPs to mock server addresses.
type Net struct {
	t   testing.TB
	Map map[netip.Addr]string
}

func NewNet(t testing.TB) *Net { return &Net{t: t, Map: map[netip.Addr]string{}} }

// Add starts z and registers it under the logical IP ip.
func (n *Net) Add(ip string, z *Zone) *Zone {
	n.Map[netip.MustParseAddr(ip)] = Start(n.t, z)
	return z
}

// AddHandler starts any handler (e.g. Multi) under the logical IP ip.
func (n *Net) AddHandler(ip string, h dns.Handler) {
	n.Map[netip.MustParseAddr(ip)] = Start(n.t, h)
}

// DoH serves h as an RFC 8484 endpoint (HTTPS POST application/dns-message)
// by forwarding to a mock UDP server. Use srv.Client() as the HTTP client.
func DoH(t testing.TB, h dns.Handler) *httptest.Server {
	t.Helper()
	addr := Start(t, h)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if r.Method != http.MethodPost || q.Unpack(b) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp, err := dns.Exchange(q, addr)
		if err != nil {
			http.Error(w, "upstream", http.StatusBadGateway)
			return
		}
		out, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ShortTimeout is a convenient timeout for tests that exercise unreachable servers.
const ShortTimeout = 300 * time.Millisecond
