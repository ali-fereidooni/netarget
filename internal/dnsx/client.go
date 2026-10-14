// Package dnsx wraps miekg/dns for direct, non-recursive queries to
// specific servers (root, TLD, authoritative) and for recursive lookups
// against a fixed list of public resolvers.
package dnsx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"domaindoctor/internal/safenet"
)

// Public resolvers used for recursive lookups and propagation comparison.
var DefaultResolvers = []Resolver{
	{Name: "Cloudflare", IP: netip.MustParseAddr("1.1.1.1"), DoH: "https://1.1.1.1/dns-query"},
	{Name: "Google", IP: netip.MustParseAddr("8.8.8.8"), DoH: "https://8.8.8.8/dns-query"},
	{Name: "Quad9", IP: netip.MustParseAddr("9.9.9.9"), DoH: "https://9.9.9.9/dns-query"},
}

// Root server IPv4 addresses (a–m.root-servers.net).
var DefaultRoots = mustAddrs(
	"198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10",
	"192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
	"193.0.14.129", "199.7.83.42", "202.12.27.33",
)

func mustAddrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

type Resolver struct {
	Name string     `json:"name"`
	IP   netip.Addr `json:"ip"`
	DoH  string     `json:"-"` // RFC 8484 endpoint, used in DoH mode
}

// Client issues DNS queries. The zero value is not usable; use New.
type Client struct {
	Timeout   time.Duration
	Port      string
	Resolvers []Resolver
	Roots     []netip.Addr

	// DoH switches to resolver-only mode for networks that block port 53:
	// queries to a configured resolver go over HTTPS (RFC 8484) and direct
	// queries to any other server fail with ErrDirectUnavailable.
	DoH     bool
	DoHHTTP *http.Client // nil = default safe client

	// Test hooks. AllowPrivate disables the safenet guard; AddrOverride maps
	// a logical server IP to the real host:port of a mock server.
	AllowPrivate bool
	AddrOverride map[netip.Addr]string
}

func New() *Client {
	return &Client{Timeout: 3 * time.Second, Port: "53", Resolvers: DefaultResolvers, Roots: DefaultRoots}
}

var ErrBlockedServer = errors.New("refusing to query a non-public DNS server address")

func (c *Client) addr(ip netip.Addr) (string, error) {
	if a, ok := c.AddrOverride[ip]; ok {
		return a, nil
	}
	if !c.AllowPrivate && safenet.IsBlocked(ip) {
		return "", ErrBlockedServer
	}
	return net.JoinHostPort(ip.String(), c.Port), nil
}

func (c *Client) dialer() *net.Dialer {
	if c.AllowPrivate {
		return &net.Dialer{Timeout: c.Timeout}
	}
	return safenet.Dialer(c.Timeout)
}

// ErrDirectUnavailable: in DoH mode only the public resolvers can be queried.
var ErrDirectUnavailable = errors.New("direct DNS queries are unavailable from this network (DNS-over-HTTPS mode)")

// Exchange sends m to server over UDP, retrying over TCP when truncated.
// In DoH mode it goes over HTTPS to the matching resolver.
func (c *Client) Exchange(ctx context.Context, m *dns.Msg, server netip.Addr) (*dns.Msg, time.Duration, error) {
	if c.DoH {
		for _, r := range c.Resolvers {
			if r.IP == server && r.DoH != "" {
				return c.exchangeDoH(ctx, m, r.DoH)
			}
		}
		return nil, 0, ErrDirectUnavailable
	}
	addr, err := c.addr(server)
	if err != nil {
		return nil, 0, err
	}
	uc := &dns.Client{Net: "udp", Timeout: c.Timeout, Dialer: c.dialer(), UDPSize: 1232}
	r, rtt, err := uc.ExchangeContext(ctx, m, addr)
	if err == nil && r.Truncated {
		tc := &dns.Client{Net: "tcp", Timeout: c.Timeout, Dialer: c.dialer()}
		r, rtt, err = tc.ExchangeContext(ctx, m, addr)
	}
	if r != nil {
		r.Answer, r.Ns, r.Extra = capRRs(r.Answer), capRRs(r.Ns), capRRs(r.Extra)
	}
	return r, rtt, err
}

// MaxRRsPerSection bounds how many records from one response are used, so
// a hostile zone cannot inflate memory, reports, or crypto work.
const MaxRRsPerSection = 32

func capRRs(rrs []dns.RR) []dns.RR {
	if len(rrs) > MaxRRsPerSection {
		return rrs[:MaxRRsPerSection]
	}
	return rrs
}

// Query builds and sends a single question.
func (c *Client) Query(ctx context.Context, server netip.Addr, name string, qtype uint16, recursive, dnssec bool) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = recursive
	m.SetEdns0(1232, dnssec)
	if dnssec {
		m.CheckingDisabled = true
	}
	return c.Exchange(ctx, m, server)
}

// Recurse asks the configured public resolvers in order and returns the
// first answer with a usable rcode.
func (c *Client) Recurse(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	var lastErr error = errors.New("no resolvers configured")
	for _, r := range c.Resolvers {
		m, _, err := c.Query(ctx, r.IP, name, qtype, true, false)
		if err != nil {
			lastErr = err
			continue
		}
		if m.Rcode == dns.RcodeServerFailure || m.Rcode == dns.RcodeRefused {
			lastErr = fmt.Errorf("%s from %s", dns.RcodeToString[m.Rcode], r.Name)
			continue
		}
		return m, nil
	}
	return nil, lastErr
}

// LookupAddrs resolves name to A and AAAA via the recursive resolvers.
// NXDOMAIN is reported via the bool.
func (c *Client) LookupAddrs(ctx context.Context, name string) (addrs []netip.Addr, nxdomain bool, err error) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var errs []error
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		wg.Add(1)
		go func(qt uint16) {
			defer wg.Done()
			m, e := c.Recurse(ctx, name, qt)
			mu.Lock()
			defer mu.Unlock()
			if e != nil {
				errs = append(errs, e)
				return
			}
			if m.Rcode == dns.RcodeNameError {
				nxdomain = true
			}
			addrs = append(addrs, AddrsFrom(m.Answer)...)
		}(qt)
	}
	wg.Wait()
	sortAddrs(addrs)
	if len(errs) == 2 {
		return nil, false, errs[0]
	}
	return addrs, nxdomain && len(addrs) == 0, nil
}

// AddrsFrom extracts A/AAAA addresses from records.
func AddrsFrom(rrs []dns.RR) []netip.Addr {
	var out []netip.Addr
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
				out = append(out, a)
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(v.AAAA); ok {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}

func sortAddrs(a []netip.Addr) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j].Less(a[j-1]); j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// Canon lowercases and fully-qualifies a name.
func Canon(name string) string { return strings.ToLower(dns.Fqdn(name)) }

// Rcode returns the textual rcode.
func Rcode(m *dns.Msg) string {
	if m == nil {
		return ""
	}
	return dns.RcodeToString[m.Rcode]
}
