package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"domaindoctor/internal/safenet"
)

// Local executes probes in-process. The agent server wraps it; single-node
// mode and the CLI use it directly. All inputs are re-validated here, so the
// agent enforces the SSRF policy itself instead of trusting the master.
type Local struct {
	HTTPProber    HTTPProber
	AllowLoopback bool        // tests only
	PortMap       map[int]int // tests/demo only (with AllowLoopback): logical -> real TCP port
	// PingFunc and TraceFunc can be replaced in tests.
	PingFunc  func(ctx context.Context, ip netip.Addr, count int) (*PingResult, error)
	HasIPv6   func() bool // defaults to HasIPv6
	TraceFunc func(ctx context.Context, ip netip.Addr, maxHops int, line func(string)) error
	sem       chan struct{}
	once      sync.Once
}

var ErrInvalidRequest = errors.New("invalid probe request")

// HasIPv6 reports whether this host has a route to the global IPv6
// Internet. A UDP "connect" sends no packets; it only consults the routing table.
func HasIPv6() bool {
	c, err := net.Dial("udp6", "[2001:4860:4860::8888]:53")
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (l *Local) acquire(ctx context.Context) (func(), error) {
	l.once.Do(func() { l.sem = make(chan struct{}, 16) })
	select {
	case l.sem <- struct{}{}:
		return func() { <-l.sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *Local) checkIPs(ips []netip.Addr) error {
	if len(ips) == 0 || len(ips) > 8 {
		return ErrInvalidRequest
	}
	if l.AllowLoopback {
		return nil
	}
	return safenet.CheckAddrs(ips)
}

func (l *Local) Health(context.Context) error { return nil }

func (l *Local) Probe(ctx context.Context, req ProbeRequest) (*ProbeResponse, error) {
	if err := l.checkIPs(req.IPs); err != nil {
		return nil, err
	}
	for _, p := range req.Ports {
		if !AllowedPorts[p] && !l.AllowLoopback {
			return nil, ErrInvalidRequest
		}
	}
	if len(req.Ports) > 4 {
		return nil, ErrInvalidRequest
	}
	rel, err := l.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer rel()
	ping := l.PingFunc
	if ping == nil {
		ping = Ping
	}
	out := &ProbeResponse{Results: make([]IPProbe, len(req.IPs))}
	hasV6 := l.HasIPv6
	if hasV6 == nil {
		hasV6 = HasIPv6
	}
	v6 := hasV6()
	var wg sync.WaitGroup
	for i, ip := range req.IPs {
		out.Results[i] = IPProbe{IP: ip, TCP: make([]TCPResult, len(req.Ports))}
		if ip.Is6() && !v6 {
			out.Results[i] = IPProbe{IP: ip, Skipped: "this node has no IPv6 connectivity", TCP: []TCPResult{}}
			continue
		}
		wg.Add(1)
		go func(r *IPProbe) {
			defer wg.Done()
			if pr, err := ping(ctx, r.IP, req.PingCount); err != nil {
				r.PingError = err.Error()
			} else {
				r.Ping = pr
			}
		}(&out.Results[i])
		for j, port := range req.Ports {
			wg.Add(1)
			go func(dst *TCPResult, ip netip.Addr, port int) {
				defer wg.Done()
				real := port
				if p, ok := l.PortMap[port]; ok && l.AllowLoopback {
					real = p
				}
				*dst = TCPConnect(ctx, ip, real, 4*time.Second, l.AllowLoopback)
				dst.Port = port
			}(&out.Results[i].TCP[j], ip, port)
		}
	}
	wg.Wait()
	return out, nil
}

// validSpec enforces the matrix policy: read-only methods, fixed UAs, known
// protocols, http(s) URLs, and a public origin IP (re-checked here, not
// trusted from the master).
func (l *Local) validSpec(s ReqSpec) error {
	if s.Method != http.MethodGet && s.Method != http.MethodHead {
		return ErrInvalidRequest
	}
	if _, ok := UserAgents[s.UA]; !ok && s.UA != "" {
		return ErrInvalidRequest
	}
	if s.Proto != "" && s.Proto != "auto" && s.Proto != "h1" && s.Proto != "h2" {
		return ErrInvalidRequest
	}
	u, err := url.Parse(s.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return ErrInvalidRequest
	}
	if s.OriginIP.IsValid() {
		return l.checkIPs([]netip.Addr{s.OriginIP})
	}
	return nil
}

func (l *Local) prober() HTTPProber {
	p := l.HTTPProber
	p.AllowLoopback = p.AllowLoopback || l.AllowLoopback
	if l.AllowLoopback && p.PortMap == nil && l.PortMap != nil {
		p.PortMap = map[string]string{}
		for k, v := range l.PortMap {
			p.PortMap[fmt.Sprint(k)] = fmt.Sprint(v)
		}
	}
	return p
}

func (l *Local) HTTP(ctx context.Context, req HTTPRequest) (*HTTPResponse, error) {
	if len(req.URLs) > 6 || len(req.Specs) > MaxSpecs || len(req.URLs)+len(req.Specs) == 0 {
		return nil, ErrInvalidRequest
	}
	for _, ips := range req.Pinned {
		if err := l.checkIPs(ips); err != nil {
			return nil, err
		}
	}
	for _, s := range req.Specs {
		if err := l.validSpec(s); err != nil {
			return nil, err
		}
	}
	// Server-side deadline, shorter than the master's client timeout, so a
	// slow site cannot make the whole call look like a dead agent.
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	rel, err := l.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer rel()
	p := l.prober()
	limit := req.MaxHops
	if limit <= 0 || limit > maxHops {
		limit = maxHops
	}
	// Run chains in parallel (bounded); each is independent.
	out := &HTTPResponse{Chains: make([]Chain, len(req.URLs)), Results: make([]SpecResult, len(req.Specs))}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, u := range req.URLs {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out.Chains[i] = p.chain(ctx, u, req.Pinned, limit, HopOpts{})
		}(i, u)
	}
	for i, s := range req.Specs {
		wg.Add(1)
		go func(i int, s ReqSpec) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			o := HopOpts{Method: s.Method, UA: s.UA, Proto: s.Proto, Compress: s.Compress, OriginIP: s.OriginIP, Sample: s.Sample, Site: siteOfURL(s.URL)}
			out.Results[i] = SpecResult{Spec: s, Chain: p.chain(ctx, s.URL, req.Pinned, limit, o)}
		}(i, s)
	}
	wg.Wait()
	enforceSampleBudget(out.Results, MaxSampleBudget)
	return out, nil
}

// enforceSampleBudget keeps body samples only on final hops and trims them
// so one call never returns more than budget bytes of page content.
func enforceSampleBudget(rs []SpecResult, budget int) {
	used := 0
	for i := range rs {
		hops := rs[i].Chain.Hops
		for j := range hops {
			if j < len(hops)-1 {
				hops[j].BodySample = ""
				continue
			}
			s := hops[j].BodySample
			if used+len(s) > budget {
				keep := budget - used
				if keep < 0 {
					keep = 0
				}
				s = strings.ToValidUTF8(s[:keep], "")
			}
			hops[j].BodySample = s
			used += len(s)
		}
	}
}

// Resources fetches a page and checks its subresources. Every subresource
// host is resolved through safenet by the prober (never via the master).
func (l *Local) Resources(ctx context.Context, req ResourceRequest) (*ResourceResponse, error) {
	u, err := url.Parse(req.PageURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || req.Max > MaxResources {
		return nil, ErrInvalidRequest
	}
	for _, ips := range req.Pinned {
		if err := l.checkIPs(ips); err != nil {
			return nil, err
		}
	}
	rel, err := l.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer rel()
	p := l.prober()
	return p.CheckResources(ctx, req), nil
}

func (l *Local) Traceroute(ctx context.Context, ip netip.Addr, maxHops int, line func(string)) error {
	if err := l.checkIPs([]netip.Addr{ip}); err != nil {
		return err
	}
	rel, err := l.acquire(ctx)
	if err != nil {
		return err
	}
	defer rel()
	tr := l.TraceFunc
	if tr == nil {
		tr = Traceroute
	}
	return tr(ctx, ip, maxHops, line)
}

func siteOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return siteOf(u.Hostname())
}
