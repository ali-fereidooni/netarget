package checks

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"domaindoctor/internal/dnsx"
	"domaindoctor/internal/safenet"
)

// Work limits for attacker-controlled delegations.
const (
	maxNSNames    = 13
	maxAddrsPerNS = 4
	maxNSAddrs    = 32
)

// ASNLookup is optional (nil when no GeoIP/ASN dataset is loaded).
type ASNLookup interface {
	LookupASN(ip netip.Addr) (asn, name string, ok bool)
}

// NSProbe is the result of querying one name server address directly.
type NSProbe struct {
	IP     netip.Addr `json:"ip"`
	Status string     `json:"status"` // ok, lame, unreachable, private
	Rcode  string     `json:"rcode,omitempty"`
	AA     bool       `json:"aa"`
	RTTms  float64    `json:"rtt_ms,omitempty"`
	Serial uint32     `json:"serial,omitempty"`
	NS     []string   `json:"ns,omitempty"`
	ASN    string     `json:"asn,omitempty"`
	ASName string     `json:"as_name,omitempty"`
	Error  string     `json:"error,omitempty"`
}

type NSServer struct {
	Name        string       `json:"name"`
	InBailiwick bool         `json:"in_bailiwick"`
	Glue        []netip.Addr `json:"glue,omitempty"`
	Addrs       []netip.Addr `json:"addrs"`
	Probes      []NSProbe    `json:"probes"`
}

type NSDetails struct {
	Delegation *dnsx.Delegation `json:"delegation,omitempty"`
	Servers    []NSServer       `json:"servers"`
	ChildNS    []string         `json:"child_ns,omitempty"`
}

// Nameservers checks the delegation published by the parent zone and
// queries every name server address directly.
func Nameservers(ctx context.Context, st *State, c *dnsx.Client, asn ASNLookup) *Result {
	r := NewResult(LayerNameservers)
	det := &NSDetails{Servers: []NSServer{}}
	r.Details = det
	apex := dnsx.Canon(st.Apex)

	if c.DoH {
		return nameserversViaResolvers(ctx, st, c, asn)
	}
	deleg, err := c.FindDelegation(ctx, apex)
	if err != nil && !checkerCanQuery(ctx, c) {
		// Not the domain's fault: this server cannot send DNS queries at all.
		r.Add("ns.checker_dns_blocked", Critical,
			"The checking server cannot send DNS queries to the Internet (outbound port 53 is blocked or filtered), so the DNS layers cannot be tested from here.",
			"no answer from the root name servers")
		r.Blocking = true
		return r.Finish("This checker's network blocks outbound DNS")
	}
	if err != nil {
		r.Add("ns.parent_unreachable", Critical,
			"The parent zone (TLD) name servers could not be queried, so the delegation is unknown.", shortErr(err))
		r.Blocking = true
		return r.Finish("Could not read the delegation from the TLD")
	}
	det.Delegation = deleg
	st.ParentServer, _ = netip.ParseAddr(deleg.ParentServer)
	if deleg.NXDomain || deleg.NoDelegation {
		ev := fmt.Sprintf("%s servers (%s) answered %s for %s",
			deleg.Parent, deleg.ParentServer, map[bool]string{true: "NXDOMAIN", false: "with no NS records"}[deleg.NXDomain], apex)
		r.Add("ns.no_delegation", Critical,
			"The TLD has no name servers on record for this domain, so nothing under it can resolve.", ev)
		r.Blocking = true
		return r.Finish("Domain is not delegated by its TLD")
	}

	// Build server list and resolve NS addresses.
	total := 0
	nsNames := deleg.NS
	if len(nsNames) > maxNSNames {
		r.Add("ns.too_many", Warning, fmt.Sprintf("%d name servers are delegated; only the first %d were checked.", len(nsNames), maxNSNames), "")
		nsNames = nsNames[:maxNSNames]
	}
	for _, name := range nsNames {
		s := NSServer{Name: name, InBailiwick: dns.IsSubDomain(apex, name), Glue: deleg.Glue[name]}
		if len(s.Glue) > 0 {
			s.Addrs = append(s.Addrs, s.Glue...)
		} else {
			if s.InBailiwick {
				r.Add("ns.missing_glue", Critical,
					fmt.Sprintf("%s is inside the domain but the TLD has no glue (IP) for it, so resolvers cannot find it.", name),
					"no A/AAAA in the parent's additional section")
			}
			addrs, nx, err := c.LookupAddrs(ctx, name)
			switch {
			case err != nil:
				r.Add("ns.no_address", Critical, fmt.Sprintf("%s could not be resolved to an IP address.", name), shortErr(err))
			case len(addrs) == 0:
				ev := "no A/AAAA records"
				if nx {
					ev = "NXDOMAIN"
				}
				r.Add("ns.no_address", Critical, fmt.Sprintf("Name server %s has no IP address.", name), ev)
			}
			s.Addrs = addrs
		}
		// Bound the work an attacker-controlled delegation can cause:
		// at most maxAddrsPerNS per name and maxNSAddrs overall.
		if len(s.Addrs) > maxAddrsPerNS {
			s.Addrs = s.Addrs[:maxAddrsPerNS]
		}
		if total+len(s.Addrs) > maxNSAddrs {
			s.Addrs = s.Addrs[:max(0, maxNSAddrs-total)]
		}
		total += len(s.Addrs)
		det.Servers = append(det.Servers, s)
	}

	// Probe addresses in parallel with bounded concurrency.
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i := range det.Servers {
		s := &det.Servers[i]
		s.Probes = make([]NSProbe, len(s.Addrs))
		for j, ip := range s.Addrs {
			wg.Add(1)
			go func(p *NSProbe, ip netip.Addr) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				*p = probeNS(ctx, c, apex, ip)
				if asn != nil {
					p.ASN, p.ASName, _ = asn.LookupASN(ip)
				}
			}(&s.Probes[j], ip)
		}
	}
	wg.Wait()

	// Evaluate.
	var usable []AuthServer
	var usableProbes []NSProbe
	brokenCodes := []int{}
	for _, s := range det.Servers {
		okCount, lame, unreach := 0, 0, 0
		for _, p := range s.Probes {
			switch p.Status {
			case "ok":
				okCount++
				usable = append(usable, AuthServer{Name: s.Name, IP: p.IP})
				usableProbes = append(usableProbes, p)
			case "lame":
				lame++
			case "unreachable":
				unreach++
			case "private":
				r.Add("ns.private_ip", Critical, fmt.Sprintf("%s resolves to a non-public address %s.", s.Name, p.IP), "")
			}
		}
		if len(s.Probes) == 0 {
			continue
		}
		if lame > 0 {
			ev := []string{}
			for _, p := range s.Probes {
				if p.Status == "lame" {
					ev = append(ev, fmt.Sprintf("%s: rcode=%s aa=%v", p.IP, p.Rcode, p.AA))
				}
			}
			r.Add("ns.lame", Warning, fmt.Sprintf("%s is listed as a name server but is not authoritative for the domain (lame delegation).", s.Name), strings.Join(ev, "; "))
			brokenCodes = append(brokenCodes, len(r.Findings)-1)
		}
		if unreach > 0 {
			sev := Warning
			msg := fmt.Sprintf("%s does not answer DNS queries on some addresses.", s.Name)
			if okCount == 0 && lame == 0 {
				msg = fmt.Sprintf("%s does not answer DNS queries (timeout).", s.Name)
			}
			ev := []string{}
			for _, p := range s.Probes {
				if p.Status == "unreachable" {
					ev = append(ev, fmt.Sprintf("%s: %s", p.IP, p.Error))
				}
			}
			r.Add("ns.unreachable", sev, msg, strings.Join(ev, "; "))
			brokenCodes = append(brokenCodes, len(r.Findings)-1)
		}
	}
	if len(usable) == 0 {
		for _, i := range brokenCodes {
			r.Findings[i].Severity = Critical
		}
		r.Add("ns.none_usable", Critical, "None of the delegated name servers answers authoritatively for the domain, so it cannot resolve anywhere.", "")
		r.Blocking = true
	}

	if len(deleg.NS) < 2 {
		r.Add("ns.too_few", Warning, fmt.Sprintf("Only %d name server is delegated; at least 2 on separate networks are recommended.", len(deleg.NS)), strings.Join(deleg.NS, ", "))
	}

	// Parent/child NS consistency.
	if len(usableProbes) > 0 {
		child := map[string]bool{}
		for _, p := range usableProbes {
			for _, n := range p.NS {
				child[n] = true
			}
		}
		det.ChildNS = keys(child)
		if !sameSet(deleg.NS, det.ChildNS) && len(det.ChildNS) > 0 {
			r.Add("ns.parent_child_mismatch", Warning,
				"The name servers listed at the registrar (parent) differ from the NS records inside the zone (child).",
				fmt.Sprintf("parent: %s | child: %s", strings.Join(deleg.NS, ", "), strings.Join(det.ChildNS, ", ")))
		}
		serials := map[uint32][]string{}
		for _, p := range usableProbes {
			serials[p.Serial] = append(serials[p.Serial], p.IP.String())
		}
		if len(serials) > 1 {
			ev := []string{}
			for s, ips := range serials {
				ev = append(ev, fmt.Sprintf("%d on %s", s, strings.Join(ips, ",")))
			}
			sort.Strings(ev)
			r.Add("ns.serial_mismatch", Warning,
				"Name servers return different SOA serials: some servers have an outdated copy of the zone.", strings.Join(ev, "; "))
		}
	}

	// Network diversity.
	var all []NSProbe
	for _, s := range det.Servers {
		all = append(all, s.Probes...)
	}
	if ev, single := singleNetwork(all); single && len(deleg.NS) >= 2 {
		r.Add("ns.single_network", Warning, "All name servers are in the same network, so one outage takes the whole domain down.", ev)
	}

	// Glue consistency for in-bailiwick servers.
	if len(usable) > 0 {
		for _, s := range det.Servers {
			if !s.InBailiwick || len(s.Glue) == 0 {
				continue
			}
			auth := authAddrs(ctx, c, usable[0].IP, s.Name)
			if len(auth) > 0 && !sameAddrSet(auth, s.Glue) {
				r.Add("ns.glue_mismatch", Warning, fmt.Sprintf("The glue IPs for %s at the TLD differ from its A/AAAA records in the zone.", s.Name),
					fmt.Sprintf("glue: %v | zone: %v", s.Glue, auth))
			}
		}
	}

	seen := map[netip.Addr]bool{}
	for _, u := range usable {
		if !seen[u.IP] {
			seen[u.IP] = true
			st.AuthServers = append(st.AuthServers, u)
		}
	}

	summary := fmt.Sprintf("%d name server(s) delegated by %s, %d of %d addresses answer authoritatively",
		len(deleg.NS), strings.TrimSuffix(deleg.Parent, "."), len(usable), len(all))
	return r.Finish(summary)
}

// checkerCanQuery reports whether any root server answers a trivial query,
// distinguishing "this network blocks DNS" from "the TLD is unreachable".
func checkerCanQuery(ctx context.Context, c *dnsx.Client) bool {
	for i, root := range c.Roots {
		if i >= 3 {
			break
		}
		if _, _, err := c.Query(ctx, root, ".", dns.TypeSOA, false, false); err == nil {
			return true
		}
	}
	return false
}

func probeNS(ctx context.Context, c *dnsx.Client, apex string, ip netip.Addr) NSProbe {
	p := NSProbe{IP: ip}
	if !c.AllowPrivate && safenet.IsBlocked(ip) {
		p.Status = "private"
		return p
	}
	m, rtt, err := c.Query(ctx, ip, apex, dns.TypeSOA, false, false)
	if err != nil {
		p.Status, p.Error = "unreachable", shortErr(err)
		return p
	}
	p.RTTms = float64(rtt.Microseconds()) / 1000
	p.Rcode, p.AA = dnsx.Rcode(m), m.Authoritative
	var soa *dns.SOA
	for _, rr := range m.Answer {
		if s, ok := rr.(*dns.SOA); ok && dnsx.Canon(s.Hdr.Name) == apex {
			soa = s
		}
	}
	if m.Rcode != dns.RcodeSuccess || !m.Authoritative || soa == nil {
		p.Status = "lame"
		return p
	}
	p.Serial = soa.Serial
	if nm, _, err := c.Query(ctx, ip, apex, dns.TypeNS, false, false); err == nil {
		for _, rr := range nm.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				p.NS = append(p.NS, dnsx.Canon(ns.Ns))
			}
		}
		sort.Strings(p.NS)
	}
	p.Status = "ok"
	return p
}

func authAddrs(ctx context.Context, c *dnsx.Client, server netip.Addr, name string) []netip.Addr {
	var out []netip.Addr
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if m, _, err := c.Query(ctx, server, name, qt, false, false); err == nil {
			out = append(out, dnsx.AddrsFrom(m.Answer)...)
		}
	}
	return out
}

// singleNetwork reports whether all probed addresses share one ASN (when
// known) or one /24 (IPv4) / /48 (IPv6).
func singleNetwork(ps []NSProbe) (string, bool) {
	if len(ps) < 2 {
		return "", false
	}
	asns := map[string]bool{}
	nets := map[netip.Prefix]bool{}
	allASN := true
	for _, p := range ps {
		if p.ASN == "" {
			allASN = false
		}
		asns[p.ASN] = true
		bits := 24
		if p.IP.Is6() {
			bits = 48
		}
		pf, _ := p.IP.Prefix(bits)
		nets[pf] = true
	}
	if allASN && len(asns) == 1 {
		return "all addresses in " + ps[0].ASN + " " + ps[0].ASName, true
	}
	if len(nets) == 1 {
		for n := range nets {
			return "all addresses in " + n.String(), true
		}
	}
	return "", false
}

func shortErr(err error) string {
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	// Map to a fixed vocabulary: raw Go network errors embed local
	// addresses ("read udp 172.18.0.3:41234->…") that must not reach users.
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "refused"):
		return "connection refused"
	case strings.Contains(s, "reset") || strings.Contains(s, "forcibly closed"):
		return "connection reset"
	case strings.Contains(s, "timeout") || strings.Contains(s, "timed out"):
		return "timeout"
	case strings.Contains(s, "unreachable") || strings.Contains(s, "no route"):
		return "network unreachable"
	case strings.Contains(s, "non-public") || strings.Contains(s, "private"):
		return "non-public address refused"
	case strings.HasPrefix(s, "servfail") || strings.HasPrefix(s, "refused") || strings.HasPrefix(s, "http "):
		return err.Error() // our own rcode/status messages
	case strings.Contains(s, "could not reach the parent"):
		return err.Error()
	}
	return "lookup failed"
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[strings.ToLower(x)] = true
	}
	for _, x := range b {
		if !m[strings.ToLower(x)] {
			return false
		}
	}
	return true
}

func sameAddrSet(a, b []netip.Addr) bool {
	m := map[netip.Addr]bool{}
	for _, x := range a {
		m[x] = true
	}
	n := map[netip.Addr]bool{}
	for _, x := range b {
		n[x] = true
	}
	if len(m) != len(n) {
		return false
	}
	for k := range n {
		if !m[k] {
			return false
		}
	}
	return true
}
