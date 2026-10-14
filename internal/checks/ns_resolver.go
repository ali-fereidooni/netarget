package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"domaindoctor/internal/dnsx"
)

// nameserversViaResolvers is the reduced name-server check used when this
// checker cannot send DNS on port 53 (DoH mode). The delegation is seen
// through public resolvers, so per-server tests (AA flag, lame delegation,
// glue, SOA serials) are impossible; what remains is still useful: whether
// the domain resolves at all, whether failures are DNSSEC-related, the NS
// set, NS addresses, count and network diversity.
func nameserversViaResolvers(ctx context.Context, st *State, c *dnsx.Client, asn ASNLookup) *Result {
	r := NewResult(LayerNameservers)
	det := &NSDetails{Servers: []NSServer{}}
	r.Details = det
	apex := dnsx.Canon(st.Apex)
	st.ViaResolvers = true
	r.Add("ns.limited_mode", Info,
		"This checker cannot query name servers directly (outbound port 53 is blocked), so DNS data comes from public resolvers over HTTPS. Lame-delegation, AA, glue and SOA-serial checks were not possible.",
		"DNS-over-HTTPS via "+resolverNames(c))

	// Ask each resolver normally, and with CD (checking disabled) to tell
	// DNSSEC failures apart from name servers that do not answer.
	type res struct {
		name     string
		rcode    int
		ns       []string
		cdRcode  int
		err, cde error
	}
	out := make([]res, len(c.Resolvers))
	var wg sync.WaitGroup
	for i, rv := range c.Resolvers {
		wg.Add(1)
		go func(i int, rv dnsx.Resolver) {
			defer wg.Done()
			o := &out[i]
			o.name, o.rcode, o.cdRcode = rv.Name, -1, -1
			if m, _, err := c.Query(ctx, rv.IP, apex, dns.TypeNS, true, false); err != nil {
				o.err = err
			} else {
				o.rcode = m.Rcode
				o.ns = nsFrom(m.Answer, apex)
			}
			if o.rcode == dns.RcodeServerFailure {
				if m, _, err := c.Query(ctx, rv.IP, apex, dns.TypeNS, true, true); err != nil {
					o.cde = err
				} else {
					o.cdRcode = m.Rcode
					if len(o.ns) == 0 {
						o.ns = nsFrom(m.Answer, apex)
					}
				}
			}
		}(i, rv)
	}
	wg.Wait()

	var answered, nx, servfail, cdOK int
	nsSet := map[string]bool{}
	var ev []string
	for _, o := range out {
		switch {
		case o.err != nil:
			ev = append(ev, o.name+": "+shortErr(o.err))
			continue
		case o.rcode == dns.RcodeNameError:
			nx++
		case o.rcode == dns.RcodeServerFailure:
			servfail++
			if o.cdRcode == dns.RcodeSuccess {
				cdOK++
			}
		}
		answered++
		ev = append(ev, fmt.Sprintf("%s: %s", o.name, dns.RcodeToString[o.rcode]))
		for _, n := range o.ns {
			nsSet[n] = true
		}
	}
	evidence := strings.Join(ev, "; ")

	switch {
	case answered == 0:
		r.Add("ns.parent_unreachable", Critical, "No public resolver could be reached over HTTPS, so the domain's DNS cannot be checked from here.", evidence)
		r.Blocking = true
		return r.Finish("Public resolvers unreachable")
	case nx == answered:
		r.Add("ns.no_delegation", Critical, "Public resolvers say the domain does not exist (NXDOMAIN): it is not delegated, not registered, or removed from its TLD zone.", evidence)
		r.Blocking = true
		return r.Finish("Domain does not resolve (NXDOMAIN)")
	case servfail == answered && cdOK > 0:
		// Data is reachable when validation is off: DNSSEC is the problem.
		// The zone layer validates the chain and reports dnssec.broken.
		r.Add("dns.resolver_servfail", Warning, "Validating resolvers return SERVFAIL, but the data is reachable with DNSSEC checking disabled: the DNSSEC chain is likely broken.", evidence)
	case servfail == answered:
		r.Add("ns.none_usable", Critical, "Public resolvers get no usable answer from the domain's name servers (SERVFAIL even without DNSSEC validation): the name servers are down, unreachable, or lame (do not serve the zone).", evidence)
		r.Blocking = true
		return r.Finish("Name servers do not answer (SERVFAIL)")
	case servfail > 0:
		r.Add("dns.resolver_servfail", Warning, "Some public resolvers return SERVFAIL while others answer: a name server may be lame or unreachable.", evidence)
	}

	names := keys(nsSet)
	if len(names) == 0 {
		r.Add("ns.no_delegation", Critical, "Public resolvers return no NS records for the domain.", evidence)
		r.Blocking = true
		return r.Finish("No name servers found")
	}
	if len(names) > maxNSNames {
		names = names[:maxNSNames]
	}
	det.ChildNS = names
	for _, name := range names {
		s := NSServer{Name: name, InBailiwick: dns.IsSubDomain(apex, name)}
		addrs, nxd, err := c.LookupAddrs(ctx, name)
		switch {
		case err != nil:
			r.Add("ns.no_address", Warning, fmt.Sprintf("%s could not be resolved right now.", name), shortErr(err))
		case len(addrs) == 0:
			e := "no A/AAAA records"
			if nxd {
				e = "NXDOMAIN"
			}
			r.Add("ns.no_address", Critical, fmt.Sprintf("Name server %s has no IP address.", name), e)
		}
		if len(addrs) > maxAddrsPerNS {
			addrs = addrs[:maxAddrsPerNS]
		}
		s.Addrs = addrs
		for _, ip := range addrs {
			p := NSProbe{IP: ip, Status: "not tested"}
			if asn != nil {
				p.ASN, p.ASName, _ = asn.LookupASN(ip)
			}
			s.Probes = append(s.Probes, p)
		}
		det.Servers = append(det.Servers, s)
	}
	if len(names) < 2 {
		r.Add("ns.too_few", Warning, fmt.Sprintf("Only %d name server is delegated; at least 2 on separate networks are recommended.", len(names)), strings.Join(names, ", "))
	}
	var all []NSProbe
	for _, s := range det.Servers {
		all = append(all, s.Probes...)
	}
	if e, single := singleNetwork(all); single && len(names) >= 2 {
		r.Add("ns.single_network", Warning, "All name servers are in the same network, so one outage takes the whole domain down.", e)
	}
	return r.Finish(fmt.Sprintf("%d name server(s) seen via public resolvers (direct checks unavailable)", len(names)))
}

func nsFrom(rrs []dns.RR, owner string) []string {
	var out []string
	for _, rr := range rrs {
		if ns, ok := rr.(*dns.NS); ok && dnsx.Canon(ns.Hdr.Name) == owner {
			out = append(out, dnsx.Canon(ns.Ns))
		}
	}
	sort.Strings(out)
	return out
}

func resolverNames(c *dnsx.Client) string {
	var n []string
	for _, r := range c.Resolvers {
		n = append(n, r.Name)
	}
	return strings.Join(n, ", ")
}
