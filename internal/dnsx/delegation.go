package dnsx

import (
	"context"
	"errors"
	"net/netip"
	"sort"

	"github.com/miekg/dns"
)

// Delegation is what the parent zone (e.g. the TLD) says about a domain.
type Delegation struct {
	Parent       string                  `json:"parent"`        // parent zone, e.g. "com."
	ParentServer string                  `json:"parent_server"` // IP that answered
	NS           []string                `json:"ns"`            // delegated NS names (fqdn, lowercase)
	Glue         map[string][]netip.Addr `json:"glue"`          // glue from the additional section
	NXDomain     bool                    `json:"nxdomain"`      // parent says the name does not exist
	NoDelegation bool                    `json:"no_delegation"` // name exists but has no NS cut
	CoHosted     bool                    `json:"co_hosted"`     // parent server is also authoritative for the child
}

var ErrParentUnreachable = errors.New("could not reach the parent zone's name servers")

// FindDelegation walks from the root down, following referrals without
// recursion, until a server returns the referral for apex itself. This
// returns the delegation as published by the parent, independent of any
// recursive resolver cache.
func (c *Client) FindDelegation(ctx context.Context, apex string) (*Delegation, error) {
	apex = Canon(apex)
	zone := "."
	servers := append([]netip.Addr{}, c.Roots...)
	for depth := 0; depth < 12; depth++ {
		var resp *dns.Msg
		var from netip.Addr
		for i, s := range servers {
			if i >= 4 { // try a few servers per zone, not all
				break
			}
			m, _, err := c.Query(ctx, s, apex, dns.TypeNS, false, false)
			if err != nil || m.Rcode == dns.RcodeServerFailure || m.Rcode == dns.RcodeRefused {
				continue
			}
			resp, from = m, s
			break
		}
		if resp == nil {
			return nil, ErrParentUnreachable
		}
		d := &Delegation{Parent: zone, ParentServer: from.String(), Glue: map[string][]netip.Addr{}}

		if resp.Rcode == dns.RcodeNameError {
			d.NXDomain = true
			return d, nil
		}
		// Parent is also authoritative for the child: NS comes back as an answer.
		if resp.Authoritative {
			if ns := nsNames(resp.Answer, apex); len(ns) > 0 {
				d.NS, d.CoHosted = ns, true
				fillGlue(d, resp.Extra)
				return d, nil
			}
		}
		owner, ns := referral(resp.Ns)
		switch {
		case len(ns) == 0:
			d.NoDelegation = true
			return d, nil
		case owner == apex:
			d.NS = ns
			fillGlue(d, resp.Extra)
			return d, nil
		case dns.IsSubDomain(owner, apex) && owner != zone && dns.IsSubDomain(zone, owner):
			// Referral to an intermediate zone: descend.
			next := glueFor(ns, resp.Extra)
			if len(next) == 0 {
				for _, n := range ns {
					addrs, _, err := c.LookupAddrs(ctx, n)
					if err == nil {
						next = append(next, addrs...)
					}
				}
			}
			if len(next) == 0 {
				return nil, ErrParentUnreachable
			}
			zone, servers = owner, next
		default:
			// Referral that does not move us closer (upward/sideways): treat
			// as no delegation rather than looping.
			d.NoDelegation = true
			return d, nil
		}
	}
	return nil, ErrParentUnreachable
}

func nsNames(rrs []dns.RR, owner string) []string {
	var out []string
	for _, rr := range rrs {
		if ns, ok := rr.(*dns.NS); ok && Canon(ns.Hdr.Name) == owner {
			out = append(out, Canon(ns.Ns))
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

func referral(auth []dns.RR) (string, []string) {
	var owner string
	for _, rr := range auth {
		if ns, ok := rr.(*dns.NS); ok {
			owner = Canon(ns.Hdr.Name)
			break
		}
	}
	if owner == "" {
		return "", nil
	}
	return owner, nsNames(auth, owner)
}

func fillGlue(d *Delegation, extra []dns.RR) {
	want := map[string]bool{}
	for _, n := range d.NS {
		want[n] = true
	}
	for _, rr := range extra {
		name := Canon(rr.Header().Name)
		if !want[name] {
			continue
		}
		d.Glue[name] = append(d.Glue[name], AddrsFrom([]dns.RR{rr})...)
	}
}

func glueFor(ns []string, extra []dns.RR) []netip.Addr {
	want := map[string]bool{}
	for _, n := range ns {
		want[n] = true
	}
	var out []netip.Addr
	for _, rr := range extra {
		if want[Canon(rr.Header().Name)] {
			out = append(out, AddrsFrom([]dns.RR{rr})...)
		}
	}
	// Prefer IPv4 first; many test/dev hosts lack IPv6.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Is4() && !out[j].Is4() })
	return out
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}
