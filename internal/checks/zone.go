package checks

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"domaindoctor/internal/dnsx"
	"domaindoctor/internal/safenet"
)

// CommonSRV are probed SRV owners (relative to the apex).
var CommonSRV = []string{
	"_autodiscover._tcp", "_sip._tls", "_sipfederationtls._tcp", "_xmpp-client._tcp",
	"_xmpp-server._tcp", "_imaps._tcp", "_submission._tcp", "_caldavs._tcp",
}

// maxRecordRows bounds the records table of one report.
const maxRecordRows = 200

type RecordRow struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}

// PropagationGroup shows how many resolvers returned each value.
type PropagationGroup struct {
	Type          string            `json:"type"`
	Name          string            `json:"name"`
	Authoritative []string          `json:"authoritative"`
	Values        []PropagationVal  `json:"values"`
	Errors        map[string]string `json:"errors,omitempty"`
	Consistent    bool              `json:"consistent"`
}

type PropagationVal struct {
	Value     string   `json:"value"`
	Count     int      `json:"count"`
	Resolvers []string `json:"resolvers"`
}

type ZoneDetails struct {
	Server      string             `json:"queried_server"`
	Records     []RecordRow        `json:"records"`
	Email       *EmailDetails      `json:"email,omitempty"`
	DNSSEC      *DNSSECDetails     `json:"dnssec,omitempty"`
	Propagation []PropagationGroup `json:"propagation,omitempty"`
}

// authQuerier queries the authoritative servers, falling back across them.
// In resolver mode (DoH) the "servers" are public resolvers, queried with
// RD and CD set so a broken DNSSEC chain still shows the zone's data.
type authQuerier struct {
	c         *dnsx.Client
	servers   []AuthServer
	recursive bool
}

func (a *authQuerier) query(ctx context.Context, name string, qt uint16, dnssec bool) (*dns.Msg, error) {
	var lastErr error = errors.New("no authoritative servers")
	for _, s := range a.servers {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(name), qt)
		q.RecursionDesired = a.recursive
		q.SetEdns0(1232, dnssec)
		q.CheckingDisabled = dnssec || a.recursive
		m, _, err := a.c.Exchange(ctx, q, s.IP)
		if err == nil && (m.Rcode == dns.RcodeSuccess || m.Rcode == dns.RcodeNameError) {
			return m, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("%s", dnsx.Rcode(m))
		}
	}
	return nil, lastErr
}

func (a *authQuerier) txt(ctx context.Context, name string) ([]string, error) {
	m, err := a.query(ctx, name, dns.TypeTXT, false)
	if err != nil {
		return nil, err
	}
	return txtStrings(m.Answer), nil
}

// Zone queries the authoritative servers for the domain's records.
func Zone(ctx context.Context, st *State, c *dnsx.Client, now time.Time) *Result {
	r := NewResult(LayerZone)
	servers, recursive := st.AuthServers, false
	if st.ViaResolvers {
		servers, recursive = nil, true
		for _, rv := range c.Resolvers {
			servers = append(servers, AuthServer{Name: rv.Name, IP: rv.IP})
		}
	}
	if len(servers) == 0 {
		return Skipped(LayerZone, "no authoritative name server answered")
	}
	det := &ZoneDetails{Server: servers[0].Name + " (" + servers[0].IP.String() + ")", Records: []RecordRow{}}
	if recursive {
		det.Server = "public resolvers over HTTPS (TTLs are cache-remaining; direct queries unavailable)"
	}
	r.Details = det
	auth := &authQuerier{c: c, servers: servers, recursive: recursive}
	apex := dnsx.Canon(st.Apex)
	www := "www." + apex

	type q struct {
		name string
		qt   uint16
	}
	qs := []q{}
	for _, t := range []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeTXT, dns.TypeCAA} {
		qs = append(qs, q{apex, t})
	}
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
		qs = append(qs, q{www, t})
	}
	sub := dnsx.Canon(st.Domain)
	if sub != apex {
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
			qs = append(qs, q{sub, t})
		}
	}
	for _, s := range CommonSRV {
		qs = append(qs, q{s + "." + apex, dns.TypeSRV})
	}

	answers := make([]*dns.Msg, len(qs))
	var wg sync.WaitGroup
	for i, qq := range qs {
		wg.Add(1)
		go func(i int, qq q) {
			defer wg.Done()
			answers[i], _ = auth.query(ctx, qq.name, qq.qt, false)
		}(i, qq)
	}
	wg.Wait()

	get := func(name string, qt uint16) []dns.RR {
		for i, qq := range qs {
			if qq.name == name && qq.qt == qt && answers[i] != nil {
				var out []dns.RR
				for _, rr := range answers[i].Answer {
					if rr.Header().Rrtype == qt && dnsx.Canon(rr.Header().Name) == name {
						out = append(out, rr)
					}
				}
				return out
			}
		}
		return nil
	}
	nx := func(name string) bool {
		for i, qq := range qs {
			if qq.name == name && answers[i] != nil && answers[i].Rcode == dns.RcodeNameError {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	for i := range qs {
		if answers[i] == nil {
			continue
		}
		for _, rr := range answers[i].Answer {
			h := rr.Header()
			row := RecordRow{Name: strings.TrimSuffix(h.Name, "."), Type: dns.TypeToString[h.Rrtype], TTL: h.Ttl, Value: rrValue(rr)}
			k := row.Name + "|" + row.Type + "|" + row.Value
			if !seen[k] && len(det.Records) < maxRecordRows {
				seen[k] = true
				det.Records = append(det.Records, row)
			}
		}
	}
	sort.SliceStable(det.Records, func(i, j int) bool {
		if det.Records[i].Name != det.Records[j].Name {
			return len(det.Records[i].Name) < len(det.Records[j].Name) || (len(det.Records[i].Name) == len(det.Records[j].Name) && det.Records[i].Name < det.Records[j].Name)
		}
		return det.Records[i].Type < det.Records[j].Type
	})

	// CNAME at apex.
	if cn := get(apex, dns.TypeCNAME); len(cn) > 0 {
		r.Add("dns.cname_at_apex", Critical, "There is a CNAME at the zone apex; this conflicts with SOA/NS and breaks resolution in many resolvers.", rrValue(cn[0]))
	}

	// Addresses for apex, www, and the requested subdomain, following CNAMEs.
	resolveName := func(name string) (v4, v6 []netip.Addr, exists bool) {
		addrs := dnsx.AddrsFrom(append(get(name, dns.TypeA), get(name, dns.TypeAAAA)...))
		if cn := get(name, dns.TypeCNAME); len(cn) > 0 {
			target := cn[0].(*dns.CNAME).Target
			exists = true
			st.CNAMEs = append(st.CNAMEs, dnsx.Canon(target))
			taddrs, tnx, err := c.LookupAddrs(ctx, target)
			switch {
			case err != nil:
				r.Add("dns.cname_unresolved", Warning, fmt.Sprintf("%s is a CNAME to %s, which could not be resolved right now.", strings.TrimSuffix(name, "."), target), shortErr(err))
			case tnx:
				r.Add("dns.dangling_cname", Critical, fmt.Sprintf("%s is a CNAME to %s, which does not exist (dangling CNAME; also a subdomain-takeover risk).", strings.TrimSuffix(name, "."), target), "target NXDOMAIN")
			case len(taddrs) == 0:
				r.Add("dns.dangling_cname", Warning, fmt.Sprintf("%s is a CNAME to %s, which has no A/AAAA records.", strings.TrimSuffix(name, "."), target), "target has no addresses")
			}
			addrs = append(addrs, taddrs...)
		}
		if len(addrs) > 0 {
			exists = true
		}
		for _, a := range addrs {
			if safenet.IsBlocked(a) && !c.AllowPrivate {
				r.Add("dns.private_address", Warning, fmt.Sprintf("%s points to a non-public address %s; it is unreachable from the Internet.", strings.TrimSuffix(name, "."), a), "")
				continue
			}
			if a.Is4() {
				v4 = append(v4, a)
			} else {
				v6 = append(v6, a)
			}
		}
		return
	}
	st.ApexV4, st.ApexV6, _ = resolveName(apex)
	st.WWWV4, st.WWWV6, st.WWWExists = resolveName(www)
	if sub != apex {
		v4, v6, ok := resolveName(sub)
		if !ok && nx(sub) {
			r.Add("dns.nxdomain", Critical, fmt.Sprintf("%s does not exist in the zone (NXDOMAIN from the authoritative servers).", st.Domain), "")
		}
		// For a subdomain target, its own addresses are what we probe.
		st.ApexV4, st.ApexV6 = v4, v6
	}
	apexHas := len(st.ApexV4)+len(st.ApexV6) > 0
	wwwHas := len(st.WWWV4)+len(st.WWWV6) > 0
	switch {
	case !apexHas && !wwwHas:
		r.Add("dns.no_address", Critical, "Neither the domain nor www has an A or AAAA record, so no web server can be reached.", "no A/AAAA at "+strings.TrimSuffix(sub, ".")+" or www")
		r.Blocking = true
	case !apexHas:
		r.Add("dns.no_address_apex", Warning, fmt.Sprintf("%s has no A/AAAA record (only www does); visitors typing the bare domain get an error.", st.Domain), "")
	case !wwwHas:
		r.Add("dns.no_www", Info, "www has no address record; visitors typing www. will get an error.", "")
	}
	if apexHas && len(st.ApexV6) == 0 {
		r.Add("dns.no_ipv6", Info, "No AAAA (IPv6) record.", "")
	}

	// MX.
	mxs := get(apex, dns.TypeMX)
	hasMX := false
	for _, rr := range mxs {
		mx := rr.(*dns.MX)
		if mx.Mx == "." {
			r.Add("dns.null_mx", Info, "Null MX published: the domain declares it accepts no mail.", "")
			continue
		}
		hasMX = true
		m, err := c.Recurse(ctx, mx.Mx, dns.TypeA)
		if err != nil {
			continue
		}
		for _, a := range m.Answer {
			if cn, ok := a.(*dns.CNAME); ok && dnsx.Canon(cn.Hdr.Name) == dnsx.Canon(mx.Mx) {
				r.Add("dns.mx_cname", Warning, fmt.Sprintf("MX %s points to a CNAME (not allowed by RFC 2181); some mail servers refuse it.", mx.Mx), "CNAME → "+cn.Target)
				break
			}
		}
		addrs, nxd, err := c.LookupAddrs(ctx, mx.Mx)
		if err == nil && len(addrs) == 0 {
			ev := "no A/AAAA"
			if nxd {
				ev = "NXDOMAIN"
			}
			r.Add("dns.mx_unresolvable", Warning, fmt.Sprintf("MX host %s does not resolve, so mail cannot be delivered to it.", mx.Mx), ev)
		}
	}
	if len(mxs) == 0 {
		r.Add("dns.no_mx", Info, "No MX record: the domain cannot receive email (fine if intended).", "")
	}

	// Authoritative consistency for the apex address set.
	if len(st.AuthServers) > 1 && !st.ViaResolvers {
		ref := ""
		for i, s := range st.AuthServers {
			m, _, err := c.Query(ctx, s.IP, apex, dns.TypeA, false, false)
			if err != nil {
				continue
			}
			got := strings.Join(addrStrings(dnsx.AddrsFrom(m.Answer)), ",")
			if i == 0 || ref == "" {
				ref = got
			} else if got != ref {
				r.Add("dns.auth_inconsistent", Warning, "Authoritative servers return different A records for the domain.", fmt.Sprintf("%s: %s vs %s", s.Name, got, ref))
				break
			}
		}
	}

	var apexTXT []string
	for _, rr := range get(apex, dns.TypeTXT) {
		apexTXT = append(apexTXT, strings.Join(rr.(*dns.TXT).Txt, ""))
	}
	det.Email = checkEmail(ctx, r, apex, apexTXT, hasMX, auth, recursiveTXT(c))
	det.DNSSEC = checkDNSSEC(ctx, r, st, c, auth, now)
	ref := "the authoritative servers"
	if st.ViaResolvers {
		ref = "the reference resolver (" + servers[0].Name + ")"
	}
	det.Propagation = comparePropagation(ctx, r, c, apex, get, det.DNSSEC, ref)

	summary := fmt.Sprintf("%d records from %s", len(det.Records), det.Server)
	return r.Finish(summary)
}

// comparePropagation asks each public resolver for A/AAAA/MX/NS at the apex
// and groups values by how many resolvers returned them.
func comparePropagation(ctx context.Context, r *Result, c *dnsx.Client, apex string, get func(string, uint16) []dns.RR, sec *DNSSECDetails, ref string) []PropagationGroup {
	types := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS}
	groups := make([]PropagationGroup, len(types))
	var wg sync.WaitGroup
	servfails := map[string]bool{}
	var mu sync.Mutex
	for gi, qt := range types {
		g := &groups[gi]
		g.Type, g.Name, g.Consistent = dns.TypeToString[qt], strings.TrimSuffix(apex, "."), true
		for _, rr := range get(apex, qt) {
			g.Authoritative = append(g.Authoritative, rrValue(rr))
		}
		sort.Strings(g.Authoritative)
		vals := map[string][]string{}
		for _, res := range c.Resolvers {
			wg.Add(1)
			go func(res dnsx.Resolver) {
				defer wg.Done()
				m, _, err := c.Query(ctx, res.IP, apex, qt, true, false)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					if g.Errors == nil {
						g.Errors = map[string]string{}
					}
					g.Errors[res.Name] = shortErr(err)
					return
				}
				if m.Rcode != dns.RcodeSuccess {
					if g.Errors == nil {
						g.Errors = map[string]string{}
					}
					g.Errors[res.Name] = dnsx.Rcode(m)
					if m.Rcode == dns.RcodeServerFailure {
						servfails[res.Name] = true
					}
					return
				}
				var got []string
				for _, rr := range m.Answer {
					if rr.Header().Rrtype == qt {
						got = append(got, rrValue(rr))
					}
				}
				sort.Strings(got)
				for _, v := range got {
					vals[v] = append(vals[v], res.Name)
				}
				if len(got) == 0 {
					vals["(empty)"] = append(vals["(empty)"], res.Name)
				}
			}(res)
		}
		wg.Wait()
		for v, rs := range vals {
			sort.Strings(rs)
			g.Values = append(g.Values, PropagationVal{Value: v, Count: len(rs), Resolvers: rs})
		}
		sort.Slice(g.Values, func(i, j int) bool { return g.Values[i].Value < g.Values[j].Value })
		authSet := map[string]bool{}
		for _, v := range g.Authoritative {
			authSet[v] = true
		}
		for _, pv := range g.Values {
			if pv.Value == "(empty)" && len(authSet) == 0 {
				continue
			}
			if !authSet[pv.Value] {
				g.Consistent = false
			}
		}
		if len(g.Authoritative) > 0 && len(g.Values) == 0 && len(g.Errors) == 0 {
			g.Consistent = false
		}
	}
	var diffs []string
	for _, g := range groups {
		if !g.Consistent {
			var parts []string
			for _, v := range g.Values {
				parts = append(parts, fmt.Sprintf("%s (%s)", v.Value, strings.Join(v.Resolvers, ",")))
			}
			diffs = append(diffs, fmt.Sprintf("%s: authoritative [%s] vs resolvers %s", g.Type, strings.Join(g.Authoritative, ", "), strings.Join(parts, "; ")))
		}
	}
	if len(diffs) > 0 {
		r.Add("dns.propagation", Warning, "Public resolvers return different data than "+ref+" (recent change still propagating, stale cache, or geo-DNS).", strings.Join(diffs, " | "))
	}
	if len(servfails) > 0 && (sec == nil || sec.Valid || !sec.Signed) {
		r.Add("dns.resolver_servfail", Warning, "Some public resolvers return SERVFAIL for the domain.", strings.Join(keys(servfails), ", "))
	}
	return groups
}

func addrStrings(a []netip.Addr) []string {
	out := make([]string, len(a))
	for i, x := range a {
		out[i] = x.String()
	}
	sort.Strings(out)
	return out
}

// rrValue returns the RDATA part of a record as text.
func rrValue(rr dns.RR) string {
	s := rr.String()
	h := rr.Header().String()
	return truncate(strings.TrimSpace(strings.TrimPrefix(s, h)), 512)
}

// truncate bounds user-controlled text kept in reports.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
