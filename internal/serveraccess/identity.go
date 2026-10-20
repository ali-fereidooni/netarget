package serveraccess

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"

	"domaindoctor/internal/asn"
	"domaindoctor/internal/rdap"
	"domaindoctor/internal/safenet"
)

// PTRLookup resolves an address to its reverse-DNS name. *dnsx.Client
// implements it; tests inject fakes. Nil deps skip PTR.
type PTRLookup interface {
	LookupPTR(ctx context.Context, ip netip.Addr) (string, error)
}

// IPRegLookup returns IP registration data (IP RDAP). *rdap.Client implements
// it; tests inject fakes. Nil deps skip RDAP.
type IPRegLookup interface {
	LookupIP(ctx context.Context, ip netip.Addr) (*rdap.IPInfo, error)
}

// ASNLookup returns the ASN/operator for an address. *asn.DB implements it;
// nil deps (no dataset loaded) skip ASN enrichment.
type ASNLookup interface {
	Lookup(ip netip.Addr) (*asn.Record, bool)
}

// Deps are the swappable external dependencies of a server-accessibility run.
// Every network-facing field is an interface so the whole feature can be
// tested without touching the network, and so measurement providers stay
// swappable (the nodes passed to Run are the measurement providers).
type Deps struct {
	Resolver safenet.Resolver // hostname resolution (nil = default resolver)
	PTR      PTRLookup        // reverse DNS (nil = skip)
	RDAP     IPRegLookup      // IP RDAP (nil = skip)
	ASN      ASNLookup        // ASN/operator (nil = skip)
	Ports    []int            // TCP ports to test
	Now      func() time.Time
	// CustomPortAllowed lets an operator add one port of their own to a
	// check (WithCustomPort). The nodes must allow it too (probe.Local.ExtraPorts).
	CustomPortAllowed bool

	customPort int // set by WithCustomPort for one run
}

// Custom-port errors. The API maps these to stable codes.
var (
	ErrBadPort       = errors.New("the extra port must be a number from 1 to 65535")
	ErrCustomPortOff = errors.New("custom ports are not enabled on this instance")
)

// WithCustomPort returns a copy of d that also tests port p in this run.
// p == 0 means "no custom port". A port already in the list is not added twice.
func (d Deps) WithCustomPort(p int) (Deps, error) {
	if p == 0 {
		return d, nil
	}
	if p < 1 || p > 65535 {
		return d, ErrBadPort
	}
	if !d.CustomPortAllowed {
		return d, ErrCustomPortOff
	}
	ports := make([]int, 0, len(d.Ports)+1) // fresh slice: never alias the shared config
	for _, q := range d.Ports {
		if q == p {
			return d, nil
		}
		ports = append(ports, q)
	}
	ports = append(ports, p)
	sort.Ints(ports)
	d.Ports, d.customPort = ports, p
	return d, nil
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// identity builds stage 1 for the bounded set of probe addresses.
func (d Deps) identity(ctx context.Context, t Target) *IdentityStage {
	st := &IdentityStage{Host: t.Host, IPs: []IPIdentity{}}
	if t.Host != "" && len(t.IPs) > len(t.probeIPs()) {
		st.Note = "resolved to several addresses; the first few are shown"
	}
	ips := t.probeIPs()
	st.IPs = make([]IPIdentity, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func(i int, ip netip.Addr) {
			defer wg.Done()
			st.IPs[i] = d.identityFor(ctx, ip)
		}(i, ip)
	}
	wg.Wait()
	return st
}

func (d Deps) identityFor(ctx context.Context, ip netip.Addr) IPIdentity {
	row := IPIdentity{IP: ip.String(), Family: family(ip)}
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		if d.PTR == nil {
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		if name, err := d.PTR.LookupPTR(cctx, ip); err == nil {
			row.PTR = name
		}
	}()

	go func() {
		defer wg.Done()
		if d.ASN == nil {
			return
		}
		if rec, ok := d.ASN.Lookup(ip); ok {
			row.ASN, row.ASName, row.ASDomain = rec.ASN, rec.Name, rec.Domain
		}
	}()

	go func() {
		defer wg.Done()
		if d.RDAP == nil {
			row.RDAPNote = "no IP RDAP source configured"
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		info, err := d.RDAP.LookupIP(cctx, ip)
		if err != nil {
			row.RDAPNote = "registration data unavailable"
			return
		}
		row.Network, row.NetName = info.Network, info.Name
		row.Org, row.Country, row.Abuse = info.Org, info.Country, info.Abuse
		row.Created, row.Updated = info.Created, info.Updated
	}()

	wg.Wait()
	return row
}
