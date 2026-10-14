package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"domaindoctor/internal/dnsx"
)

// Bounds on signature verification work per check.
const (
	maxSignerKeys     = 8
	maxVerifyAttempts = 4
)

type DNSSECDetails struct {
	Signed     bool     `json:"signed"`
	DS         []string `json:"ds,omitempty"`
	DNSKEYs    []string `json:"dnskeys,omitempty"`
	MatchedKSK uint16   `json:"matched_ksk,omitempty"`
	Chain      []string `json:"chain"` // human-readable validation steps
	Valid      bool     `json:"valid"`
}

// checkDNSSEC validates DS (parent) -> DNSKEY (child) -> RRSIG over DNSKEY and SOA.
func checkDNSSEC(ctx context.Context, r *Result, st *State, c *dnsx.Client, auth *authQuerier, now time.Time) *DNSSECDetails {
	d := &DNSSECDetails{Chain: []string{}}
	apex := dnsx.Canon(st.Apex)

	// DS from the parent server directly, else via a recursive resolver.
	var dsMsg *dns.Msg
	if st.ParentServer.IsValid() {
		if m, _, err := c.Query(ctx, st.ParentServer, apex, dns.TypeDS, false, true); err == nil {
			dsMsg = m
		}
	}
	if dsMsg == nil {
		if m, err := c.Recurse(ctx, apex, dns.TypeDS); err == nil {
			dsMsg = m
		}
	}
	var dss []*dns.DS
	if dsMsg != nil {
		for _, rr := range dsMsg.Answer {
			if ds, ok := rr.(*dns.DS); ok {
				dss = append(dss, ds)
				d.DS = append(d.DS, fmt.Sprintf("%d %s %d", ds.KeyTag, dns.AlgorithmToString[ds.Algorithm], ds.DigestType))
			}
		}
	}

	keyMsg, err := auth.query(ctx, apex, dns.TypeDNSKEY, true)
	var keys []*dns.DNSKEY
	var keySigs []*dns.RRSIG
	keyRRs := []dns.RR{}
	if err == nil {
		for _, rr := range keyMsg.Answer {
			switch v := rr.(type) {
			case *dns.DNSKEY:
				// The RRset is verified whole, but only a few keys are tried
				// as signers, bounding crypto work (KeyTrap-style zones).
				if len(keys) < maxSignerKeys {
					keys = append(keys, v)
				}
				keyRRs = append(keyRRs, v)
				d.DNSKEYs = append(d.DNSKEYs, fmt.Sprintf("%d flags=%d %s", v.KeyTag(), v.Flags, dns.AlgorithmToString[v.Algorithm]))
			case *dns.RRSIG:
				if v.TypeCovered == dns.TypeDNSKEY {
					keySigs = append(keySigs, v)
				}
			}
		}
	}

	if len(dss) == 0 {
		if len(keys) > 0 {
			r.Add("dnssec.no_ds", Info, "The zone is signed (DNSKEY present) but no DS record is published at the registrar, so DNSSEC is not active.", strings.Join(d.DNSKEYs, "; "))
		} else {
			r.Add("dnssec.unsigned", Info, "DNSSEC is not enabled for this domain.", "no DS at parent")
		}
		d.Chain = append(d.Chain, "no DS at parent: zone is insecure (unsigned delegation)")
		return d
	}
	d.Signed = true
	d.Chain = append(d.Chain, fmt.Sprintf("parent publishes %d DS record(s)", len(dss)))
	broken := func(msg, ev string) *DNSSECDetails {
		d.Chain = append(d.Chain, "FAIL: "+msg)
		r.Add("dnssec.broken", Critical, "DNSSEC is broken: "+msg+" Validating resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9) will return SERVFAIL.", ev)
		return d
	}
	if len(keys) == 0 {
		return broken("the parent has a DS record but the zone publishes no DNSKEY.", strings.Join(d.DS, "; "))
	}

	// DS -> DNSKEY match.
	var ksk *dns.DNSKEY
	for _, ds := range dss {
		for _, k := range keys {
			if k.KeyTag() != ds.KeyTag || k.Algorithm != ds.Algorithm {
				continue
			}
			if calc := k.ToDS(ds.DigestType); calc != nil && strings.EqualFold(calc.Digest, ds.Digest) {
				ksk = k
				break
			}
		}
		if ksk != nil {
			break
		}
	}
	if ksk == nil {
		return broken("no DNSKEY in the zone matches the DS at the parent (often a DS left behind after changing DNS provider).",
			"DS: "+strings.Join(d.DS, "; ")+" | DNSKEY: "+strings.Join(d.DNSKEYs, "; "))
	}
	d.MatchedKSK = ksk.KeyTag()
	d.Chain = append(d.Chain, fmt.Sprintf("DS matches DNSKEY %d", ksk.KeyTag()))

	// RRSIG over DNSKEY by the KSK.
	if err := verifySet(keySigs, ksk, keyRRs, now); err != nil {
		return broken("the DNSKEY set signature does not validate ("+err.Error()+").", fmt.Sprintf("KSK %d", ksk.KeyTag()))
	}
	d.Chain = append(d.Chain, fmt.Sprintf("DNSKEY RRset signed by %d: valid", ksk.KeyTag()))

	// RRSIG over SOA by any zone key.
	soaMsg, err := auth.query(ctx, apex, dns.TypeSOA, true)
	if err != nil {
		return broken("the SOA could not be fetched for validation.", shortErr(err))
	}
	var soaRRs []dns.RR
	var soaSigs []*dns.RRSIG
	for _, rr := range soaMsg.Answer {
		switch v := rr.(type) {
		case *dns.SOA:
			soaRRs = append(soaRRs, v)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeSOA {
				soaSigs = append(soaSigs, v)
			}
		}
	}
	var soaErr error = fmt.Errorf("no RRSIG over SOA")
	for _, k := range keys {
		if soaErr = verifySet(soaSigs, k, soaRRs, now); soaErr == nil {
			d.Chain = append(d.Chain, fmt.Sprintf("SOA signed by %d: valid", k.KeyTag()))
			break
		}
	}
	if soaErr != nil {
		return broken("the SOA record signature does not validate ("+soaErr.Error()+").", "")
	}

	// Expiring signatures. Online signers (e.g. Cloudflare) issue signatures
	// valid for only a few days, so "close to expiry" must be judged against
	// the signature's own validity window, not an absolute threshold.
	for _, s := range append(append([]*dns.RRSIG{}, keySigs...), soaSigs...) {
		if sigExpiringSoon(s, now) {
			exp := time.Unix(int64(s.Expiration), 0)
			r.Add("dnssec.sig_expiring", Warning, fmt.Sprintf("An RRSIG expires on %s; re-signing may have stopped.", exp.UTC().Format(time.RFC3339)),
				fmt.Sprintf("%s signature by key %d", dns.TypeToString[s.TypeCovered], s.KeyTag))
			break
		}
	}
	if ksk.Algorithm == dns.RSASHA1 || ksk.Algorithm == dns.RSASHA1NSEC3SHA1 {
		r.Add("dnssec.weak_algorithm", Info, "The zone uses RSASHA1, which is deprecated; roll to algorithm 13 (ECDSAP256SHA256).", "")
	}
	d.Valid = true
	r.Add("dnssec.valid", Info, "DNSSEC chain DS → DNSKEY → RRSIG validates.", strings.Join(d.Chain, "; "))
	return d
}

// sigExpiringSoon: less than 72h and less than 20% of the validity window left.
func sigExpiringSoon(s *dns.RRSIG, now time.Time) bool {
	inc, exp := time.Unix(int64(s.Inception), 0), time.Unix(int64(s.Expiration), 0)
	left, window := exp.Sub(now), exp.Sub(inc)
	return left > 0 && left < 72*time.Hour && window > 0 && left*5 < window
}

// verifySet checks that one of sigs, made by key, validates rrset now.
func verifySet(sigs []*dns.RRSIG, key *dns.DNSKEY, rrset []dns.RR, now time.Time) error {
	if len(rrset) == 0 {
		return fmt.Errorf("empty RRset")
	}
	var last error = fmt.Errorf("no RRSIG from key %d", key.KeyTag())
	attempts := 0
	for _, s := range sigs {
		if s.KeyTag != key.KeyTag() || s.Algorithm != key.Algorithm {
			continue
		}
		if attempts++; attempts > maxVerifyAttempts {
			break
		}
		if !s.ValidityPeriod(now) {
			last = fmt.Errorf("signature by key %d is expired or not yet valid", s.KeyTag)
			continue
		}
		if err := s.Verify(key, rrset); err != nil {
			last = fmt.Errorf("signature by key %d: %v", s.KeyTag, err)
			continue
		}
		return nil
	}
	return last
}
