// Package asn provides optional IP -> ASN/operator lookups from an
// ipinfo-style CSV (or CSV.GZ) loaded into binary radix tries. The service
// runs fine without it; lookups then simply return ok=false.
//
// Accepted header columns (order-independent): network (CIDR), asn,
// as_name (or name), as_domain (or domain). Extra columns such as country
// are ignored. This matches the free "IPinfo Lite" CSV.
package asn

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

type Record struct {
	ASN    string `json:"asn"`
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
}

type node struct {
	child [2]*node
	rec   *Record
}

// DB is an immutable lookup structure.
type DB struct {
	v4, v6 *node
	Count  int
}

func (db *DB) insert(p netip.Prefix, r *Record) {
	root := &db.v4
	if p.Addr().Is6() {
		root = &db.v6
	}
	if *root == nil {
		*root = &node{}
	}
	n := *root
	b := p.Addr().AsSlice()
	for i := 0; i < p.Bits(); i++ {
		bit := (b[i/8] >> (7 - uint(i%8))) & 1
		if n.child[bit] == nil {
			n.child[bit] = &node{}
		}
		n = n.child[bit]
	}
	n.rec = r
	db.Count++
}

// Lookup returns the longest-prefix match.
func (db *DB) Lookup(ip netip.Addr) (*Record, bool) {
	if db == nil {
		return nil, false
	}
	ip = ip.Unmap()
	n := db.v4
	if ip.Is6() {
		n = db.v6
	}
	var best *Record
	b := ip.AsSlice()
	for i := 0; n != nil; i++ {
		if n.rec != nil {
			best = n.rec
		}
		if i >= len(b)*8 {
			break
		}
		n = n.child[(b[i/8]>>(7-uint(i%8)))&1]
	}
	return best, best != nil
}

// LookupASN satisfies checks.ASNLookup.
func (db *DB) LookupASN(ip netip.Addr) (string, string, bool) {
	r, ok := db.Lookup(ip)
	if !ok {
		return "", "", false
	}
	return r.ASN, r.Name, true
}

// LoadFile loads a CSV or CSV.GZ file.
func LoadFile(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rd io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		rd = gz
	}
	return Load(rd)
}

// Load parses CSV with a header row. A malformed file is rejected entirely.
func Load(r io.Reader) (*DB, error) {
	cr := csv.NewReader(r)
	cr.ReuseRecord = true
	head, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("asn csv: %w", err)
	}
	col := map[string]int{}
	for i, h := range head {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	idx := func(names ...string) int {
		for _, n := range names {
			if i, ok := col[n]; ok {
				return i
			}
		}
		return -1
	}
	iNet, iASN, iName, iDom := idx("network"), idx("asn"), idx("as_name", "name"), idx("as_domain", "domain")
	if iNet < 0 || iASN < 0 {
		return nil, fmt.Errorf("asn csv: header must contain network and asn columns")
	}
	db := &DB{}
	recs := map[string]*Record{} // dedupe identical AS records
	line := 1
	for {
		row, err := cr.Read()
		line++
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("asn csv line %d: %w", line, err)
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(row[iNet]))
		if err != nil {
			return nil, fmt.Errorf("asn csv line %d: bad network", line)
		}
		as := strings.TrimSpace(row[iASN])
		if as == "" {
			continue
		}
		get := func(i int) string {
			if i >= 0 && i < len(row) {
				return strings.TrimSpace(row[i])
			}
			return ""
		}
		key := as + "|" + get(iName) + "|" + get(iDom)
		rec, ok := recs[key]
		if !ok {
			rec = &Record{ASN: as, Name: get(iName), Domain: get(iDom)}
			recs[key] = rec
		}
		db.insert(p.Masked(), rec)
	}
	return db, nil
}
