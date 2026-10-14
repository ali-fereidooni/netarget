package asn

import (
	"net/netip"
	"strings"
	"testing"
)

const sample = `network,country,country_code,continent,continent_code,asn,as_name,as_domain
1.1.1.0/24,Australia,AU,Oceania,OC,AS13335,"Cloudflare, Inc.",cloudflare.com
8.8.0.0/16,United States,US,North America,NA,AS15169,Google LLC,google.com
8.8.8.0/24,United States,US,North America,NA,AS15169,Google DNS,google.com
2606:4700::/32,United States,US,North America,NA,AS13335,"Cloudflare, Inc.",cloudflare.com
`

func TestLoadLookup(t *testing.T) {
	db, err := Load(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"1.1.1.1":         "AS13335 Cloudflare, Inc.",
		"8.8.4.4":         "AS15169 Google LLC",
		"8.8.8.8":         "AS15169 Google DNS", // longest prefix wins
		"2606:4700::1111": "AS13335 Cloudflare, Inc.",
		"::ffff:1.1.1.1":  "AS13335 Cloudflare, Inc.",
		"9.9.9.9":         "",
	}
	for ip, want := range cases {
		asn, name, ok := db.LookupASN(netip.MustParseAddr(ip))
		got := ""
		if ok {
			got = asn + " " + name
		}
		if got != want {
			t.Errorf("%s: got %q want %q", ip, got, want)
		}
	}
	var nilDB *DB
	if _, ok := nilDB.Lookup(netip.MustParseAddr("1.1.1.1")); ok {
		t.Error("nil db returned a match")
	}
}

func TestLoadRejectsBadFile(t *testing.T) {
	if _, err := Load(strings.NewReader("a,b\n1,2\n")); err == nil {
		t.Error("bad header accepted")
	}
	if _, err := Load(strings.NewReader("network,asn\nnot-a-cidr,AS1\n")); err == nil {
		t.Error("bad cidr accepted")
	}
}
