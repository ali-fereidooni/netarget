package clientip

import (
	"net/http/httptest"
	"testing"
)

func TestExtractor(t *testing.T) {
	cidrs, err := ParseCIDRs("127.0.0.1, 10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		e      Extractor
		remote string
		xff    []string
		want   string
	}{
		{"no proxy ignores xff", Extractor{}, "203.0.113.9:1234", []string{"1.1.1.1"}, "203.0.113.9"},
		{"nginx one hop", Extractor{Hops: 1}, "127.0.0.1:5000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"spoofed prefix ignored", Extractor{Hops: 1}, "127.0.0.1:5000", []string{"6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		{"cdn+nginx two hops", Extractor{Hops: 2}, "127.0.0.1:5000", []string{"6.6.6.6, 198.51.100.7, 104.16.0.1"}, "198.51.100.7"},
		{"multiple headers", Extractor{Hops: 1}, "127.0.0.1:5000", []string{"6.6.6.6", "198.51.100.7"}, "198.51.100.7"},
		{"too few entries falls back", Extractor{Hops: 2}, "127.0.0.1:5000", []string{"198.51.100.7"}, "127.0.0.1"},
		{"garbage falls back", Extractor{Hops: 1}, "127.0.0.1:5000", []string{"not-an-ip"}, "127.0.0.1"},
		{"untrusted remote ignores xff", Extractor{Hops: 1, TrustedCIDRs: cidrs}, "203.0.113.9:1", []string{"1.1.1.1"}, "203.0.113.9"},
		{"trusted remote uses xff", Extractor{Hops: 1, TrustedCIDRs: cidrs}, "10.2.3.4:1", []string{"1.1.1.1"}, "1.1.1.1"},
		{"ipv6 with port", Extractor{Hops: 1}, "[::1]:80", []string{"[2001:db8::5]:443"}, "2001:db8::5"},
		{"ipv4 with port", Extractor{Hops: 1}, "[::1]:80", []string{"198.51.100.7:55"}, "198.51.100.7"},
	}
	// IPv6 clients share a key per /64; IPv4 keys are the address.
	r6 := httptest.NewRequest("GET", "/", nil)
	r6.RemoteAddr = "[2001:db8:1:2:aaaa::1]:5"
	if k := (Extractor{}).Key(r6); k != "2001:db8:1:2::/64" {
		t.Errorf("v6 key %q", k)
	}
	r4 := httptest.NewRequest("GET", "/", nil)
	r4.RemoteAddr = "198.51.100.7:5"
	if k := (Extractor{}).Key(r4); k != "198.51.100.7" {
		t.Errorf("v4 key %q", k)
	}

	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := c.e.IP(r); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
