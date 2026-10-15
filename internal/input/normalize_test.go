package input

import (
	"errors"
	"testing"
)

func TestNormalize(t *testing.T) {
	ok := []struct{ in, name, apex string }{
		{"example.com", "example.com", "example.com"},
		{"  EXAMPLE.COM.  ", "example.com", "example.com"},
		{"https://www.Example.com:8443/path?q=1#x", "example.com", "example.com"},
		{"http://user:pw@shop.example.co.uk/", "shop.example.co.uk", "example.co.uk"},
		{"//example.org", "example.org", "example.org"},
		{"www.example.net", "example.net", "example.net"},
		{"bücher.de", "xn--bcher-kva.de", "xn--bcher-kva.de"},
		{"https://xn--bcher-kva.de", "xn--bcher-kva.de", "xn--bcher-kva.de"},
		{"ПРИМЕР.рф", "xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai"},
	}
	for _, c := range ok {
		d, err := Normalize(c.in)
		if err != nil {
			t.Errorf("Normalize(%q) error: %v", c.in, err)
			continue
		}
		if d.Name != c.name || d.Apex != c.apex {
			t.Errorf("Normalize(%q) = %q/%q, want %q/%q", c.in, d.Name, d.Apex, c.name, c.apex)
		}
	}

	bad := []struct {
		in   string
		want error
	}{
		{"", ErrEmpty},
		{"   ", ErrEmpty},
		{"1.2.3.4", ErrIP},
		{"http://1.2.3.4:80/", ErrIP},
		{"[::1]:443", ErrIP},
		{"::1", ErrIP},
		{"127.1", ErrIP},
		{"0x7f.1", ErrIP},
		{"localhost", ErrLocal},
		{"foo.localhost", ErrLocal},
		{"printer.local", ErrLocal},
		{"db.internal", ErrLocal},
		{"com", ErrNoTLD},
		{"co.uk", ErrPublicSufix},
		{"exa mple.com", ErrInvalid},
		{"example.com;rm -rf /", ErrInvalid},
		{"$(id).example.com", ErrInvalid},
		{"-bad.com", ErrInvalid},
		{"a..b.com", ErrInvalid},
		{"example.com:abc", ErrInvalid},
	}
	for _, c := range bad {
		_, err := Normalize(c.in)
		if err == nil || !errors.Is(err, c.want) {
			t.Errorf("Normalize(%q) err = %v, want %v", c.in, err, c.want)
		}
	}
}

func TestParseOriginIP(t *testing.T) {
	for _, bad := range []string{"fe80::1%eth0", "2606:4700::1%25eth0", "2001:0:4136:e378::1", "10.0.0.1", "example.com"} {
		if _, err := ParseOriginIP(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if a, err := ParseOriginIP("93.184.215.14"); err != nil || a.String() != "93.184.215.14" {
		t.Fatalf("%v %v", a, err)
	}
}
