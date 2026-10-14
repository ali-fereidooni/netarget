package rdap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const domainJSON = `{
 "objectClassName":"domain","ldhName":"EXAMPLE.COM",
 "status":["client delete prohibited","client hold","redemption period"],
 "events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},
           {"eventAction":"expiration","eventDate":"2026-08-13T04:00:00Z"},
           {"eventAction":"last changed","eventDate":"2025-08-14T07:01:39Z"}],
 "entities":[{"objectClassName":"entity","roles":["registrar"],"handle":"376",
   "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RESERVED-Internet Assigned Numbers Authority"]]]}],
 "nameservers":[{"ldhName":"A.IANA-SERVERS.NET"},{"ldhName":"B.IANA-SERVERS.NET"}]
}`

func newTestServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/dns.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"services":[[["com","net"],["` + srv.URL + `/com/"]],[["uk"],["` + srv.URL + `/uk/"]]]}`))
	})
	mux.HandleFunc("/com/domain/example.com", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte(domainJSON))
	})
	mux.HandleFunc("/com/domain/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/example.com") {
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/uk/domain/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestLookup(t *testing.T) {
	srv := newTestServer(t)
	c := &Client{HTTP: srv.Client(), BootstrapURL: srv.URL + "/dns.json"}
	info, err := c.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if info.Registrar != "RESERVED-Internet Assigned Numbers Authority" {
		t.Errorf("registrar %q", info.Registrar)
	}
	if info.Expires == nil || info.Expires.Year() != 2026 || info.Created.Year() != 1995 {
		t.Errorf("dates %v %v", info.Created, info.Expires)
	}
	want := []string{"clientDeleteProhibited", "clientHold", "redemptionPeriod"}
	if strings.Join(info.Status, ",") != strings.Join(want, ",") {
		t.Errorf("status %v", info.Status)
	}
	if len(info.Nameservers) != 2 || info.Nameservers[0] != "a.iana-servers.net" {
		t.Errorf("ns %v", info.Nameservers)
	}

	if _, err := c.Lookup(context.Background(), "nonexistent.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404 err = %v", err)
	}
	if _, err := c.Lookup(context.Background(), "example.ir"); !errors.Is(err, ErrNoService) {
		t.Errorf("no service err = %v", err)
	}
	if _, err := c.Lookup(context.Background(), "example.co.uk"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("500 err = %v", err)
	}
}

func TestNormalizeStatus(t *testing.T) {
	cases := map[string]string{
		"client hold":       "clientHold",
		"server hold":       "serverHold",
		"pending delete":    "pendingDelete",
		"redemption period": "redemptionPeriod",
		"clientTransferProhibited https://icann.org/epp#clientTransferProhibited": "clientTransferProhibited",
		"ok":           "ok",
		"Active":       "active",
		"CLIENT-HOLD":  "clientHold",
		"serverHold (": "serverHold",
	}
	for in, want := range cases {
		if got := NormalizeStatus(in); got != want {
			t.Errorf("NormalizeStatus(%q) = %q want %q", in, got, want)
		}
	}
}
