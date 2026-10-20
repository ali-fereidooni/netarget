package rdap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

const ipJSON = `{
 "objectClassName":"ip network","handle":"NET-93-184-215-0-1",
 "startAddress":"93.184.215.0","endAddress":"93.184.215.255",
 "name":"EDGECAST-NETBLK","type":"ALLOCATED PA","country":"US",
 "cidr0_cidrs":[{"v4prefix":"93.184.215.0","length":24}],
 "events":[{"eventAction":"registration","eventDate":"2008-06-02T00:00:00Z"},
           {"eventAction":"last changed","eventDate":"2024-01-15T00:00:00Z"}],
 "entities":[
   {"roles":["registrant","administrative"],"handle":"EDGC",
    "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Edgecast Inc."]]]},
   {"roles":["abuse"],"handle":"AB",
    "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Abuse"],["email",{},"text","abuse@example.net"]]]}
 ]
}`

func newIPServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/ipv4.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"services":[[["93.184.215.0/24","1.0.0.0/8"],["` + srv.URL + `/rir/"]]]}`))
	})
	mux.HandleFunc("/rir/ip/93.184.215.14", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte(ipJSON))
	})
	mux.HandleFunc("/rir/ip/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestLookupIP(t *testing.T) {
	srv := newIPServer(t)
	c := &Client{HTTP: srv.Client(), IPv4BootstrapURL: srv.URL + "/ipv4.json"}
	info, err := c.LookupIP(context.Background(), netip.MustParseAddr("93.184.215.14"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Network != "93.184.215.0/24" {
		t.Errorf("network %q", info.Network)
	}
	if info.Name != "EDGECAST-NETBLK" || info.Country != "US" {
		t.Errorf("name/country %q %q", info.Name, info.Country)
	}
	if info.Org != "Edgecast Inc." {
		t.Errorf("org %q", info.Org)
	}
	if info.Abuse != "abuse@example.net" {
		t.Errorf("abuse %q", info.Abuse)
	}
	if info.Created == nil || info.Created.Year() != 2008 || info.Updated == nil || info.Updated.Year() != 2024 {
		t.Errorf("dates %v %v", info.Created, info.Updated)
	}

	if _, err := c.LookupIP(context.Background(), netip.MustParseAddr("93.184.215.99")); !errors.Is(err, ErrNotFound) {
		t.Errorf("404 err = %v", err)
	}
	// An address outside any configured block has no RDAP service.
	if _, err := c.LookupIP(context.Background(), netip.MustParseAddr("8.8.8.8")); !errors.Is(err, ErrNoService) {
		t.Errorf("no-service err = %v", err)
	}
}
