package whois

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"domaindoctor/internal/rdap"
)

// fakeWhois serves canned responses keyed by the query line.
func fakeWhois(t *testing.T, answers map[string]string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				c.Write([]byte(answers[strings.TrimSpace(line)]))
			}(c)
		}
	}()
	return ln.Addr().String()
}

func testClient(addr string) *Client {
	d := &net.Dialer{}
	return &Client{
		Dial:       func(ctx context.Context, n, _ string) (net.Conn, error) { return d.DialContext(ctx, n, addr) },
		IANAServer: addr, Timeout: 2 * time.Second,
	}
}

func TestLookupViaIANAReferral(t *testing.T) {
	addr := fakeWhois(t, map[string]string{
		"ir": "% IANA WHOIS server\nrefer:        whois.nic.ir\n\ndomain:       IR\nwhois:        whois.nic.ir\n",
		"example.ir": "% This is the IRNIC Whois server\ndomain:\t\texample.ir\nexpire-date:\t2020-01-01\n" +
			"nserver:\t\tns1.example.ir\nnserver:\t\tns2.example.ir\nlast-updated:\t2019-01-01\nsource:\t\tIRNIC\n",
		"free.ir": "%ERROR:101: no entries found\n",
	})
	c := testClient(addr)
	srv, err := c.Server(context.Background(), "example.ir")
	if err != nil || srv != "whois.nic.ir:43" {
		t.Fatalf("server %q %v", srv, err)
	}
	info, err := c.Lookup(context.Background(), "example.ir")
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Nameservers) != 2 || info.Source != "whois" || info.Expires == nil || info.Expires.Year() != 2020 {
		t.Errorf("info %+v", info)
	}
	if _, err := c.Lookup(context.Background(), "free.ir"); !errors.Is(err, rdap.ErrNotFound) {
		t.Errorf("free err %v", err)
	}
}

func TestParseVerisignStyle(t *testing.T) {
	resp := `   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN
   Registrar: RESERVED-Internet Assigned Numbers Authority
   Updated Date: 2024-08-14T07:01:34Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2025-08-13T04:00:00Z
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: serverHold https://icann.org/epp#serverHold
   Name Server: A.IANA-SERVERS.NET
>>> Last update of whois database: 2024-10-01T00:00:00Z <<<`
	info, err := Parse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if info.Registrar != "RESERVED-Internet Assigned Numbers Authority" || info.Expires.Year() != 2025 || info.Created.Year() != 1995 {
		t.Errorf("%+v", info)
	}
	if strings.Join(info.Status, ",") != "clientDeleteProhibited,serverHold" {
		t.Errorf("status %v", info.Status)
	}
	if _, err := Parse("No match for \"NOPE.COM\".\n"); !errors.Is(err, rdap.ErrNotFound) {
		t.Errorf("no match err %v", err)
	}
	if _, err := Parse("garbage"); err == nil || errors.Is(err, rdap.ErrNotFound) {
		t.Errorf("garbage err %v", err)
	}
}
