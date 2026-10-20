package rdap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// IANA's RDAP bootstrap files for IP address space. They map address blocks
// to the RDAP base URL of the RIR (ARIN, RIPE, APNIC, ...) that manages them.
const (
	DefaultIPv4BootstrapURL = "https://data.iana.org/rdap/ipv4.json"
	DefaultIPv6BootstrapURL = "https://data.iana.org/rdap/ipv6.json"
)

// IPInfo is normalized registration data for an IP address, from IP RDAP.
type IPInfo struct {
	Source  string     `json:"source"` // "rdap"
	Server  string     `json:"server"`
	Handle  string     `json:"handle,omitempty"`
	Network string     `json:"network,omitempty"` // CIDR or start-end range
	Name    string     `json:"name,omitempty"`    // network name
	Type    string     `json:"type,omitempty"`    // allocation type (e.g. "ALLOCATED PA")
	Country string     `json:"country,omitempty"`
	Org     string     `json:"org,omitempty"`   // registrant / org entity
	Abuse   string     `json:"abuse,omitempty"` // abuse contact email
	Created *time.Time `json:"created,omitempty"`
	Updated *time.Time `json:"updated,omitempty"`
}

// bootstrapIP fetches and caches one IP bootstrap file as a list of
// (prefixes, base URLs) pairs, preserving order (longest-prefix wins later).
func (c *Client) bootstrapIP(ctx context.Context, is6 bool) ([][2][]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ipServices == nil {
		c.ipServices = map[bool][][2][]string{}
	}
	if svc, ok := c.ipServices[is6]; ok && time.Since(c.ipFetched) < 24*time.Hour {
		return svc, nil
	}
	u := c.ipv4Bootstrap()
	if is6 {
		u = c.ipv6Bootstrap()
	}
	var doc struct {
		Services [][][]string `json:"services"`
	}
	if _, err := c.getJSON(ctx, u, &doc); err != nil {
		if svc, ok := c.ipServices[is6]; ok {
			return svc, nil // serve stale on refresh failure
		}
		return nil, err
	}
	out := make([][2][]string, 0, len(doc.Services))
	for _, svc := range doc.Services {
		if len(svc) < 2 {
			continue
		}
		out = append(out, [2][]string{svc[0], svc[1]})
	}
	c.ipServices[is6] = out
	c.ipFetched = time.Now()
	return out, nil
}

func (c *Client) ipv4Bootstrap() string {
	if c.IPv4BootstrapURL != "" {
		return c.IPv4BootstrapURL
	}
	return DefaultIPv4BootstrapURL
}

func (c *Client) ipv6Bootstrap() string {
	if c.IPv6BootstrapURL != "" {
		return c.IPv6BootstrapURL
	}
	return DefaultIPv6BootstrapURL
}

// ipBaseURLs returns the RDAP base URLs for ip, most specific prefix first.
func (c *Client) ipBaseURLs(ctx context.Context, ip netip.Addr) ([]string, error) {
	svc, err := c.bootstrapIP(ctx, ip.Is6())
	if err != nil {
		return nil, err
	}
	best := -1
	var urls []string
	for _, pair := range svc {
		for _, cidr := range pair[0] {
			p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
			if err != nil {
				continue
			}
			if p.Contains(ip) && p.Bits() > best {
				best, urls = p.Bits(), pair[1]
			}
		}
	}
	if len(urls) == 0 {
		return nil, ErrNoService
	}
	return urls, nil
}

// LookupIP returns registration data for ip from IP RDAP, or ErrNoService
// when the address is in a block with no RDAP service and ErrNotFound when the
// registry has no record for it.
func (c *Client) LookupIP(ctx context.Context, ip netip.Addr) (*IPInfo, error) {
	bases, err := c.ipBaseURLs(ctx, ip)
	if err != nil {
		return nil, err
	}
	for i, b := range bases { // prefer https
		if strings.HasPrefix(b, "https://") && i > 0 {
			bases[0], bases[i] = bases[i], bases[0]
			break
		}
	}
	var lastErr error = ErrNoService
	for _, base := range bases {
		if !strings.HasSuffix(base, "/") {
			base += "/"
		}
		u := base + "ip/" + url.PathEscape(ip.String())
		var doc rdapIP
		code, err := c.getJSON(ctx, u, &doc)
		if code == http.StatusNotFound {
			return nil, ErrNotFound
		}
		if err != nil {
			lastErr = err
			continue
		}
		info := doc.toInfo()
		info.Server = hostOf(base)
		return info, nil
	}
	return nil, lastErr
}

type rdapIP struct {
	Handle       string `json:"handle"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Country      string `json:"country"`
	CIDR0        []struct {
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []rdapEntity `json:"entities"`
}

func (d *rdapIP) toInfo() *IPInfo {
	info := &IPInfo{Source: "rdap", Handle: d.Handle, Name: d.Name, Type: d.Type, Country: strings.ToUpper(d.Country)}
	switch {
	case len(d.CIDR0) > 0:
		p := d.CIDR0[0].V4Prefix
		if p == "" {
			p = d.CIDR0[0].V6Prefix
		}
		if p != "" {
			info.Network = p + "/" + strconv.Itoa(d.CIDR0[0].Length)
		}
	case d.StartAddress != "" && d.EndAddress != "":
		info.Network = d.StartAddress + " – " + d.EndAddress
	}
	for _, e := range d.Events {
		t, ok := ParseDate(e.Date)
		if !ok {
			continue
		}
		switch strings.ToLower(e.Action) {
		case "registration":
			info.Created = &t
		case "last changed":
			info.Updated = &t
		}
	}
	info.Org, info.Abuse = orgAndAbuse(d.Entities)
	return info
}

// orgAndAbuse walks the (possibly nested) entity list for a registrant /
// administrative org name and an abuse-role email address.
func orgAndAbuse(ents []rdapEntity) (org, abuse string) {
	var walk func([]rdapEntity)
	walk = func(es []rdapEntity) {
		for _, e := range es {
			if abuse == "" && hasRole(e.Roles, "abuse") {
				abuse = vcardEmail(e.VCardArray)
			}
			if org == "" && (hasRole(e.Roles, "registrant") || hasRole(e.Roles, "administrative")) {
				if n := vcardFN(e.VCardArray); n != "" {
					org = n
				} else if e.Handle != "" {
					org = e.Handle
				}
			}
			walk(e.Entities)
		}
	}
	walk(ents)
	return org, abuse
}

// vcardEmail extracts the first "email" property value from a jCard.
func vcardEmail(raw json.RawMessage) string {
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil || len(arr) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if json.Unmarshal(arr[1], &props) != nil {
		return ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var name, val string
		if json.Unmarshal(p[0], &name) == nil && name == "email" && json.Unmarshal(p[3], &val) == nil {
			return val
		}
	}
	return ""
}
