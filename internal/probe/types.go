// Package probe holds the network measurements executed on agents (and by
// the in-process local agent): ICMP ping, TCP connect, HTTP(S) with redirect
// chain and timing, TLS inspection, and traceroute. Request/response types
// are shared by the agent server, the agent client, and the checks.
package probe

import (
	"context"
	"net/netip"
	"time"
)

// Prober is implemented by the local in-process agent and the remote agent client.
type Prober interface {
	Probe(ctx context.Context, req ProbeRequest) (*ProbeResponse, error)
	HTTP(ctx context.Context, req HTTPRequest) (*HTTPResponse, error)
	Traceroute(ctx context.Context, ip netip.Addr, maxHops int, line func(string)) error
	Health(ctx context.Context) error
}

// AllowedPorts are the only TCP ports agents will test (limits port-scan abuse).
var AllowedPorts = map[int]bool{80: true, 443: true}

type ProbeRequest struct {
	Host      string       `json:"host"`
	IPs       []netip.Addr `json:"ips"`
	PingCount int          `json:"ping_count"`
	Ports     []int        `json:"ports"`
}

type ProbeResponse struct {
	Results []IPProbe `json:"results"`
}

type IPProbe struct {
	IP netip.Addr `json:"ip"`
	// Skipped is set when this node cannot test the address at all (e.g.
	// an IPv6 target on a node without IPv6); the result says nothing about the target.
	Skipped   string      `json:"skipped,omitempty"`
	Ping      *PingResult `json:"ping,omitempty"`
	PingError string      `json:"ping_error,omitempty"`
	TCP       []TCPResult `json:"tcp"`
}

type PingResult struct {
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	Loss     float64 `json:"loss"`
	RTTMin   float64 `json:"rtt_min"`
	RTTAvg   float64 `json:"rtt_avg"`
	RTTMax   float64 `json:"rtt_max"`
}

type TCPResult struct {
	Port      int     `json:"port"`
	Status    string  `json:"status"` // open, closed, filtered
	LatencyMS float64 `json:"latency_ms,omitempty"`
	Error     string  `json:"error,omitempty"`
}

type HTTPRequest struct {
	URLs    []string                `json:"urls"`
	Pinned  map[string][]netip.Addr `json:"pinned"` // host -> IPs resolved by the master
	MaxHops int                     `json:"max_hops"`
}

type HTTPResponse struct {
	Chains []Chain `json:"chains"`
}

type Chain struct {
	Start string `json:"start"`
	Hops  []Hop  `json:"hops"`
	Loop  bool   `json:"loop,omitempty"`
}

// Final returns the last hop (or nil).
func (c *Chain) Final() *Hop {
	if len(c.Hops) == 0 {
		return nil
	}
	return &c.Hops[len(c.Hops)-1]
}

type Hop struct {
	URL        string            `json:"url"`
	IP         string            `json:"ip,omitempty"`
	Status     int               `json:"status,omitempty"`
	StatusText string            `json:"status_text,omitempty"`
	Location   string            `json:"location,omitempty"`
	Server     string            `json:"server,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Timing     Timing            `json:"timing"`
	TLS        *TLSInfo          `json:"tls,omitempty"`
	CDN        string            `json:"cdn,omitempty"`
	CDNError   bool              `json:"cdn_error,omitempty"`
	ErrorKind  string            `json:"error_kind,omitempty"` // timeout, refused, reset, tls_handshake, dns, blocked, bad_url, other
	Error      string            `json:"error,omitempty"`
}

type Timing struct {
	DNSms     float64 `json:"dns_ms"`
	ConnectMS float64 `json:"connect_ms"`
	TLSms     float64 `json:"tls_ms"`
	TTFBms    float64 `json:"ttfb_ms"`
	TotalMS   float64 `json:"total_ms"`
}

type TLSInfo struct {
	Version         string    `json:"version"`
	Cipher          string    `json:"cipher"`
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	DaysLeft        int       `json:"days_left"`
	SANs            []string  `json:"sans"`
	HostnameMatch   bool      `json:"hostname_match"`
	ChainValid      bool      `json:"chain_valid"`
	ChainError      string    `json:"chain_error,omitempty"`
	IncompleteChain bool      `json:"incomplete_chain,omitempty"`
	SelfSigned      bool      `json:"self_signed,omitempty"`
	ChainLength     int       `json:"chain_length"`
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
