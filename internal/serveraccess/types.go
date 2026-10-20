// Package serveraccess implements the Server Accessibility check: given a
// customer's IP address or hostname, it reports who/where the host is
// (identity), whether it answers from the measurement nodes (ping), and which
// of a small, configured set of service ports are reachable (ports).
//
// It is a self-contained feature layered on top of the existing building
// blocks (safenet, probe, nodes, rdap, asn, dnsx) and does not alter the
// domain-troubleshooting pipeline. Everything is read-only and non-intrusive:
// ICMP/TCP-connect reachability, reverse DNS, public RDAP/ASN lookups, and at
// most a single GET/HEAD per open web port for a TLS/HTTP summary. It never
// authenticates, sends no payloads, and executes nothing on the target.
package serveraccess

import (
	"net/netip"
	"time"
)

// Status values for a report and its stages.
const (
	StatusRunning = "running"
	StatusDone    = "done"
)

// Report is the full result of one server-accessibility check.
type Report struct {
	ID         string         `json:"id"`
	Target     string         `json:"target"` // what the operator entered (host or IP)
	Host       string         `json:"host,omitempty"`
	Status     string         `json:"status"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	Ports      []int          `json:"ports"` // the port set that was tested
	Identity   *IdentityStage `json:"identity,omitempty"`
	Ping       *PingStage     `json:"ping,omitempty"`
	Services   *PortStage     `json:"services,omitempty"`
}

// Event is a progress update streamed as each stage completes.
type Event struct {
	Type     string         `json:"type"` // start, identity, ping, services, done, error
	Target   string         `json:"target,omitempty"`
	Host     string         `json:"host,omitempty"`
	Ports    []int          `json:"ports,omitempty"`
	Identity *IdentityStage `json:"identity,omitempty"`
	Ping     *PingStage     `json:"ping,omitempty"`
	Services *PortStage     `json:"services,omitempty"`
	Report   *Report        `json:"report,omitempty"`
	Error    string         `json:"error,omitempty"`
	Code     string         `json:"code,omitempty"`
}

// IPIdentity is the identity data gathered for one address.
type IPIdentity struct {
	IP       string     `json:"ip"`
	Family   string     `json:"family"` // IPv4 / IPv6
	PTR      string     `json:"ptr,omitempty"`
	ASN      string     `json:"asn,omitempty"`
	ASName   string     `json:"as_name,omitempty"`
	ASDomain string     `json:"as_domain,omitempty"`
	Network  string     `json:"network,omitempty"` // CIDR / range
	NetName  string     `json:"net_name,omitempty"`
	Org      string     `json:"org,omitempty"`
	Country  string     `json:"country,omitempty"`
	Abuse    string     `json:"abuse,omitempty"`
	Created  *time.Time `json:"created,omitempty"`
	Updated  *time.Time `json:"updated,omitempty"`
	RDAPNote string     `json:"rdap_note,omitempty"` // why RDAP data is missing, if so
}

// IdentityStage is stage 1.
type IdentityStage struct {
	Host string       `json:"host,omitempty"` // resolved hostname, if any
	IPs  []IPIdentity `json:"ips"`
	Note string       `json:"note,omitempty"`
}

// PingRow is one node's ping result for one address.
type PingRow struct {
	NodeID    string  `json:"node_id"`
	Node      string  `json:"node"`
	Location  string  `json:"location"`
	IP        string  `json:"ip"`
	Family    string  `json:"family"`
	Sent      int     `json:"sent"`
	Received  int     `json:"received"`
	Loss      float64 `json:"loss"`
	RTTMin    float64 `json:"rtt_min"`
	RTTAvg    float64 `json:"rtt_avg"`
	RTTMax    float64 `json:"rtt_max"`
	PingError string  `json:"ping_error,omitempty"`
	Status    string  `json:"status"` // ok, icmp_blocked, down, error, n/a
	Note      string  `json:"note,omitempty"`
}

// PingStage is stage 2.
type PingStage struct {
	Rows           []PingRow `json:"rows"`
	ReachableNodes int       `json:"reachable_nodes"`
	TotalNodes     int       `json:"total_nodes"`
	Summary        string    `json:"summary"`
}

// PortRow aggregates one TCP port across all nodes for one address.
type PortRow struct {
	IP        string       `json:"ip"`
	Family    string       `json:"family"`
	Port      int          `json:"port"`
	Service   string       `json:"service"`   // well-known label
	State     string       `json:"state"`     // open, closed, filtered, mixed
	OpenFrom  int          `json:"open_from"` // nodes that saw it open
	Nodes     int          `json:"nodes"`     // nodes that tested it
	LatencyMS float64      `json:"latency_ms,omitempty"`
	HTTP      *HTTPSummary `json:"http,omitempty"`
	TLS       *TLSSummary  `json:"tls,omitempty"`
}

// HTTPSummary is a light reachability signal for an open web port.
type HTTPSummary struct {
	Status     int    `json:"status,omitempty"`
	StatusText string `json:"status_text,omitempty"`
	Server     string `json:"server,omitempty"`
	Error      string `json:"error,omitempty"`
}

// TLSSummary is a certificate summary for an open 443 (identity, not a scan).
type TLSSummary struct {
	Version   string     `json:"version,omitempty"`
	Subject   string     `json:"subject,omitempty"`
	Issuer    string     `json:"issuer,omitempty"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
	DaysLeft  int        `json:"days_left,omitempty"`
	SANsCount int        `json:"sans_count,omitempty"`
}

// PortStage is stage 3.
type PortStage struct {
	Rows    []PortRow `json:"rows"`
	Summary string    `json:"summary"`
}

func family(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}

// serviceName labels a well-known port for display. Unknown ports get "".
func serviceName(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 110:
		return "POP3"
	case 143:
		return "IMAP"
	case 443:
		return "HTTPS"
	case 465, 587:
		return "SMTP (submission)"
	case 993:
		return "IMAPS"
	case 995:
		return "POP3S"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 8080:
		return "HTTP (alt)"
	case 8443:
		return "HTTPS (alt)"
	}
	return ""
}

// isWebPort reports whether a light HTTP/TLS summary is worth attempting.
func isWebPort(port int) bool {
	switch port {
	case 80, 443, 8080, 8443:
		return true
	}
	return false
}
