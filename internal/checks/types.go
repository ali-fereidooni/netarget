// Package checks implements the five troubleshooting layers. Each layer
// returns a Result; findings carry stable codes that the diagnosis engine
// and the dns-diagnostics skill key off.
package checks

import (
	"encoding/json"
	"net/netip"
	"sort"
	"time"
)

type Status string

const (
	OK      Status = "OK"
	WARN    Status = "WARN"
	FAIL    Status = "FAIL"
	SKIPPED Status = "SKIPPED"
)

type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warn"
	Critical Severity = "fail"
)

// Layer identifiers, in execution order.
const (
	LayerRegistration = "registration"
	LayerNameservers  = "nameservers"
	LayerZone         = "zone"
	LayerReach        = "reachability"
	LayerWeb          = "web"
)

var LayerTitles = map[string]string{
	LayerRegistration: "Domain registration",
	LayerNameservers:  "Name servers",
	LayerZone:         "DNS zone",
	LayerReach:        "Reachability",
	LayerWeb:          "Website load",
}

var LayerOrder = []string{LayerRegistration, LayerNameservers, LayerZone, LayerReach, LayerWeb}

// Finding is one observation. Code is stable (see dns-diagnostics skill).
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Evidence string   `json:"evidence,omitempty"`
}

// Result is a layer's outcome.
type Result struct {
	Layer      string    `json:"layer"`
	Title      string    `json:"title"`
	Status     Status    `json:"status"`
	Summary    string    `json:"summary"`
	Findings   []Finding `json:"findings"`
	Details    any       `json:"details,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	// SkipReason is set when Status is SKIPPED.
	SkipReason string `json:"skip_reason,omitempty"`
	// Blocking means later layers cannot work and should be skipped.
	Blocking bool `json:"-"`
}

// UnmarshalJSON restores the typed Details for each layer, so stored
// reports render exactly like live ones.
func (r *Result) UnmarshalJSON(b []byte) error {
	type plain Result
	var tmp struct {
		plain
		Details json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	*r = Result(tmp.plain)
	if len(tmp.Details) == 0 || string(tmp.Details) == "null" {
		return nil
	}
	var d any
	switch r.Layer {
	case LayerRegistration:
		d = &RegistrationDetails{}
	case LayerNameservers:
		d = &NSDetails{}
	case LayerZone:
		d = &ZoneDetails{}
	case LayerReach:
		d = &ReachDetails{}
	case LayerWeb:
		d = &WebDetails{}
	default:
		var m any
		d = &m
	}
	if err := json.Unmarshal(tmp.Details, d); err != nil {
		return err
	}
	r.Details = d
	return nil
}

func NewResult(layer string) *Result {
	return &Result{Layer: layer, Title: LayerTitles[layer], Findings: []Finding{}, StartedAt: time.Now().UTC()}
}

// Add records a finding. Messages and evidence can embed data from the
// target's DNS/HTTP responses, so both are length-bounded.
func (r *Result) Add(code string, sev Severity, msg, evidence string) {
	if len(r.Findings) >= 100 {
		return
	}
	r.Findings = append(r.Findings, Finding{Code: code, Severity: sev, Message: truncate(msg, 600), Evidence: truncate(evidence, 1000)})
}

func (r *Result) Has(code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// Finish derives Status from findings (unless already SKIPPED) and sets duration.
func (r *Result) Finish(summary string) *Result {
	if r.Status != SKIPPED {
		r.Status = OK
		for _, f := range r.Findings {
			switch f.Severity {
			case Critical:
				r.Status = FAIL
			case Warning:
				if r.Status == OK {
					r.Status = WARN
				}
			}
		}
	}
	r.Summary = summary
	r.DurationMS = time.Since(r.StartedAt).Milliseconds()
	// Most severe first for display.
	rank := map[Severity]int{Critical: 0, Warning: 1, Info: 2}
	sort.SliceStable(r.Findings, func(i, j int) bool { return rank[r.Findings[i].Severity] < rank[r.Findings[j].Severity] })
	return r
}

func Skipped(layer, reason string) *Result {
	r := NewResult(layer)
	r.Status = SKIPPED
	r.SkipReason = reason
	return r.Finish("Skipped: " + reason)
}

// AuthServer is an authoritative name server address that answered with AA.
type AuthServer struct {
	Name string     `json:"name"`
	IP   netip.Addr `json:"ip"`
}

// State is passed between layers so later ones reuse earlier discoveries.
type State struct {
	Domain string // ASCII, the host the user asked about (www stripped)
	Apex   string // registrable domain

	Registered   bool
	OnHold       bool
	AuthServers  []AuthServer // usable authoritative servers (AA answers)
	ParentServer netip.Addr   // TLD server that returned the delegation (for DS)
	// ViaResolvers: direct DNS is unavailable (DoH mode); the zone layer
	// queries public resolvers instead of the authoritative servers.
	ViaResolvers bool

	// Address records found in the zone (pinned for reachability/web).
	ApexV4, ApexV6 []netip.Addr
	WWWV4, WWWV6   []netip.Addr
	WWWExists      bool
	CNAMEs         []string // CNAME targets of apex/www/sub (for CDN fingerprinting)

	// Website-load options (from /api/web-diagnose).
	OriginIP netip.Addr // optional user-supplied origin address (already validated public)
}

// Addrs returns the apex addresses (v4 then v6), falling back to www.
func (s *State) Addrs() []netip.Addr {
	out := append(append([]netip.Addr{}, s.ApexV4...), s.ApexV6...)
	if len(out) == 0 {
		out = append(append(out, s.WWWV4...), s.WWWV6...)
	}
	return out
}
