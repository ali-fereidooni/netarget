package checks

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"domaindoctor/internal/nodes"
	"domaindoctor/internal/probe"
)

type ReachRow struct {
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
	TCP80     string  `json:"tcp_80"`
	TCP443    string  `json:"tcp_443"`
	Status    string  `json:"status"` // ok, icmp_blocked, down, error
	Note      string  `json:"note,omitempty"`
}

type ReachDetails struct {
	Targets []string   `json:"targets"`
	Rows    []ReachRow `json:"rows"`
}

// reachTargets picks up to 2 IPv4 and 2 IPv6 addresses.
func reachTargets(st *State) []netip.Addr {
	var v4, v6 []netip.Addr
	for _, a := range st.Addrs() {
		if a.Is4() && len(v4) < 2 {
			v4 = append(v4, a)
		} else if a.Is6() && len(v6) < 2 {
			v6 = append(v6, a)
		}
	}
	return append(v4, v6...)
}

// Reach pings and TCP-connects (80/443) the pinned addresses from every live node.
func Reach(ctx context.Context, st *State, ns []*nodes.Node) *Result {
	targets := reachTargets(st)
	if len(targets) == 0 {
		return Skipped(LayerReach, "the domain has no A/AAAA records to test")
	}
	if len(ns) == 0 {
		return Skipped(LayerReach, "no measurement nodes are available")
	}
	r := NewResult(LayerReach)
	det := &ReachDetails{}
	r.Details = det
	for _, t := range targets {
		det.Targets = append(det.Targets, t.String())
	}

	per := nodes.Fanout(ctx, ns, 8, func(ctx context.Context, n *nodes.Node) []ReachRow {
		cctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		resp, err := n.P.Probe(cctx, probe.ProbeRequest{Host: st.Domain, IPs: targets, PingCount: 4, Ports: []int{80, 443}})
		rows := make([]ReachRow, 0, len(targets))
		for i, t := range targets {
			row := ReachRow{NodeID: n.ID, Node: n.Name, Location: n.Location, IP: t.String(), Family: family(t)}
			if err != nil || resp == nil || i >= len(resp.Results) {
				row.Status, row.Note = "error", "agent unreachable"
				rows = append(rows, row)
				continue
			}
			res := resp.Results[i]
			if res.Skipped != "" {
				row.Status, row.Note = "n/a", res.Skipped
				rows = append(rows, row)
				continue
			}
			if res.Ping != nil {
				row.Sent, row.Received, row.Loss = res.Ping.Sent, res.Ping.Received, res.Ping.Loss
				row.RTTMin, row.RTTAvg, row.RTTMax = res.Ping.RTTMin, res.Ping.RTTAvg, res.Ping.RTTMax
			} else {
				row.PingError = res.PingError
			}
			tcpAnswer := false
			for _, tr := range res.TCP {
				switch tr.Port {
				case 80:
					row.TCP80 = tr.Status
				case 443:
					row.TCP443 = tr.Status
				}
				if tr.Status == "open" || tr.Status == "closed" {
					tcpAnswer = true
				}
			}
			icmp := res.Ping != nil && res.Ping.Received > 0
			switch {
			case icmp:
				row.Status = "ok"
				if res.Ping.Loss > 0 {
					row.Note = fmt.Sprintf("%.0f%% packet loss", res.Ping.Loss)
				}
			case tcpAnswer:
				row.Status, row.Note = "icmp_blocked", "ICMP filtered, TCP answers"
			default:
				row.Status = "down"
			}
			rows = append(rows, row)
		}
		return rows
	})
	for _, rows := range per {
		det.Rows = append(det.Rows, rows...)
	}

	// Evaluate.
	var measured, reachable, icmpOK, tcpOpen int
	nodeUp := map[string]bool{}
	nodeSeen := map[string]bool{}
	v4Up, v6Up, v6Seen := false, false, false
	for _, row := range det.Rows {
		if row.Status == "error" || row.Status == "n/a" {
			continue
		}
		measured++
		nodeSeen[row.Node] = true
		up := row.Status == "ok" || row.Status == "icmp_blocked"
		if up {
			reachable++
			nodeUp[row.Node] = true
			if row.Family == "IPv4" {
				v4Up = true
			} else {
				v6Up = true
			}
		}
		if row.Family == "IPv6" {
			v6Seen = true
		}
		if row.Status == "ok" {
			icmpOK++
		}
		if row.TCP80 == "open" || row.TCP443 == "open" {
			tcpOpen++
		}
	}
	if measured == 0 {
		r.Add("reach.no_data", Warning, "No measurement node could run the reachability test.", "all agents unreachable")
		return r.Finish("No measurements")
	}
	if reachable == 0 {
		r.Add("reach.down_all", Critical,
			"The server does not respond to ping or to TCP on ports 80/443 from any measurement node: the host is down, firewalled, or the A/AAAA record points to the wrong address.",
			"targets: "+strings.Join(det.Targets, ", "))
		r.Blocking = true
		return r.Finish("Host unreachable from all nodes")
	}
	if icmpOK == 0 {
		r.Add("reach.icmp_blocked", Info, "Ping (ICMP) is blocked, but the server answers on TCP — this is normal for many firewalls and not a problem.", "")
	}
	var down []string
	for n := range nodeSeen {
		if !nodeUp[n] {
			down = append(down, n)
		}
	}
	if len(down) > 0 {
		r.Add("reach.partial", Warning,
			"Some measurement nodes reach the server and others do not: a regional routing problem, geo-blocking, or a firewall rule.",
			"unreachable from: "+strings.Join(sortStrings(down), ", "))
	}
	if v6Seen && !v6Up && v4Up {
		r.Add("reach.v6_broken", Warning,
			"The domain publishes IPv6 (AAAA) but the IPv6 address is unreachable from every node, while IPv4 works. IPv6 users will see delays or failures.",
			"")
	}
	if tcpOpen == 0 {
		r.Add("reach.web_ports_closed", Warning, "The host answers, but neither port 80 nor 443 is open from any node.", "")
	}
	return r.Finish(fmt.Sprintf("Reachable from %d of %d node(s)", len(nodeUp), len(nodeSeen)))
}

func family(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}

func sortStrings(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}
