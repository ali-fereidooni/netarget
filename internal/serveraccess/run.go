package serveraccess

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"domaindoctor/internal/nodes"
	"domaindoctor/internal/probe"
)

// maxWebSummaries caps how many open web ports get a TLS/HTTP summary, so one
// check never fans out into many extra requests.
const maxWebSummaries = 4

// Run executes the three stages in order, emitting an Event after each so the
// UI can show progress, and returns the assembled report. emit may be nil.
// ns are the live measurement nodes (the measurement providers).
func Run(ctx context.Context, deps Deps, t Target, ns []*nodes.Node, id string, emit func(Event)) *Report {
	if emit == nil {
		emit = func(Event) {}
	}
	rep := &Report{
		ID: id, Target: t.Input, Host: t.Host, Status: StatusRunning,
		StartedAt: deps.now().UTC(), Ports: deps.Ports,
	}
	emit(Event{Type: "start", Target: t.Input, Host: t.Host, Ports: deps.Ports})

	// Stage 1: identity.
	rep.Identity = deps.identity(ctx, t)
	emit(Event{Type: "identity", Identity: rep.Identity})

	ips := t.probeIPs()

	// Stages 2+3 share one measurement fan-out per node.
	per := nodes.Fanout(ctx, ns, 8, func(ctx context.Context, n *nodes.Node) nodeResult {
		cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		resp, err := n.P.Probe(cctx, probe.ProbeRequest{Host: t.Host, IPs: ips, PingCount: 4, Ports: deps.Ports})
		return nodeResult{node: n, resp: resp, err: err}
	})

	rep.Ping = buildPingStage(ns, ips, per)
	emit(Event{Type: "ping", Ping: rep.Ping})

	rep.Services = buildPortStage(ips, deps.Ports, per)
	addWebSummaries(ctx, ns, rep.Services, deps.Ports)
	emit(Event{Type: "services", Services: rep.Services})

	fin := deps.now().UTC()
	rep.FinishedAt, rep.Status = &fin, StatusDone
	emit(Event{Type: "done", Report: rep})
	return rep
}

type nodeResult struct {
	node *nodes.Node
	resp *probe.ProbeResponse
	err  error
}

func buildPingStage(ns []*nodes.Node, ips []netip.Addr, per []nodeResult) *PingStage {
	st := &PingStage{Rows: []PingRow{}}
	nodeUp := map[string]bool{}
	nodeSeen := map[string]bool{}
	for _, nr := range per {
		n := nr.node
		for i, ip := range ips {
			row := PingRow{NodeID: n.ID, Node: n.Name, Location: n.Location, IP: ip.String(), Family: family(ip)}
			switch {
			case nr.err != nil || nr.resp == nil || i >= len(nr.resp.Results):
				row.Status, row.Note = "error", "node unreachable"
			default:
				res := nr.resp.Results[i]
				if res.Skipped != "" {
					row.Status, row.Note = "n/a", res.Skipped
					break
				}
				nodeSeen[n.ID] = true
				if res.Ping != nil {
					row.Sent, row.Received, row.Loss = res.Ping.Sent, res.Ping.Received, res.Ping.Loss
					row.RTTMin, row.RTTAvg, row.RTTMax = res.Ping.RTTMin, res.Ping.RTTAvg, res.Ping.RTTMax
				} else {
					row.PingError = res.PingError
				}
				tcpAnswer := false
				for _, tr := range res.TCP {
					if tr.Status == "open" || tr.Status == "closed" {
						tcpAnswer = true
					}
				}
				switch {
				case res.Ping != nil && res.Ping.Received > 0:
					row.Status = "ok"
					if res.Ping.Loss > 0 {
						row.Note = fmt.Sprintf("%.0f%% packet loss", res.Ping.Loss)
					}
					nodeUp[n.ID] = true
				case tcpAnswer:
					row.Status, row.Note = "icmp_blocked", "ICMP filtered, TCP answers"
					nodeUp[n.ID] = true
				default:
					row.Status = "down"
				}
			}
			st.Rows = append(st.Rows, row)
		}
	}
	st.TotalNodes = len(nodeSeen)
	st.ReachableNodes = len(nodeUp)
	switch {
	case st.TotalNodes == 0:
		st.Summary = "No measurement node could test the target."
	case st.ReachableNodes == 0:
		st.Summary = fmt.Sprintf("Unreachable from all %d node(s).", st.TotalNodes)
	default:
		st.Summary = fmt.Sprintf("Reachable from %d of %d node(s).", st.ReachableNodes, st.TotalNodes)
	}
	return st
}

func buildPortStage(ips []netip.Addr, ports []int, per []nodeResult) *PortStage {
	st := &PortStage{Rows: []PortRow{}}
	// Aggregate each (ip, port) across nodes.
	for _, ip := range ips {
		for _, port := range ports {
			row := PortRow{IP: ip.String(), Family: family(ip), Port: port, Service: serviceName(port)}
			var minLatency float64 = -1
			states := map[string]int{}
			for _, nr := range per {
				if nr.err != nil || nr.resp == nil {
					continue
				}
				res := findResult(nr.resp, ip)
				if res == nil || res.Skipped != "" {
					continue
				}
				for _, tr := range res.TCP {
					if tr.Port != port {
						continue
					}
					row.Nodes++
					states[tr.Status]++
					if tr.Status == "open" {
						row.OpenFrom++
						if minLatency < 0 || tr.LatencyMS < minLatency {
							minLatency = tr.LatencyMS
						}
					}
				}
			}
			if minLatency >= 0 {
				row.LatencyMS = minLatency
			}
			row.State = aggregateState(states, row.Nodes)
			st.Rows = append(st.Rows, row)
		}
	}
	// Order rows by IP then port for stable display.
	sort.SliceStable(st.Rows, func(i, j int) bool {
		if st.Rows[i].IP != st.Rows[j].IP {
			return st.Rows[i].IP < st.Rows[j].IP
		}
		return st.Rows[i].Port < st.Rows[j].Port
	})
	open := 0
	for _, r := range st.Rows {
		if r.State == "open" || r.State == "mixed" {
			open++
		}
	}
	st.Summary = fmt.Sprintf("%d of %d port(s) reachable.", open, len(st.Rows))
	return st
}

// aggregateState collapses the per-node states for one port into one label:
// open if open anywhere, mixed if open from some nodes but not all, closed if
// any node got a RST, else filtered. No measurement => "unknown".
func aggregateState(states map[string]int, nodes int) string {
	if nodes == 0 {
		return "unknown"
	}
	switch {
	case states["open"] == nodes:
		return "open"
	case states["open"] > 0:
		return "mixed"
	case states["closed"] > 0:
		return "closed"
	default:
		return "filtered"
	}
}

func findResult(resp *probe.ProbeResponse, ip netip.Addr) *probe.IPProbe {
	for i := range resp.Results {
		if resp.Results[i].IP == ip {
			return &resp.Results[i]
		}
	}
	return nil
}

// addWebSummaries fetches a light TLS/HTTP summary for open web ports from the
// first live node, best-effort (failures are left empty). GET/HEAD only.
func addWebSummaries(ctx context.Context, ns []*nodes.Node, st *PortStage, ports []int) {
	if len(ns) == 0 {
		return
	}
	n := ns[0]
	done := 0
	for i := range st.Rows {
		r := &st.Rows[i]
		if done >= maxWebSummaries {
			return
		}
		if (r.State != "open" && r.State != "mixed") || !isWebPort(r.Port) {
			continue
		}
		done++
		scheme := "http"
		if r.Port == 443 || r.Port == 8443 {
			scheme = "https"
		}
		host := r.IP
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		u := fmt.Sprintf("%s://%s:%d/", scheme, host, r.Port)
		ip, _ := netip.ParseAddr(r.IP)
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		resp, err := n.P.HTTP(cctx, probe.HTTPRequest{URLs: []string{u}, Pinned: map[string][]netip.Addr{host: {ip}}, MaxHops: 1})
		cancel()
		if err != nil || resp == nil || len(resp.Chains) == 0 {
			r.HTTP = &HTTPSummary{Error: "no response"}
			continue
		}
		hop := resp.Chains[0].Final()
		if hop == nil {
			r.HTTP = &HTTPSummary{Error: "no response"}
			continue
		}
		r.HTTP = &HTTPSummary{Status: hop.Status, StatusText: hop.StatusText, Server: hop.Server}
		if hop.ErrorKind != "" {
			r.HTTP.Error = hop.ErrorKind
		}
		if hop.TLS != nil {
			na := hop.TLS.NotAfter
			r.TLS = &TLSSummary{
				Version: hop.TLS.Version, Subject: hop.TLS.Subject, Issuer: hop.TLS.Issuer,
				NotAfter: &na, DaysLeft: hop.TLS.DaysLeft, SANsCount: len(hop.TLS.SANs),
			}
		}
	}
}
