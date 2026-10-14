// Package orchestrator runs the five layers in order, applies skip logic,
// emits progress events, and assembles the final report with its diagnosis.
package orchestrator

import (
	"context"
	"fmt"
	"time"

	"domaindoctor/internal/checks"
	"domaindoctor/internal/diagnose"
	"domaindoctor/internal/dnsx"
	"domaindoctor/internal/input"
	"domaindoctor/internal/nodes"
)

// Deps are the external dependencies of a check run.
type Deps struct {
	DNS   *dnsx.Client
	RDAP  checks.RegLookup
	WHOIS checks.RegLookup
	Nodes func() []*nodes.Node
	ASN   checks.ASNLookup
	Now   func() time.Time
}

// Report is the full result of one check, as served by the API and exported.
type Report struct {
	ID         string              `json:"request_id"`
	Domain     input.Domain        `json:"domain"`
	Status     string              `json:"status"` // running, done
	StartedAt  time.Time           `json:"started_at"`
	FinishedAt *time.Time          `json:"finished_at,omitempty"`
	Nodes      []nodes.Public      `json:"nodes"`
	Layers     []*checks.Result    `json:"layers"`
	Diagnosis  *diagnose.Diagnosis `json:"diagnosis,omitempty"`
}

// Event is a progress update streamed to clients.
type Event struct {
	Type   string         `json:"type"` // layer_start, layer_done, done
	Layer  string         `json:"layer,omitempty"`
	Title  string         `json:"title,omitempty"`
	Result *checks.Result `json:"result,omitempty"`
	Report *Report        `json:"report,omitempty"`
}

// Run executes all layers. emit is called synchronously for every event.
func Run(ctx context.Context, deps Deps, d input.Domain, id string, emit func(Event)) *Report {
	now := time.Now
	if deps.Now != nil {
		now = deps.Now
	}
	var ns []*nodes.Node
	if deps.Nodes != nil {
		ns = deps.Nodes()
	}
	rep := &Report{ID: id, Domain: d, Status: "running", StartedAt: now().UTC(), Nodes: []nodes.Public{}, Layers: []*checks.Result{}}
	for _, n := range ns {
		rep.Nodes = append(rep.Nodes, nodes.Public{ID: n.ID, Name: n.Name, Location: n.Location})
	}
	st := &checks.State{Domain: d.Name, Apex: d.Apex}
	blockedBy := ""

	run := func(layer string, fn func() *checks.Result) {
		var r *checks.Result
		if blockedBy != "" {
			r = checks.Skipped(layer, blockedBy)
		} else {
			emit(Event{Type: "layer_start", Layer: layer, Title: checks.LayerTitles[layer]})
			if ctx.Err() != nil {
				r = checks.Skipped(layer, "the check was cancelled or timed out")
			} else {
				r = fn()
			}
			if r.Blocking {
				blockedBy = fmt.Sprintf("%s failed (%s)", checks.LayerTitles[layer], r.Summary)
			}
		}
		rep.Layers = append(rep.Layers, r)
		emit(Event{Type: "layer_done", Layer: layer, Result: r})
	}

	run(checks.LayerRegistration, func() *checks.Result {
		return checks.Registration(ctx, st, deps.RDAP, deps.WHOIS, now())
	})
	run(checks.LayerNameservers, func() *checks.Result {
		return checks.Nameservers(ctx, st, deps.DNS, deps.ASN)
	})
	run(checks.LayerZone, func() *checks.Result {
		return checks.Zone(ctx, st, deps.DNS, now())
	})
	run(checks.LayerReach, func() *checks.Result {
		return checks.Reach(ctx, st, ns)
	})
	run(checks.LayerWeb, func() *checks.Result {
		return checks.Web(ctx, st, ns, now())
	})

	rep.Diagnosis = diagnose.Diagnose(rep.Layers)
	fin := now().UTC()
	rep.FinishedAt, rep.Status = &fin, "done"
	emit(Event{Type: "done", Report: rep})
	return rep
}
