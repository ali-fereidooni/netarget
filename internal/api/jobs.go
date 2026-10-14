package api

import (
	"sync"

	"domaindoctor/internal/checks"
	"domaindoctor/internal/input"
	"domaindoctor/internal/orchestrator"
)

// Job is one check run. Events are kept so late SSE subscribers can replay.
type Job struct {
	ID     string
	Domain input.Domain

	mu     sync.Mutex
	events []orchestrator.Event
	layers []*checks.Result
	subs   map[chan orchestrator.Event]struct{}
	report *orchestrator.Report
	done   chan struct{}
}

func newJob(id string, d input.Domain) *Job {
	return &Job{ID: id, Domain: d, subs: map[chan orchestrator.Event]struct{}{}, done: make(chan struct{})}
}

// publish records an event and fans it out without blocking the check.
func (j *Job) publish(e orchestrator.Event) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.events = append(j.events, e)
	if e.Type == "layer_done" && e.Result != nil {
		j.layers = append(j.layers, e.Result)
	}
	if e.Type == "done" {
		j.report = e.Report
	}
	for ch := range j.subs {
		select {
		case ch <- e:
		default: // slow subscriber: it will notice via done and fetch the report
		}
	}
	if e.Type == "done" {
		close(j.done)
	}
}

// subscribe returns the history so far and a channel for later events.
// ok is false when the job already has max subscribers.
func (j *Job) subscribe(max int) (hist []orchestrator.Event, ch chan orchestrator.Event, unsub func(), ok bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.subs) >= max {
		return nil, nil, nil, false
	}
	hist = append([]orchestrator.Event{}, j.events...)
	ch = make(chan orchestrator.Event, 16)
	j.subs[ch] = struct{}{}
	return hist, ch, func() {
		j.mu.Lock()
		delete(j.subs, ch)
		j.mu.Unlock()
	}, true
}

// Report returns the final report or nil while running.
func (j *Job) Report() *orchestrator.Report {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.report
}

// Snapshot returns the final report, or a partial one while running.
func (j *Job) Snapshot() *orchestrator.Report {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.report != nil {
		return j.report
	}
	return &orchestrator.Report{ID: j.ID, Domain: j.Domain, Status: "running", Layers: append([]*checks.Result{}, j.layers...)}
}
