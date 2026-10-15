// Package api is the master's HTTP surface: the check API with SSE
// progress, node metadata, traceroute streaming, shareable reports,
// exports, and the embedded web UI.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"domaindoctor/internal/asn"
	"domaindoctor/internal/checks"
	"domaindoctor/internal/clientip"
	"domaindoctor/internal/input"
	"domaindoctor/internal/nodes"
	"domaindoctor/internal/orchestrator"
	"domaindoctor/internal/probe"
	"domaindoctor/internal/ratelimit"
	"domaindoctor/internal/report"
	"domaindoctor/internal/safenet"
)

type Config struct {
	Deps          orchestrator.Deps
	Registry      *nodes.Registry
	ClientIP      clientip.Extractor
	Store         *report.Store // nil: permanent links disabled
	ASN           *asn.DB       // nil: no hop enrichment
	UI            fs.FS         // static files (index.html at root)
	MaxConcurrent int           // global cap on running checks/traceroutes
	CheckTimeout  time.Duration
	Log           *log.Logger
}

type Server struct {
	cfg     Config
	jobs    *report.Cache[*Job]
	general *ratelimit.Limiter
	promote *ratelimit.Limiter
	gate    *ratelimit.KeyGate
	global  ratelimit.Semaphore
	streams *ratelimit.KeyGate // concurrent SSE streams per client
	promAll *ratelimit.Limiter // global promote budget across all clients
}

const (
	maxStreamsPerClient  = 4
	maxSubscribersPerJob = 32
	maxReportBytes       = 1 << 20 // larger reports are not promoted
)

func New(cfg Config) *Server {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 30
	}
	if cfg.CheckTimeout <= 0 {
		cfg.CheckTimeout = 3 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = log.New(io.Discard, "", 0)
	}
	cfg.Deps.Nodes = cfg.Registry.Live
	return &Server{
		cfg:     cfg,
		jobs:    report.NewCache[*Job](2000, 30*time.Minute),
		general: ratelimit.NewPerMinute(20, 5),
		promote: ratelimit.NewPerHour(10, 3),
		gate:    ratelimit.NewKeyGate(1),
		global:  ratelimit.NewSemaphore(cfg.MaxConcurrent),
		streams: ratelimit.NewKeyGate(maxStreamsPerClient),
		promAll: ratelimit.NewPerHour(300, 30),
	}
}

// Limiters exposes the limiters for tests.
func (s *Server) Limiters() (general, promote *ratelimit.Limiter) { return s.general, s.promote }

// StartBackground runs periodic cleanup until ctx is done.
func (s *Server) StartBackground(ctx context.Context) {
	ratelimit.StartCleanup(ctx.Done(), 5*time.Minute, s.general, s.promote)
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.jobs.Sweep()
				if s.cfg.Store != nil {
					s.cfg.Store.Sweep()
				}
			}
		}
	}()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/check", s.startCheck)
	mux.HandleFunc("POST /api/web-diagnose", s.webDiagnose)
	mux.HandleFunc("GET /api/check/{id}", s.getCheck)
	mux.HandleFunc("GET /api/nodes", s.getNodes)
	mux.HandleFunc("GET /api/traceroute", s.traceroute)
	mux.HandleFunc("POST /api/report/promote", s.promoteReport)
	mux.HandleFunc("GET /api/report", s.getReport)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })
	if s.cfg.UI != nil {
		files := http.FileServer(http.FS(s.cfg.UI))
		index := func(w http.ResponseWriter, r *http.Request) {
			b, err := fs.ReadFile(s.cfg.UI, "index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(b)
		}
		mux.HandleFunc("GET /{$}", index)
		mux.HandleFunc("GET /r/{id}", index)
		mux.HandleFunc("GET /c/{id}", index)
		mux.Handle("GET /static/", http.StripPrefix("/static/", files))
	}
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

const msgRateLimited = "rate limited — try again in a minute"

// ---- checks ----

func (s *Server) startCheck(w http.ResponseWriter, r *http.Request) { s.start(w, r, false) }

// webDiagnose is the Website Load entry point: the same pipeline, limits and
// reports as /api/check, plus an optional origin IP for the origin-direct test.
func (s *Server) webDiagnose(w http.ResponseWriter, r *http.Request) { s.start(w, r, true) }

func (s *Server) start(w http.ResponseWriter, r *http.Request, allowOrigin bool) {
	ip := s.cfg.ClientIP.Key(r)
	if !s.general.Allow(ip) {
		writeErr(w, http.StatusTooManyRequests, msgRateLimited)
		return
	}
	var body struct {
		Domain   string `json:"domain"`
		OriginIP string `json:"originIp"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	d, err := input.Normalize(body.Domain)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var opts orchestrator.Options
	if body.OriginIP != "" {
		if !allowOrigin {
			writeErr(w, http.StatusBadRequest, "originIp is only accepted by /api/web-diagnose")
			return
		}
		if opts.OriginIP, err = input.ParseOriginIP(body.OriginIP); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	release, ok := s.gate.TryAcquire(ip)
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "a check from your address is already running — wait for it to finish")
		return
	}
	releaseGlobal, ok := s.global.TryAcquire()
	if !ok {
		release()
		writeErr(w, http.StatusServiceUnavailable, "the server is busy — please try again shortly")
		return
	}
	id := report.NewID()
	job := newJob(id, d)
	s.jobs.Put(id, job)
	go func() {
		defer release()
		defer releaseGlobal()
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.CheckTimeout)
		defer cancel()
		defer func() {
			if p := recover(); p != nil {
				s.cfg.Log.Printf("check %s panicked: %v", id, p)
				job.publish(orchestrator.Event{Type: "done", Report: &orchestrator.Report{ID: id, Domain: d, Status: "error"}})
			}
		}()
		orchestrator.RunWith(ctx, s.cfg.Deps, d, id, opts, job.publish)
		s.cfg.Log.Printf("check %s done for %s", id, d.Name)
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{
		"request_id": id, "domain": d, "status": "running",
		"stream_url": "/api/check/" + id + "?stream=1",
	})
}

func (s *Server) job(id string) (*Job, bool) {
	if !report.ValidID(id) {
		return nil, false
	}
	return s.jobs.Get(id)
}

func (s *Server) getCheck(w http.ResponseWriter, r *http.Request) {
	j, ok := s.job(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "check not found or expired — please re-run it")
		return
	}
	q := r.URL.Query()
	if q.Get("stream") == "1" || strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		s.stream(w, r, j)
		return
	}
	rep := j.Snapshot()
	switch q.Get("format") {
	case "md", "markdown":
		if rep.Status != "done" {
			writeErr(w, http.StatusConflict, "the check is still running")
			return
		}
		writeMarkdown(w, rep, q.Get("download") == "1")
	default:
		if q.Get("download") == "1" {
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="netarget-%s.json"`, rep.Domain.Name))
		}
		writeJSON(w, http.StatusOK, rep)
	}
}

func writeMarkdown(w http.ResponseWriter, rep *orchestrator.Report, download bool) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	if download {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="netarget-%s.md"`, rep.Domain.Name))
	}
	io.WriteString(w, orchestrator.Markdown(rep))
}

func sseHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // disable nginx buffering
}

func sseEvent(w io.Writer, event string, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request, j *Job) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	release, ok := s.streams.TryAcquire(s.cfg.ClientIP.Key(r))
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "too many open progress streams from your address")
		return
	}
	defer release()
	hist, ch, unsub, ok := j.subscribe(maxSubscribersPerJob)
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "too many viewers for this check — use the JSON endpoint instead")
		return
	}
	defer unsub()
	sseHeaders(w)
	w.WriteHeader(http.StatusOK)
	sseEvent(w, "request_id", map[string]any{"request_id": j.ID, "domain": j.Domain, "layers": checks.LayerOrder, "titles": checks.LayerTitles})
	for _, e := range hist {
		sseEvent(w, e.Type, e)
		if e.Type == "done" {
			fl.Flush()
			return
		}
	}
	fl.Flush()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			sseEvent(w, e.Type, e)
			fl.Flush()
			if e.Type == "done" {
				return
			}
		case <-j.done:
			// Drain anything buffered, then send the final report.
			for {
				select {
				case e := <-ch:
					sseEvent(w, e.Type, e)
					if e.Type == "done" {
						fl.Flush()
						return
					}
					continue
				default:
				}
				break
			}
			sseEvent(w, "done", orchestrator.Event{Type: "done", Report: j.Report()})
			fl.Flush()
			return
		case <-ping.C:
			io.WriteString(w, ": keep-alive\n\n")
			fl.Flush()
		}
	}
}

func (s *Server) getNodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.cfg.Registry.PublicLive())
}

// ---- traceroute ----

type hopEvent struct {
	Line   string `json:"line"`
	Hop    int    `json:"hop,omitempty"`
	IP     string `json:"ip,omitempty"`
	ASN    string `json:"asn,omitempty"`
	ASName string `json:"as_name,omitempty"`
}

// traceroute streams a traceroute from one node to one of the IPs that a
// finished check already resolved and validated (no free-form targets).
func (s *Server) traceroute(w http.ResponseWriter, r *http.Request) {
	ip := s.cfg.ClientIP.Key(r)
	if !s.general.Allow(ip) {
		writeErr(w, http.StatusTooManyRequests, msgRateLimited)
		return
	}
	q := r.URL.Query()
	j, ok := s.job(q.Get("id"))
	if !ok || j.Report() == nil {
		writeErr(w, http.StatusNotFound, "run a check first; traceroute targets come from its results")
		return
	}
	target, err := netip.ParseAddr(q.Get("ip"))
	if err != nil || !targetInReport(j.Report(), target) {
		writeErr(w, http.StatusBadRequest, "ip must be one of the addresses found by the check")
		return
	}
	node, ok := s.cfg.Registry.Get(q.Get("node"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "unknown node")
		return
	}
	if !s.cfg.Registry.IsLive(node.ID) {
		writeErr(w, http.StatusBadGateway, "agent unreachable")
		return
	}
	maxHops, _ := strconv.Atoi(q.Get("maxhops"))
	if maxHops < 5 || maxHops > 64 {
		maxHops = 30
	}
	release, ok := s.gate.TryAcquire(ip)
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "another request from your address is still running")
		return
	}
	defer release()
	releaseGlobal, ok := s.global.TryAcquire()
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "the server is busy — please try again shortly")
		return
	}
	defer releaseGlobal()
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	sseHeaders(w)
	w.WriteHeader(http.StatusOK)
	sseEvent(w, "start", map[string]any{"node": nodes.Public{ID: node.ID, Name: node.Name, Location: node.Location}, "ip": target.String(), "max_hops": maxHops})
	fl.Flush()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	err = node.P.Traceroute(ctx, target, maxHops, func(line string) {
		ev := hopEvent{Line: line}
		if n, hip, ok := probe.HopIP(line); ok {
			ev.Hop, ev.IP = n, hip.String()
			if safenet.IsBlocked(hip) {
				// Hide the node's internal network layout (gateways, CGNAT).
				ev.IP, ev.Line = "", fmt.Sprintf("%2d  (private address hidden)", n)
			} else if rec, ok := s.cfg.ASN.Lookup(hip); ok {
				ev.ASN, ev.ASName = rec.ASN, rec.Name
			}
		}
		sseEvent(w, "hop", ev)
		fl.Flush()
	})
	if err != nil {
		msg := "agent unreachable"
		if errors.Is(err, probe.ErrNoTraceroute) || err.Error() == probe.ErrNoTraceroute.Error() {
			msg = probe.ErrNoTraceroute.Error()
		}
		sseEvent(w, "error", map[string]string{"error": msg})
	} else {
		sseEvent(w, "done", map[string]string{"status": "done"})
	}
	fl.Flush()
}

func targetInReport(rep *orchestrator.Report, ip netip.Addr) bool {
	for _, l := range rep.Layers {
		if d, ok := l.Details.(*checks.ReachDetails); ok {
			for _, t := range d.Targets {
				if t == ip.String() {
					return true
				}
			}
		}
	}
	return false
}

// ---- permanent links ----

func (s *Server) promoteReport(w http.ResponseWriter, r *http.Request) {
	ip := s.cfg.ClientIP.Key(r)
	if !s.promote.Allow(ip) || !s.promAll.Allow("all") {
		writeErr(w, http.StatusTooManyRequests, "too many permanent links requested — try again later")
		return
	}
	var body struct {
		RequestID string `json:"request_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !report.ValidID(body.RequestID) {
		writeErr(w, http.StatusBadRequest, "invalid request id")
		return
	}
	if s.cfg.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, "permanent links are unavailable")
		return
	}
	j, ok := s.jobs.Get(body.RequestID)
	if !ok || j.Report() == nil {
		writeErr(w, http.StatusNotFound, "this result is no longer available to make permanent — please re-run the check")
		return
	}
	data, err := json.Marshal(j.Report())
	if err == nil && len(data) > maxReportBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "this report is too large to store as a permanent link")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to save permanent link")
		return
	}
	id, err := s.cfg.Store.Save("check", j.Domain.Name, data)
	switch {
	case errors.Is(err, report.ErrFull):
		writeErr(w, http.StatusServiceUnavailable, "too many active shared links right now — please try again later")
	case err != nil:
		s.cfg.Log.Printf("promote: %v", err)
		writeErr(w, http.StatusInternalServerError, "failed to save permanent link")
	default:
		writeJSON(w, http.StatusOK, map[string]string{"id": id, "url": "/r/" + id})
	}
}

func (s *Server) getReport(w http.ResponseWriter, r *http.Request) {
	ip := s.cfg.ClientIP.Key(r)
	if !s.general.Allow(ip) {
		writeErr(w, http.StatusTooManyRequests, msgRateLimited)
		return
	}
	if s.cfg.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, "permanent links are unavailable")
		return
	}
	st, err := s.cfg.Store.Get(r.URL.Query().Get("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "report not found or expired")
		return
	}
	if f := r.URL.Query().Get("format"); f == "md" || f == "markdown" {
		var rep orchestrator.Report
		if err := json.Unmarshal(st.Data, &rep); err != nil {
			writeErr(w, http.StatusInternalServerError, "stored report is unreadable")
			return
		}
		writeMarkdown(w, &rep, r.URL.Query().Get("download") == "1")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, st)
}
