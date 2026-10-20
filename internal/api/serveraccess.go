package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"domaindoctor/internal/report"
	"domaindoctor/internal/serveraccess"
)

// serverAccessReady reports whether the feature is configured (ports set).
func (s *Server) serverAccessReady() bool { return len(s.cfg.ServerAccess.Ports) > 0 }

// saTargetCode maps a target-parsing error to a stable error code.
func saTargetCode(err error) (code, msg string) {
	switch {
	case errors.Is(err, serveraccess.ErrEmpty):
		return "sa_empty", serveraccess.ErrEmpty.Error()
	case errors.Is(err, serveraccess.ErrTooLong):
		return "sa_too_long", serveraccess.ErrTooLong.Error()
	case errors.Is(err, serveraccess.ErrPrivate):
		return "sa_private", serveraccess.ErrPrivate.Error()
	case errors.Is(err, serveraccess.ErrReserved):
		return "sa_reserved", serveraccess.ErrReserved.Error()
	case errors.Is(err, serveraccess.ErrNoIP):
		return "sa_no_ip", serveraccess.ErrNoIP.Error()
	default:
		return "sa_invalid", serveraccess.ErrInvalid.Error()
	}
}

// serverAccess streams a server-accessibility check (identity, ping, ports)
// for one user-supplied IP or hostname. The operator must confirm they are
// authorized to check the target (authorized=1); every request is audit
// logged (client IP + target + time), never any secret.
//
//	GET /api/server-access?target=<ip|host>&authorized=1
func (s *Server) serverAccess(w http.ResponseWriter, r *http.Request) {
	ip := s.cfg.ClientIP.Key(r)
	if !s.general.Allow(ip) {
		writeErr(w, http.StatusTooManyRequests, msgRateLimited)
		return
	}
	if !s.serverAccessReady() {
		writeErrCode(w, http.StatusServiceUnavailable, "sa_disabled", "the server check is not enabled")
		return
	}
	q := r.URL.Query()
	if q.Get("authorized") != "1" {
		writeErrCode(w, http.StatusBadRequest, "sa_unauthorized", "confirm you are authorized to check this target")
		return
	}

	// Resolve/validate the target before taking any slot, so bad input is cheap.
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.CheckTimeout)
	defer cancel()
	target, err := serveraccess.ParseTarget(ctx, s.cfg.ServerAccess.Resolver, q.Get("target"))
	if err != nil {
		code, msg := saTargetCode(err)
		writeErrCode(w, http.StatusBadRequest, code, msg)
		return
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
	streamRelease, ok := s.streams.TryAcquire(ip)
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "too many open progress streams from your address")
		return
	}
	defer streamRelease()
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	id := report.NewID()
	// Audit log: who asked, for what, when. No secrets.
	s.cfg.Log.Printf("server-access %s target=%q from=%s at=%s", id, target.Input, ip, time.Now().UTC().Format(time.RFC3339))

	sseHeaders(w)
	w.WriteHeader(http.StatusOK)
	sseEvent(w, "meta", map[string]any{"id": id, "target": target.Input, "host": target.Host, "ports": s.cfg.ServerAccess.Ports})
	fl.Flush()

	ns := s.cfg.Registry.Live()
	serveraccess.Run(ctx, s.cfg.ServerAccess, target, ns, id, func(e serveraccess.Event) {
		sseEvent(w, e.Type, e)
		fl.Flush()
	})
}
