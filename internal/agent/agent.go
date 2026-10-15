// Package agent is the measurement-node HTTP API (server) and the master's
// client for it. Every request carries X-Agent-Secret; the agent re-validates
// all targets itself (pinned IPs must be public) rather than trusting the master.
// Over the public internet the agent serves HTTPS and the client pins its
// self-signed certificate by SHA-256 (tls.go).
package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"domaindoctor/internal/probe"
)

const SecretHeader = "X-Agent-Secret"

// ErrUnreachable is the only error text the master ever shows for agent failures.
var ErrUnreachable = errors.New("agent unreachable")

// Server exposes a probe.Prober over HTTP.
type Server struct {
	Secret string
	P      probe.Prober
	Log    *log.Logger
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	mux.HandleFunc("POST /v1/probe", s.probe)
	mux.HandleFunc("POST /v1/http", s.http)
	mux.HandleFunc("POST /v1/resources", s.resources)
	mux.HandleFunc("GET /v1/traceroute", s.traceroute)
	return s.auth(mux)
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(SecretHeader)
		if s.Secret == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.Secret)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) logf(format string, a ...any) {
	if s.Log != nil {
		s.Log.Printf(format, a...)
	}
}

func (s *Server) probe(w http.ResponseWriter, r *http.Request) {
	var req probe.ProbeRequest
	if !decode(w, r, &req) {
		return
	}
	resp, err := s.P.Probe(r.Context(), req)
	if err != nil {
		s.logf("probe rejected: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) http(w http.ResponseWriter, r *http.Request) {
	var req probe.HTTPRequest
	if !decode(w, r, &req) {
		return
	}
	resp, err := s.P.HTTP(r.Context(), req)
	if err != nil {
		s.logf("http rejected: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) traceroute(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(r.URL.Query().Get("ip"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	maxHops, _ := strconv.Atoi(r.URL.Query().Get("maxhops"))
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	err = s.P.Traceroute(r.Context(), ip.Unmap(), maxHops, func(line string) {
		fmt.Fprintf(w, "data: %s\n\n", sanitizeLine(line))
		fl.Flush()
	})
	if err != nil {
		s.logf("traceroute: %v", err)
		msg := "traceroute failed"
		if errors.Is(err, probe.ErrNoTraceroute) {
			msg = probe.ErrNoTraceroute.Error()
		}
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", msg)
	} else {
		io.WriteString(w, "event: done\ndata: done\n\n")
	}
	fl.Flush()
}

func sanitizeLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}

// Client talks to a remote agent and implements probe.Prober.
type Client struct {
	BaseURL string
	Secret  string
	Calls   *http.Client // request/response calls
	Stream  *http.Client // traceroute (long-lived)
}

// NewClient returns a client for an http:// agent, or an https:// agent with a
// publicly trusted certificate.
func NewClient(baseURL, secret string, timeout time.Duration) *Client {
	return NewPinnedClient(baseURL, secret, nil, timeout)
}

// NewPinnedClient is NewClient with the agent's TLS certificate pinned to the
// SHA-256 fingerprint pin (see ParseFingerprint). A mismatch fails the
// handshake, which surfaces as ErrUnreachable like every other failure.
// Callers must pair a pin with an https:// URL (nodes.Load enforces it).
func NewPinnedClient(baseURL, secret string, pin []byte, timeout time.Duration) *Client {
	// No proxies from the environment and no redirects: a redirect would
	// carry X-Agent-Secret to wherever the response points.
	tr := &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 8, IdleConnTimeout: 60 * time.Second,
		TLSClientConfig: clientTLSConfig(pin), TLSHandshakeTimeout: 10 * time.Second}
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"), Secret: secret,
		Calls:  &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: noRedirect},
		Stream: &http.Client{Transport: tr, CheckRedirect: noRedirect},
	}
}

func (c *Client) do(ctx context.Context, cl *http.Client, method, path string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return nil, ErrUnreachable
	}
	req.Header.Set(SecretHeader, c.Secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, ErrUnreachable
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, ErrUnreachable
	}
	return resp, nil
}

func (c *Client) postJSON(ctx context.Context, path string, in, out any) error {
	resp, err := c.do(ctx, c.Calls, http.MethodPost, path, in)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
		return ErrUnreachable
	}
	return nil
}

func (c *Client) Health(ctx context.Context) error {
	resp, err := c.do(ctx, c.Calls, http.MethodGet, "/health", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (c *Client) Probe(ctx context.Context, req probe.ProbeRequest) (*probe.ProbeResponse, error) {
	var out probe.ProbeResponse
	return &out, c.postJSON(ctx, "/v1/probe", req, &out)
}

func (c *Client) HTTP(ctx context.Context, req probe.HTTPRequest) (*probe.HTTPResponse, error) {
	var out probe.HTTPResponse
	return &out, c.postJSON(ctx, "/v1/http", req, &out)
}

func (c *Client) Traceroute(ctx context.Context, ip netip.Addr, maxHops int, line func(string)) error {
	q := url.Values{"ip": {ip.String()}, "maxhops": {strconv.Itoa(maxHops)}}
	resp, err := c.do(ctx, c.Stream, http.MethodGet, "/v1/traceroute?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	event := ""
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "event: "):
			event = strings.TrimPrefix(l, "event: ")
		case strings.HasPrefix(l, "data: "):
			data := strings.TrimPrefix(l, "data: ")
			switch event {
			case "error":
				return errors.New(data)
			case "done":
				return nil
			default:
				line(data)
			}
		case l == "":
			event = ""
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrUnreachable
}

func (s *Server) resources(w http.ResponseWriter, r *http.Request) {
	var req probe.ResourceRequest
	if !decode(w, r, &req) {
		return
	}
	resp, err := s.P.Resources(r.Context(), req)
	if err != nil {
		s.logf("resources rejected: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (c *Client) Resources(ctx context.Context, req probe.ResourceRequest) (*probe.ResourceResponse, error) {
	var out probe.ResourceResponse
	return &out, c.postJSON(ctx, "/v1/resources", req, &out)
}
