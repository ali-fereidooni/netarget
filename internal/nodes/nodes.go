// Package nodes holds the measurement-node registry, background liveness
// tracking, and bounded parallel fan-out.
package nodes

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"

	"domaindoctor/internal/agent"
	"domaindoctor/internal/probe"
)

// Node is one measurement location. URL and secret never leave the master.
type Node struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`

	P      probe.Prober `json:"-"` // probes
	health probe.Prober // dedicated client for /health (separate timeout/pool)
}

// Public is the only node data exposed to clients.
type Public struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
}

type fileNode struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Location  string `json:"location"`
	URL       string `json:"url"`
	SecretEnv string `json:"secret_env,omitempty"` // env var holding this node's secret; default AGENT_SECRET
	// CertSHA256 pins an https agent's (self-signed) certificate. Not a
	// secret: it is the public cert's fingerprint.
	CertSHA256 string `json:"cert_sha256,omitempty"`
}

type liveness struct {
	fails int
	live  bool
}

// Registry is immutable node metadata plus separately tracked liveness.
type Registry struct {
	nodes []*Node
	mu    sync.RWMutex
	state map[string]*liveness
	Log   *log.Logger
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// New builds a registry from ready-made nodes (tests, single-node mode).
func New(ns ...*Node) *Registry {
	r := &Registry{nodes: ns, state: map[string]*liveness{}}
	for _, n := range ns {
		if n.health == nil {
			n.health = n.P
		}
		r.state[n.ID] = &liveness{live: true} // live until proven otherwise
	}
	return r
}

// LocalNode is the in-process agent used in single-node mode and by the CLI.
func LocalNode(name, location string, p probe.Prober) *Node {
	return &Node{ID: "local", Name: name, Location: location, P: p}
}

// Load reads a node registry file. Secrets come from the environment only.
func Load(path string, getenv func(string) string) (*Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Nodes []fileNode `json:"nodes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("nodes file: %w", err)
	}
	seen := map[string]bool{}
	var ns []*Node
	for _, fn := range doc.Nodes {
		if !idRe.MatchString(fn.ID) || seen[fn.ID] {
			return nil, fmt.Errorf("nodes file: invalid or duplicate id %q", fn.ID)
		}
		seen[fn.ID] = true
		u, err := url.Parse(fn.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("nodes file: node %s has an invalid url", fn.ID)
		}
		var pin []byte
		if fn.CertSHA256 != "" {
			// A pin on an http:// URL would be silently ignored and the
			// secret would still travel in clear text.
			if u.Scheme != "https" {
				return nil, fmt.Errorf("nodes file: node %s: cert_sha256 needs an https:// url", fn.ID)
			}
			if pin, err = agent.ParseFingerprint(fn.CertSHA256); err != nil {
				return nil, fmt.Errorf("nodes file: node %s: %v", fn.ID, err)
			}
		}
		env := fn.SecretEnv
		if env == "" {
			env = "AGENT_SECRET"
		}
		secret := getenv(env)
		if len(secret) < 32 {
			return nil, fmt.Errorf("nodes file: node %s: %s must hold the agent secret (32-byte hex, e.g. openssl rand -hex 32)", fn.ID, env)
		}
		if fn.Name == "" {
			fn.Name = fn.ID
		}
		n := &Node{ID: fn.ID, Name: fn.Name, Location: fn.Location,
			P:      agent.NewPinnedClient(fn.URL, secret, pin, 45*time.Second),
			health: agent.NewPinnedClient(fn.URL, secret, pin, 3*time.Second),
		}
		ns = append(ns, n)
	}
	if len(ns) == 0 {
		return nil, fmt.Errorf("nodes file: no nodes defined")
	}
	return New(ns...), nil
}

func (r *Registry) All() []*Node { return r.nodes }

func (r *Registry) IsLive(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.state[id]
	return ok && s.live
}

// Live returns live nodes in registry order.
func (r *Registry) Live() []*Node {
	var out []*Node
	for _, n := range r.nodes {
		if r.IsLive(n.ID) {
			out = append(out, n)
		}
	}
	return out
}

// Get returns a node by id (live or not).
func (r *Registry) Get(id string) (*Node, bool) {
	for _, n := range r.nodes {
		if n.ID == id {
			return n, true
		}
	}
	return nil, false
}

// PublicLive lists live nodes' public metadata only.
func (r *Registry) PublicLive() []Public {
	out := []Public{}
	for _, n := range r.Live() {
		out = append(out, Public{ID: n.ID, Name: n.Name, Location: n.Location})
	}
	return out
}

// CheckOnce health-checks every node in parallel. A node becomes dead after
// 2 consecutive failures and live again after 1 success.
func (r *Registry) CheckOnce(ctx context.Context, timeout time.Duration) {
	var wg sync.WaitGroup
	for _, n := range r.nodes {
		wg.Add(1)
		go func(n *Node) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			err := n.health.Health(cctx)
			cancel()
			r.mu.Lock()
			defer r.mu.Unlock()
			s := r.state[n.ID]
			if err == nil {
				if !s.live && r.Log != nil {
					r.Log.Printf("node %s is live again", n.ID)
				}
				s.fails, s.live = 0, true
				return
			}
			s.fails++
			if s.fails >= 2 && s.live {
				s.live = false
				if r.Log != nil {
					r.Log.Printf("node %s marked dead after %d failed health checks", n.ID, s.fails)
				}
			}
		}(n)
	}
	wg.Wait()
}

// StartHealthChecker runs an immediate check, then one every interval.
func (r *Registry) StartHealthChecker(ctx context.Context, interval, timeout time.Duration) {
	go func() {
		r.CheckOnce(ctx, timeout)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.CheckOnce(ctx, timeout)
			}
		}
	}()
}

// Fanout runs fn for every node with at most limit in flight and returns
// results in node order.
func Fanout[T any](ctx context.Context, ns []*Node, limit int, fn func(context.Context, *Node) T) []T {
	if limit <= 0 {
		limit = 8
	}
	out := make([]T, len(ns))
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i, n := range ns {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, n *Node) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = fn(ctx, n)
		}(i, n)
	}
	wg.Wait()
	return out
}
