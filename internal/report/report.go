// Package report holds completed check results: an in-memory ephemeral cache
// keyed by request_id (capped, evicts oldest) and a disk-backed store of
// promoted "Permanent Link" reports (capped, rejects when full, 24h TTL).
package report

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// NewID returns 20 bytes of crypto/rand, hex encoded (40 chars, 160 bits).
func NewID() string {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// ValidID reports whether s is exactly 40 lowercase hex characters. It must
// be called before any client-supplied ID touches the filesystem.
func ValidID(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Cache is a capped in-memory map with a max age. At capacity it evicts the
// oldest entry: the client already received that result, so nothing they
// hold disappears. Get enforces the age itself (no stale-until-sweep gap).
type Cache[T any] struct {
	mu      sync.Mutex
	cap     int
	ttl     time.Duration
	entries map[string]cacheEntry[T]
	now     func() time.Time
}

type cacheEntry[T any] struct {
	v       T
	created time.Time
}

func NewCache[T any](capacity int, ttl time.Duration) *Cache[T] {
	return &Cache[T]{cap: capacity, ttl: ttl, entries: map[string]cacheEntry[T]{}, now: time.Now}
}

func (c *Cache[T]) SetClock(now func() time.Time) { c.now = now }

// Put stores v under id, evicting the oldest entry when full.
func (c *Cache[T]) Put(id string, v T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[id]; !ok && len(c.entries) >= c.cap {
		var oldID string
		var oldT time.Time
		for k, e := range c.entries {
			if oldID == "" || e.created.Before(oldT) {
				oldID, oldT = k, e.created
			}
		}
		delete(c.entries, oldID)
	}
	c.entries[id] = cacheEntry[T]{v: v, created: c.now()}
}

// Get returns the entry if present and younger than ttl.
func (c *Cache[T]) Get(id string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok || c.now().Sub(e.created) > c.ttl {
		var zero T
		return zero, false
	}
	return e.v, true
}

// Sweep removes expired entries.
func (c *Cache[T]) Sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, e := range c.entries {
		if now.Sub(e.created) > c.ttl {
			delete(c.entries, k)
		}
	}
}

func (c *Cache[T]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Stored is a promoted report as kept on disk and served by GET /api/report.
type Stored struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Target     string          `json:"target"`
	CapturedAt time.Time       `json:"captured_at"`
	Data       json.RawMessage `json:"data"`
}

var (
	ErrFull     = errors.New("report store is full")
	ErrNotFound = errors.New("report not found or expired")
)

// Store persists promoted reports as <dir>/<id>.json for ttl (from the
// captured_at stored inside the JSON, not file mtime).
type Store struct {
	mu  sync.Mutex
	dir string
	cap int
	ttl time.Duration
	idx map[string]time.Time // id -> captured_at
	now func() time.Time
}

// OpenStore creates dir if needed and indexes existing unexpired reports.
func OpenStore(dir string, capacity int, ttl time.Duration) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, cap: capacity, ttl: ttl, idx: map[string]time.Time{}, now: time.Now}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidID(id) {
			continue
		}
		r, err := s.read(id)
		if err != nil {
			continue
		}
		s.idx[id] = r.CapturedAt
	}
	s.Sweep()
	return s, nil
}

func (s *Store) SetClock(now func() time.Time) { s.now = now }

func (s *Store) path(id string) string { return filepath.Join(s.dir, id+".json") }

func (s *Store) read(id string) (*Stored, error) {
	b, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, err
	}
	var r Stored
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.ID != id {
		return nil, fmt.Errorf("id mismatch")
	}
	return &r, nil
}

// Save writes a new report under a fresh ID. It never evicts.
func (s *Store) Save(kind, target string, data json.RawMessage) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if len(s.idx) >= s.cap {
		return "", ErrFull
	}
	r := Stored{ID: NewID(), Kind: kind, Target: target, CapturedAt: s.now().UTC().Truncate(time.Second), Data: data}
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		return "", err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	if err := os.Rename(tmp.Name(), s.path(r.ID)); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	s.idx[r.ID] = r.CapturedAt
	return r.ID, nil
}

// Get returns an unexpired report. Invalid IDs are rejected before any path is built.
func (s *Store) Get(id string) (*Stored, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	s.mu.Lock()
	at, ok := s.idx[id]
	s.mu.Unlock()
	if !ok || s.now().Sub(at) > s.ttl {
		return nil, ErrNotFound
	}
	r, err := s.read(id)
	if err != nil {
		return nil, ErrNotFound
	}
	return r, nil
}

// Sweep deletes expired reports.
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
}

func (s *Store) sweepLocked() {
	now := s.now()
	for id, at := range s.idx {
		if now.Sub(at) > s.ttl {
			os.Remove(s.path(id))
			delete(s.idx, id)
		}
	}
}

func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.idx)
}
