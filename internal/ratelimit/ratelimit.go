// Package ratelimit provides the in-process abuse controls: a per-key token
// bucket, a per-key single-active-job gate, and a global concurrency cap.
package ratelimit

import (
	"sync"
	"time"
)

const idleTTL = 30 * time.Minute

// Limiter is a per-key token bucket.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewPerMinute allows rpm sustained requests per minute with the given burst.
func NewPerMinute(rpm, burst int) *Limiter { return newLimiter(float64(rpm)/60, burst) }

// NewPerHour allows rph sustained requests per hour; needed because a
// sub-1/minute rate cannot be expressed with an integer rpm.
func NewPerHour(rph, burst int) *Limiter { return newLimiter(float64(rph)/3600, burst) }

func newLimiter(rate float64, burst int) *Limiter {
	if burst < 1 {
		burst = 1
	}
	return &Limiter{rate: rate, burst: float64(burst), buckets: map[string]*bucket{}, now: time.Now}
}

// SetClock replaces the time source (tests).
func (l *Limiter) SetClock(now func() time.Time) { l.now = now }

// Allow consumes one token for key if available.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Cleanup removes buckets idle for longer than 30 minutes.
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := l.now().Add(-idleTTL)
	for k, b := range l.buckets {
		if b.last.Before(cut) {
			delete(l.buckets, k)
		}
	}
}

// Len returns the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// KeyGate allows at most n concurrent holders per key (n=1: one active
// subprocess-backed job per client IP).
type KeyGate struct {
	mu     sync.Mutex
	n      int
	active map[string]int
}

func NewKeyGate(n int) *KeyGate { return &KeyGate{n: n, active: map[string]int{}} }

// TryAcquire returns a release func and true, or nil and false if key is at capacity.
func (g *KeyGate) TryAcquire(key string) (func(), bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active[key] >= g.n {
		return nil, false
	}
	g.active[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			if g.active[key]--; g.active[key] <= 0 {
				delete(g.active, key)
			}
		})
	}, true
}

// Semaphore is a global non-blocking concurrency cap.
type Semaphore chan struct{}

func NewSemaphore(n int) Semaphore { return make(Semaphore, n) }

// TryAcquire returns a release func and true, or nil and false when full.
func (s Semaphore) TryAcquire() (func(), bool) {
	select {
	case s <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-s }) }, true
	default:
		return nil, false
	}
}

// StartCleanup runs Cleanup on every limiter every interval until stop closes.
func StartCleanup(stop <-chan struct{}, interval time.Duration, ls ...*Limiter) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				for _, l := range ls {
					l.Cleanup()
				}
			}
		}
	}()
}
