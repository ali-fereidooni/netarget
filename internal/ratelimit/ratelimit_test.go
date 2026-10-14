package ratelimit

import (
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestLimiterBurstAndRefill(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	l := NewPerMinute(6, 3) // one token per 10s
	l.SetClock(c.now)
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("burst request %d denied", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("4th request allowed beyond burst")
	}
	if !l.Allow("b") {
		t.Fatal("other key affected")
	}
	c.advance(9 * time.Second)
	if l.Allow("a") {
		t.Fatal("refilled too early")
	}
	c.advance(1 * time.Second)
	if !l.Allow("a") {
		t.Fatal("not refilled after 10s")
	}
	c.advance(time.Hour)
	for i := 0; i < 3; i++ {
		l.Allow("a")
	}
	if l.Allow("a") {
		t.Fatal("refill exceeded burst cap")
	}
}

func TestPerHour(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	l := NewPerHour(10, 3)
	l.SetClock(c.now)
	for i := 0; i < 3; i++ {
		if !l.Allow("ip") {
			t.Fatal("burst denied")
		}
	}
	if l.Allow("ip") {
		t.Fatal("over burst")
	}
	c.advance(5 * time.Minute)
	if l.Allow("ip") {
		t.Fatal("refilled before 6 minutes")
	}
	c.advance(61 * time.Second)
	if !l.Allow("ip") {
		t.Fatal("not refilled after 6 minutes")
	}
}

func TestCleanup(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	l := NewPerMinute(20, 5)
	l.SetClock(c.now)
	l.Allow("x")
	c.advance(31 * time.Minute)
	l.Allow("y")
	l.Cleanup()
	if l.Len() != 1 {
		t.Fatalf("len = %d, want 1", l.Len())
	}
}

func TestKeyGate(t *testing.T) {
	g := NewKeyGate(1)
	rel, ok := g.TryAcquire("1.2.3.4")
	if !ok {
		t.Fatal("first acquire failed")
	}
	if _, ok := g.TryAcquire("1.2.3.4"); ok {
		t.Fatal("second concurrent acquire allowed")
	}
	if _, ok := g.TryAcquire("5.6.7.8"); !ok {
		t.Fatal("other key blocked")
	}
	rel()
	rel() // idempotent
	if _, ok := g.TryAcquire("1.2.3.4"); !ok {
		t.Fatal("acquire after release failed")
	}
}

func TestSemaphoreConcurrent(t *testing.T) {
	s := NewSemaphore(5)
	var mu sync.Mutex
	got := 0
	var wg sync.WaitGroup
	var rels []func()
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rel, ok := s.TryAcquire(); ok {
				mu.Lock()
				got++
				rels = append(rels, rel)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if got != 5 {
		t.Fatalf("acquired %d, want 5", got)
	}
	for _, r := range rels {
		r()
	}
	if _, ok := s.TryAcquire(); !ok {
		t.Fatal("not released")
	}
}
