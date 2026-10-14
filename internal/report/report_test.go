package report

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIDs(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewID()
		if !ValidID(id) {
			t.Fatalf("invalid id %q", id)
		}
		if seen[id] {
			t.Fatal("duplicate id")
		}
		seen[id] = true
	}
	for _, bad := range []string{"", "../../etc/passwd", "ABCDEF0123456789abcdef0123456789abcdef01",
		"0123456789abcdef0123456789abcdef0123456", "0123456789abcdef0123456789abcdef012345678",
		"0123456789abcdef0123456789abcdef0123456/", "..\\..\\windows\\system32\\config\\sam0000000"} {
		if ValidID(bad) {
			t.Errorf("ValidID(%q) = true", bad)
		}
	}
}

func TestCacheEvictsOldestAndExpires(t *testing.T) {
	now := time.Unix(0, 0)
	c := NewCache[int](3, 30*time.Minute)
	c.SetClock(func() time.Time { return now })
	for i, id := range []string{"a", "b", "c"} {
		c.Put(id, i)
		now = now.Add(time.Second)
	}
	c.Put("d", 3)
	if _, ok := c.Get("a"); ok {
		t.Fatal("oldest not evicted")
	}
	if v, ok := c.Get("d"); !ok || v != 3 {
		t.Fatal("new entry missing")
	}
	now = now.Add(31 * time.Minute)
	if _, ok := c.Get("d"); ok {
		t.Fatal("expired entry returned before sweep")
	}
	c.Sweep()
	if c.Len() != 0 {
		t.Fatalf("len after sweep %d", c.Len())
	}
}

func TestStoreRejectsWhenFullAndExpires(t *testing.T) {
	dir := t.TempDir()
	now := time.Now() // OpenStore sweeps with the real clock on reopen
	s, err := OpenStore(dir, 2, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.SetClock(func() time.Time { return now })
	data := json.RawMessage(`{"x":1}`)
	id1, err := s.Save("check", "example.com", data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save("check", "example.org", data); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save("check", "example.net", data); !errors.Is(err, ErrFull) {
		t.Fatalf("third save err = %v, want ErrFull", err)
	}
	r, err := s.Get(id1)
	if err != nil || r.Target != "example.com" || string(r.Data) != `{"x":1}` {
		t.Fatalf("get: %v %+v", err, r)
	}
	if _, err := s.Get("../" + id1[:37]); !errors.Is(err, ErrNotFound) {
		t.Fatal("traversal id accepted")
	}

	// Reopen indexes existing reports.
	s2, err := OpenStore(dir, 2, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s2.SetClock(func() time.Time { return now })
	if s2.Len() != 2 {
		t.Fatalf("reopened len %d", s2.Len())
	}

	now = now.Add(25 * time.Hour)
	if _, err := s.Get(id1); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired report served")
	}
	s.Sweep()
	if _, err := os.Stat(filepath.Join(dir, id1+".json")); !os.IsNotExist(err) {
		t.Fatal("expired file not removed")
	}
	if _, err := s.Save("check", "x.com", data); err != nil {
		t.Fatalf("save after expiry: %v", err)
	}
}
