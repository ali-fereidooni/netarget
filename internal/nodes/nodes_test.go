package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"domaindoctor/internal/probe"
)

type fakeProber struct {
	healthy        atomic.Bool
	inFlight, peak atomic.Int32
}

func (f *fakeProber) Health(context.Context) error {
	if f.healthy.Load() {
		return nil
	}
	return errors.New("down")
}
func (f *fakeProber) Probe(context.Context, probe.ProbeRequest) (*probe.ProbeResponse, error) {
	return nil, nil
}
func (f *fakeProber) HTTP(context.Context, probe.HTTPRequest) (*probe.HTTPResponse, error) {
	return nil, nil
}
func (f *fakeProber) Traceroute(context.Context, netip.Addr, int, func(string)) error { return nil }

func TestLiveness(t *testing.T) {
	a, b := &fakeProber{}, &fakeProber{}
	a.healthy.Store(true)
	reg := New(&Node{ID: "a", P: a}, &Node{ID: "b", P: b})
	ctx := context.Background()
	if len(reg.Live()) != 2 {
		t.Fatal("nodes should start live")
	}
	reg.CheckOnce(ctx, time.Second)
	if !reg.IsLive("b") {
		t.Fatal("dead after a single failure")
	}
	reg.CheckOnce(ctx, time.Second)
	if reg.IsLive("b") || len(reg.Live()) != 1 || reg.Live()[0].ID != "a" {
		t.Fatal("not dead after two failures")
	}
	if pub := reg.PublicLive(); len(pub) != 1 || pub[0].ID != "a" {
		t.Fatalf("public %v", pub)
	}
	b.healthy.Store(true)
	reg.CheckOnce(ctx, time.Second)
	if !reg.IsLive("b") {
		t.Fatal("not live after one success")
	}
}

func TestFanoutBounded(t *testing.T) {
	var ns []*Node
	f := &fakeProber{}
	for i := 0; i < 20; i++ {
		ns = append(ns, &Node{ID: string(rune('a' + i)), P: f})
	}
	res := Fanout(context.Background(), ns, 8, func(_ context.Context, n *Node) string {
		cur := f.inFlight.Add(1)
		for {
			p := f.peak.Load()
			if cur <= p || f.peak.CompareAndSwap(p, cur) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		f.inFlight.Add(-1)
		return n.ID
	})
	if f.peak.Load() > 8 {
		t.Fatalf("peak concurrency %d > 8", f.peak.Load())
	}
	for i, r := range res {
		if r != ns[i].ID {
			t.Fatal("results out of order")
		}
	}
}

func TestLoadAndPublicMetadata(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nodes.json")
	doc := map[string]any{"nodes": []map[string]string{
		{"id": "fra1", "name": "Frankfurt", "location": "DE", "url": "http://10.0.0.2:9090"},
		{"id": "ams1", "name": "Amsterdam", "location": "NL", "url": "http://10.0.0.3:9090", "secret_env": "AMS_SECRET"},
	}}
	b, _ := json.Marshal(doc)
	os.WriteFile(p, b, 0o600)
	env := map[string]string{"AGENT_SECRET": strings.Repeat("a", 64), "AMS_SECRET": strings.Repeat("b", 64)}
	reg, err := Load(p, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(reg.PublicLive())
	s := string(out)
	if strings.Contains(s, "10.0.0") || strings.Contains(s, "aaaa") || strings.Contains(s, "url") {
		t.Fatalf("public metadata leaks internals: %s", s)
	}
	delete(env, "AMS_SECRET")
	if _, err := Load(p, func(k string) string { return env[k] }); err == nil {
		t.Fatal("missing secret accepted")
	}
	os.WriteFile(p, []byte(`{"nodes":[{"id":"../x","url":"http://a"}]}`), 0o600)
	if _, err := Load(p, func(k string) string { return env[k] }); err == nil {
		t.Fatal("bad id accepted")
	}
}
