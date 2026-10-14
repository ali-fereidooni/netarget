package safenet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsBlocked(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.8.9.10", "10.1.2.3", "172.16.0.1", "172.31.255.255",
		"192.168.1.1", "169.254.169.254", "169.254.0.1", "0.0.0.0", "100.64.0.1",
		"224.0.0.1", "239.1.1.1", "255.255.255.255", "::1", "::", "fe80::1",
		"fc00::1", "fd00:ec2::254", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "2002:7f00:1::1", "2001:db8::1",
		"::7f00:1", "::ffff:0:7f00:1",
	}
	for _, s := range blocked {
		if !IsBlocked(netip.MustParseAddr(s)) {
			t.Errorf("IsBlocked(%s) = false, want true", s)
		}
	}
	public := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "64:ff9b::808:808", "172.32.0.1"}
	for _, s := range public {
		if IsBlocked(netip.MustParseAddr(s)) {
			t.Errorf("IsBlocked(%s) = true, want false", s)
		}
	}
}

type fakeResolver struct {
	answers [][]netip.Addr // successive answers (rebinding simulation)
	calls   atomic.Int32
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	n := int(f.calls.Add(1)) - 1
	if n >= len(f.answers) {
		n = len(f.answers) - 1
	}
	return f.answers[n], nil
}

func TestResolveRejectsPrivateAndMixed(t *testing.T) {
	ctx := context.Background()
	cases := map[string][]netip.Addr{
		"private":  {netip.MustParseAddr("10.0.0.5")},
		"metadata": {netip.MustParseAddr("169.254.169.254")},
		"mixed":    {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")},
		"mapped":   {netip.MustParseAddr("::ffff:192.168.0.1")},
	}
	for name, ans := range cases {
		r := &fakeResolver{answers: [][]netip.Addr{ans}}
		if _, err := Resolve(ctx, r, "evil.example.com"); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: err = %v, want ErrBlocked", name, err)
		}
	}
	if _, err := Resolve(ctx, nil, "127.0.0.1"); !errors.Is(err, ErrBlocked) {
		t.Errorf("literal loopback not blocked: %v", err)
	}
	r := &fakeResolver{answers: [][]netip.Addr{{}}}
	if _, err := Resolve(ctx, r, "empty.example.com"); !errors.Is(err, ErrNoAddress) {
		t.Errorf("empty answer: %v", err)
	}
}

// TestRebindingPinned simulates a DNS rebinding attacker: the first lookup
// returns a public address, later lookups return loopback. Resolve is called
// once, and the pinned dialer must never ask DNS again, so the second
// (malicious) answer is never used.
func TestRebindingPinned(t *testing.T) {
	// We cannot dial a real public IP in a unit test, so verify pinning by
	// checking that DNS is consulted exactly once across resolve + dial.
	r := &fakeResolver{answers: [][]netip.Addr{
		{netip.MustParseAddr("8.8.8.8")},
		{netip.MustParseAddr("127.0.0.1")},
	}}
	ips, err := Resolve(context.Background(), r, "rebind.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ips[0] != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("pinned %v", ips)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	dial := PinnedDialContext(ips, 50*time.Millisecond)
	_, _ = dial(ctx, "tcp", "rebind.example.com:80") // result irrelevant (no network in tests)
	if got := r.calls.Load(); got != 1 {
		t.Fatalf("resolver called %d times, want 1 (pinned dial must not re-resolve)", got)
	}
}

// TestPinnedDialerRefusesBlocked: even if a blocked IP gets into a pinned
// list, the dialer refuses it before any connection.
func TestPinnedDialerRefusesBlocked(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	dial := PinnedDialContext([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, time.Second)
	if _, err := dial(context.Background(), "tcp", "anything.example.com:"+port); !errors.Is(err, ErrBlocked) {
		t.Fatalf("dial err = %v, want ErrBlocked", err)
	}
	// Control hook on the plain dialer also refuses.
	if _, err := Dialer(time.Second).Dial("tcp", ln.Addr().String()); !errors.Is(err, ErrBlocked) {
		t.Fatalf("Control dial err = %v, want ErrBlocked", err)
	}
	select {
	case <-accepted:
		t.Fatal("a connection reached the loopback listener")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestCheckAddrs(t *testing.T) {
	if err := CheckAddrs(nil); !errors.Is(err, ErrNoAddress) {
		t.Error(err)
	}
	if err := CheckAddrs([]netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1")}); !errors.Is(err, ErrBlocked) {
		t.Error(err)
	}
	if err := CheckAddrs([]netip.Addr{netip.MustParseAddr("1.1.1.1")}); err != nil {
		t.Error(err)
	}
}
