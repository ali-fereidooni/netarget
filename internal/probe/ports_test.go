package probe

import "testing"

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in    string
		want  []int
		isErr bool
	}{
		{"", nil, false},
		{"22,80,443,8443", []int{22, 80, 443, 8443}, false},
		{" 80 , 443 ", []int{80, 443}, false},
		{"80,80,443", []int{80, 443}, false}, // deduped
		{"0", nil, true},
		{"70000", nil, true},
		{"80,abc", nil, true},
		{"1,2,3,4,5,6,7,8,9", nil, true}, // over MaxProbePorts
	}
	for _, c := range cases {
		set, err := ParsePorts(c.in)
		if c.isErr {
			if err == nil {
				t.Errorf("%q: expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		got := SortedPorts(set)
		if len(got) != len(c.want) {
			t.Errorf("%q: got %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q: got %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

func TestLocalPortAllowList(t *testing.T) {
	// Default (nil AllowPorts) allows only 80/443.
	l := &Local{}
	if l.portAllowed(22) || !l.portAllowed(80) {
		t.Error("default allow-list should be 80/443 only")
	}
	// Explicit allow-list is honored.
	l2 := &Local{AllowPorts: map[int]bool{22: true, 8443: true}}
	if !l2.portAllowed(22) || !l2.portAllowed(8443) || l2.portAllowed(80) {
		t.Error("explicit allow-list not honored")
	}
}
