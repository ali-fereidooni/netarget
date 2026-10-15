package checks

import (
	"context"
	"errors"
	"testing"
	"time"

	"domaindoctor/internal/rdap"
)

type fakeReg struct {
	info *rdap.Info
	err  error
	n    int
}

func (f *fakeReg) Lookup(context.Context, string) (*rdap.Info, error) {
	f.n++
	return f.info, f.err
}

func TestRegistration(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	date := func(d int) *time.Time { t := now.AddDate(0, 0, d); return &t }
	cases := []struct {
		name     string
		rd, wh   *fakeReg
		status   Status
		blocking bool
		codes    []string
	}{
		{"healthy", &fakeReg{info: &rdap.Info{Registrar: "R", Expires: date(200), Status: []string{"clientTransferProhibited"}}}, nil, OK, false, []string{"reg.ok"}},
		{"expiring", &fakeReg{info: &rdap.Info{Expires: date(10)}}, nil, WARN, false, []string{"reg.expiring_soon"}},
		{"expired", &fakeReg{info: &rdap.Info{Expires: date(-3)}}, nil, FAIL, false, []string{"reg.expired"}},
		{"client hold", &fakeReg{info: &rdap.Info{Expires: date(100), Status: []string{"clientHold"}}}, nil, FAIL, true, []string{"reg.client_hold"}},
		{"server hold", &fakeReg{info: &rdap.Info{Expires: date(100), Status: []string{"serverHold"}}}, nil, FAIL, true, []string{"reg.server_hold"}},
		{"redemption", &fakeReg{info: &rdap.Info{Expires: date(-40), Status: []string{"redemptionPeriod"}}}, nil, FAIL, true, []string{"reg.redemption", "reg.expired"}},
		{"pending delete", &fakeReg{info: &rdap.Info{Status: []string{"pendingDelete"}}}, nil, FAIL, true, []string{"reg.pending_delete"}},
		{"not registered rdap", &fakeReg{err: rdap.ErrNotFound}, &fakeReg{}, FAIL, true, []string{"reg.not_registered"}},
		{"whois fallback", &fakeReg{err: rdap.ErrNoService}, &fakeReg{info: &rdap.Info{Source: "whois", Expires: date(400)}}, OK, false, []string{"reg.ok"}},
		{"whois not found", &fakeReg{err: rdap.ErrNoService}, &fakeReg{err: rdap.ErrNotFound}, FAIL, true, []string{"reg.not_registered"}},
		{"both fail", &fakeReg{err: errors.New("boom")}, &fakeReg{err: errors.New("bang")}, WARN, false, []string{"reg.lookup_failed"}},
	}
	// .ir: the lookup still runs; when it fails (data hidden) there is no warning.
	ir, irWh := &fakeReg{err: rdap.ErrNoService}, &fakeReg{err: errors.New("bang")}
	r := Registration(context.Background(), &State{Domain: "shop.example.ir", Apex: "example.ir"}, ir, irWh, now)
	if r.Status != OK || r.Blocking || !r.Has("reg.not_published") || r.Has("reg.lookup_failed") || ir.n != 1 || irWh.n != 1 {
		t.Errorf(".ir: status %s lookups %d/%d [%s]", r.Status, ir.n, irWh.n, codes(r))
	}
	for _, c := range cases {
		st := &State{Domain: "example.com", Apex: "example.com"}
		var wh RegLookup
		if c.wh != nil {
			wh = c.wh
		}
		r := Registration(context.Background(), st, c.rd, wh, now)
		if r.Status != c.status || r.Blocking != c.blocking {
			t.Errorf("%s: status %s blocking %v [%s]", c.name, r.Status, r.Blocking, codes(r))
		}
		for _, code := range c.codes {
			if !r.Has(code) {
				t.Errorf("%s: missing %s in [%s]", c.name, code, codes(r))
			}
		}
		if c.name == "not registered rdap" && c.wh.n != 0 {
			t.Errorf("WHOIS consulted although RDAP gave a definitive not-found")
		}
	}
}
