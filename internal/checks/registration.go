package checks

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"domaindoctor/internal/rdap"
)

// RegLookup is implemented by *rdap.Client and *whois.Client.
type RegLookup interface {
	Lookup(ctx context.Context, domain string) (*rdap.Info, error)
}

// RegistrationDetails is the Details payload of the registration layer.
type RegistrationDetails struct {
	Domain     string     `json:"domain"`
	Registered bool       `json:"registered"`
	Info       *rdap.Info `json:"info,omitempty"`
	DaysLeft   *int       `json:"days_left,omitempty"`
	RDAPError  string     `json:"rdap_error,omitempty"`
	WHOISError string     `json:"whois_error,omitempty"`
}

// Registration checks the registry record of st.Apex. RDAP first, WHOIS fallback.
func Registration(ctx context.Context, st *State, rd, wh RegLookup, now time.Time) *Result {
	r := NewResult(LayerRegistration)
	d := &RegistrationDetails{Domain: st.Apex}
	r.Details = d
	st.Registered = true // assume registered unless proven otherwise

	info, err := rd.Lookup(ctx, st.Apex)
	if err != nil && !errors.Is(err, rdap.ErrNotFound) {
		d.RDAPError = publicErr(err)
		if wh != nil {
			info, err = wh.Lookup(ctx, st.Apex)
			if err != nil && !errors.Is(err, rdap.ErrNotFound) {
				d.WHOISError = publicErr(err)
			}
		}
	}
	switch {
	case errors.Is(err, rdap.ErrNotFound):
		st.Registered = false
		r.Add("reg.not_registered", Critical,
			fmt.Sprintf("%s is not registered: the registry has no record of it.", st.Apex),
			"registry lookup returned \"not found\"")
		r.Blocking = true
		return r.Finish("Domain is not registered")
	case err != nil || info == nil:
		r.Add("reg.lookup_failed", Warning,
			"Registration data could not be retrieved (RDAP and WHOIS both failed); continuing with DNS checks.",
			strings.TrimSpace(d.RDAPError+"; "+d.WHOISError))
		return r.Finish("Registration data unavailable")
	}

	d.Registered, d.Info = true, info
	status := map[string]bool{}
	for _, s := range info.Status {
		status[s] = true
	}

	if info.Expires != nil {
		days := int(math.Floor(info.Expires.Sub(now).Hours() / 24))
		d.DaysLeft = &days
		exp := info.Expires.Format("2006-01-02")
		switch {
		case days < 0:
			r.Add("reg.expired", Critical,
				fmt.Sprintf("The domain expired %d day(s) ago (%s).", -days, exp),
				"expiry date "+exp)
		case days < 30:
			r.Add("reg.expiring_soon", Warning,
				fmt.Sprintf("The domain expires in %d day(s) (%s).", days, exp),
				"expiry date "+exp)
		default:
			r.Add("reg.ok", Info, fmt.Sprintf("Registered until %s (%d days left).", exp, days), "")
		}
	}

	hold := false
	if status["redemptionPeriod"] {
		r.Add("reg.redemption", Critical,
			"The domain is in the redemption period: it was deleted after expiring and no longer resolves.",
			"EPP status redemptionPeriod")
		hold = true
	}
	if status["pendingDelete"] {
		r.Add("reg.pending_delete", Critical,
			"The domain is pending deletion and will be released by the registry.",
			"EPP status pendingDelete")
		hold = true
	}
	if status["clientHold"] {
		r.Add("reg.client_hold", Critical,
			"The registrar has put the domain on hold (clientHold), so it is removed from the DNS.",
			"EPP status clientHold")
		hold = true
	}
	if status["serverHold"] {
		r.Add("reg.server_hold", Critical,
			"The registry has put the domain on hold (serverHold), so it is removed from the DNS.",
			"EPP status serverHold")
		hold = true
	}
	if status["inactive"] {
		r.Add("reg.inactive", Warning, "The registry marks the domain inactive (no name servers delegated).", "EPP status inactive")
	}
	if status["autoRenewPeriod"] && d.DaysLeft != nil && *d.DaysLeft < 0 {
		r.Add("reg.auto_renew_grace", Info, "The registry auto-renewed the domain; the registrar may still delete it if unpaid.", "EPP status autoRenewPeriod")
	}
	st.OnHold = hold
	r.Blocking = hold

	summary := "Registered"
	if info.Registrar != "" {
		summary += " with " + info.Registrar
	}
	if d.DaysLeft != nil {
		if *d.DaysLeft < 0 {
			summary = fmt.Sprintf("Expired %d day(s) ago", -*d.DaysLeft)
			if info.Registrar != "" {
				summary += " (registrar: " + info.Registrar + ")"
			}
		} else {
			summary += fmt.Sprintf(", %d days left", *d.DaysLeft)
		}
	}
	if hold {
		summary = "Domain is on hold / being deleted — it cannot resolve"
	}
	return r.Finish(summary)
}

// publicErr shortens an error for display without leaking local details.
func publicErr(err error) string {
	switch {
	case errors.Is(err, rdap.ErrNoService):
		return "no RDAP service for this TLD"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case strings.HasPrefix(err.Error(), "RDAP bootstrap: HTTP ") || strings.HasPrefix(err.Error(), "HTTP "):
		return err.Error() // our own status-code messages, no addresses
	case strings.Contains(err.Error(), "no WHOIS server") || strings.Contains(err.Error(), "unrecognized WHOIS"):
		return err.Error()
	}
	return shortErr(err)
}
