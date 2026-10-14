package checks

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"domaindoctor/internal/dnsx"
)

// DKIMSelectors are common selectors probed under _domainkey. DKIM
// selectors cannot be enumerated, so "none found" is informational only.
var DKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2",
	"smtp", "mxvault", "zoho", "protonmail", "fm1", "everlytickey1", "mandrill", "amazonses",
}

type SPFResult struct {
	Record   string   `json:"record,omitempty"`
	Records  int      `json:"records"`
	Lookups  int      `json:"lookups"`
	Errors   []string `json:"errors,omitempty"`
	AllQual  string   `json:"all,omitempty"` // qualifier of the "all" mechanism
	Includes []string `json:"includes,omitempty"`
}

type EmailDetails struct {
	SPF   SPFResult `json:"spf"`
	DMARC struct {
		Record string `json:"record,omitempty"`
		Policy string `json:"policy,omitempty"`
		Error  string `json:"error,omitempty"`
	} `json:"dmarc"`
	DKIM []string `json:"dkim_selectors_found"`
}

// TXTFetcher returns TXT strings for a name (each record joined).
type TXTFetcher func(ctx context.Context, name string) ([]string, error)

// spfRecords filters TXT records to SPF ones.
func spfRecords(txts []string) []string {
	var out []string
	for _, t := range txts {
		l := strings.ToLower(strings.TrimSpace(t))
		if l == "v=spf1" || strings.HasPrefix(l, "v=spf1 ") {
			out = append(out, strings.TrimSpace(t))
		}
	}
	return out
}

// AnalyzeSPF parses an SPF record and counts DNS-querying terms recursively
// (RFC 7208 §4.6.4 limit of 10), following include: and redirect=.
func AnalyzeSPF(ctx context.Context, record string, fetch TXTFetcher) SPFResult {
	res := SPFResult{Record: record, Records: 1}
	visited := map[string]bool{}
	budget := 25 // max fetches, guards against loops/abuse
	var walk func(rec string, depth int, top bool)
	walk = func(rec string, depth int, top bool) {
		terms := strings.Fields(rec)
		for _, term := range terms[1:] {
			lt := strings.ToLower(term)
			qual := "+"
			if strings.ContainsAny(lt[:1], "+-~?") {
				qual, lt = lt[:1], lt[1:]
			}
			name, arg, _ := cutAny(lt, ":=")
			if strings.Contains(lt, "/") && !strings.Contains(lt, ":") {
				name = strings.SplitN(lt, "/", 2)[0]
			}
			switch name {
			case "all":
				if top {
					res.AllQual = qual
				}
			case "ip4", "ip6":
				if arg == "" {
					res.Errors = append(res.Errors, "missing address in "+term)
				}
			case "a", "mx", "ptr", "exists":
				res.Lookups++
				if name == "exists" && arg == "" {
					res.Errors = append(res.Errors, "exists without domain")
				}
			case "include", "redirect":
				res.Lookups++
				if arg == "" {
					res.Errors = append(res.Errors, name+" without domain")
					continue
				}
				if top {
					res.Includes = append(res.Includes, arg)
				}
				if visited[arg] || depth >= 10 || budget <= 0 {
					if visited[arg] {
						res.Errors = append(res.Errors, "include loop via "+arg)
					}
					continue
				}
				visited[arg] = true
				budget--
				txts, err := fetch(ctx, arg)
				if err != nil {
					continue // a temporary failure is not a syntax error
				}
				sub := spfRecords(txts)
				if len(sub) == 0 {
					res.Errors = append(res.Errors, fmt.Sprintf("%s:%s has no SPF record (permerror)", name, arg))
					continue
				}
				walk(sub[0], depth+1, false)
			case "exp", "v":
				// modifiers without lookups
			default:
				if strings.Contains(lt, "=") {
					continue // unknown modifiers are allowed
				}
				res.Errors = append(res.Errors, "unknown mechanism "+term)
			}
		}
	}
	walk(record, 0, true)
	return res
}

func cutAny(s, seps string) (string, string, bool) {
	if i := strings.IndexAny(s, seps); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// checkEmail evaluates SPF, DMARC and common DKIM selectors.
func checkEmail(ctx context.Context, r *Result, apex string, apexTXT []string, hasMX bool, auth *authQuerier, rec TXTFetcher) *EmailDetails {
	ed := &EmailDetails{DKIM: []string{}}
	spfs := spfRecords(apexTXT)
	ed.SPF.Records = len(spfs)
	switch {
	case len(spfs) == 0:
		sev := Warning
		if !hasMX {
			sev = Info
		}
		r.Add("mail.spf_missing", sev, "No SPF record: receivers cannot verify which servers may send mail for this domain.", "no TXT starting with v=spf1")
	case len(spfs) > 1:
		r.Add("mail.spf_multiple", Warning, "More than one SPF record exists; receivers treat this as a permanent error and SPF fails.", strings.Join(spfs, " | "))
	}
	if len(spfs) >= 1 {
		res := AnalyzeSPF(ctx, spfs[0], rec)
		res.Records = len(spfs)
		ed.SPF = res
		if len(res.Errors) > 0 {
			r.Add("mail.spf_syntax", Warning, "The SPF record has errors.", strings.Join(res.Errors, "; "))
		}
		if res.Lookups > 10 {
			r.Add("mail.spf_too_many_lookups", Warning, fmt.Sprintf("SPF needs %d DNS lookups (limit is 10), so it fails with permerror.", res.Lookups), spfs[0])
		}
		if res.AllQual == "+" {
			r.Add("mail.spf_plus_all", Warning, "SPF ends with +all, which authorizes every server on the Internet to send as this domain.", spfs[0])
		}
	}

	// DMARC.
	dm, _ := auth.txt(ctx, "_dmarc."+apex)
	var dmarcs []string
	for _, t := range dm {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			dmarcs = append(dmarcs, t)
		}
	}
	switch {
	case len(dmarcs) == 0:
		r.Add("mail.dmarc_missing", Warning, "No DMARC record: spoofed mail using this domain is not rejected or reported.", "no TXT at _dmarc."+strings.TrimSuffix(apex, "."))
	case len(dmarcs) > 1:
		ed.DMARC.Error = "multiple records"
		r.Add("mail.dmarc_invalid", Warning, "Multiple DMARC records exist; receivers ignore DMARC entirely.", strings.Join(dmarcs, " | "))
	default:
		ed.DMARC.Record = dmarcs[0]
		for _, tag := range strings.Split(dmarcs[0], ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(tag), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "p") {
				ed.DMARC.Policy = strings.ToLower(strings.TrimSpace(v))
			}
		}
		switch ed.DMARC.Policy {
		case "":
			ed.DMARC.Error = "missing p= tag"
			r.Add("mail.dmarc_invalid", Warning, "The DMARC record has no p= policy tag.", dmarcs[0])
		case "none":
			r.Add("mail.dmarc_none", Info, "DMARC policy is p=none (monitoring only); spoofed mail is still delivered.", dmarcs[0])
		case "quarantine", "reject":
		default:
			ed.DMARC.Error = "invalid policy"
			r.Add("mail.dmarc_invalid", Warning, "The DMARC policy value is not valid.", dmarcs[0])
		}
	}

	// DKIM (common selectors only).
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, sel := range DKIMSelectors {
		wg.Add(1)
		go func(sel string) {
			defer wg.Done()
			txts, err := auth.txt(ctx, sel+"._domainkey."+apex)
			if err != nil {
				return
			}
			for _, t := range txts {
				l := strings.ToLower(t)
				if strings.Contains(l, "p=") && (strings.Contains(l, "v=dkim1") || strings.Contains(l, "k=")) || strings.HasPrefix(l, "p=") {
					mu.Lock()
					ed.DKIM = append(ed.DKIM, sel)
					mu.Unlock()
					return
				}
			}
		}(sel)
	}
	wg.Wait()
	if len(ed.DKIM) == 0 && hasMX {
		r.Add("mail.dkim_none_found", Info, "No DKIM key found under common selectors (your provider may use a custom selector).", "")
	}
	return ed
}

// recursiveTXT fetches TXT via the public resolvers (for SPF includes on other domains).
func recursiveTXT(c *dnsx.Client) TXTFetcher {
	return func(ctx context.Context, name string) ([]string, error) {
		m, err := c.Recurse(ctx, name, dns.TypeTXT)
		if err != nil {
			return nil, err
		}
		return txtStrings(m.Answer), nil
	}
}

func txtStrings(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out
}
