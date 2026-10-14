package checks

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"domaindoctor/internal/nodes"
	"domaindoctor/internal/probe"
)

type WebNodeRow struct {
	Node      string  `json:"node"`
	Location  string  `json:"location"`
	URL       string  `json:"url"`
	FinalURL  string  `json:"final_url,omitempty"`
	Status    int     `json:"status,omitempty"`
	ErrorKind string  `json:"error_kind,omitempty"`
	Hops      int     `json:"hops"`
	TotalMS   float64 `json:"total_ms"`
	OK        bool    `json:"ok"`
}

type WebDetails struct {
	PrimaryNode string                    `json:"primary_node"`
	Chains      []probe.Chain             `json:"chains"`
	Nodes       []WebNodeRow              `json:"nodes"`
	TLS         map[string]*probe.TLSInfo `json:"tls,omitempty"`
}

type nodeHTTP struct {
	node *nodes.Node
	resp *probe.HTTPResponse
	err  error
}

func chainOK(c *probe.Chain) bool {
	f := c.Final()
	return f != nil && !c.Loop && f.ErrorKind == "" && f.Status > 0 && f.Status < 400
}

// Web requests http/https for the host (and www) from every live node.
func Web(ctx context.Context, st *State, ns []*nodes.Node, now time.Time) *Result {
	if len(ns) == 0 {
		return Skipped(LayerWeb, "no measurement nodes are available")
	}
	host := strings.TrimSuffix(st.Domain, ".")
	pinned := map[string][]netip.Addr{}
	hosts := []string{}
	if len(st.ApexV4)+len(st.ApexV6) > 0 {
		pinned[host] = pinList(st.ApexV4, st.ApexV6)
		hosts = append(hosts, host)
	}
	www := "www." + strings.TrimSuffix(st.Apex, ".")
	if host == strings.TrimSuffix(st.Apex, ".") && len(st.WWWV4)+len(st.WWWV6) > 0 {
		pinned[www] = pinList(st.WWWV4, st.WWWV6)
		hosts = append(hosts, www)
	}
	if len(hosts) == 0 {
		return Skipped(LayerWeb, "the domain has no A/AAAA records to test")
	}
	var urls []string
	for _, h := range hosts {
		urls = append(urls, "http://"+h+"/", "https://"+h+"/")
	}
	r := NewResult(LayerWeb)
	det := &WebDetails{TLS: map[string]*probe.TLSInfo{}}
	r.Details = det

	results := nodes.Fanout(ctx, ns, 8, func(ctx context.Context, n *nodes.Node) nodeHTTP {
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		resp, err := n.P.HTTP(cctx, probe.HTTPRequest{URLs: urls, Pinned: pinned})
		if err == nil && (resp == nil || len(resp.Chains) != len(urls)) {
			err = fmt.Errorf("agent unreachable")
		}
		return nodeHTTP{node: n, resp: resp, err: err}
	})

	var primary *nodeHTTP
	for i := range results {
		nr := &results[i]
		if nr.err != nil {
			for _, u := range urls {
				det.Nodes = append(det.Nodes, WebNodeRow{Node: nr.node.Name, Location: nr.node.Location, URL: u, ErrorKind: "agent_unreachable"})
			}
			continue
		}
		if primary == nil {
			primary = nr
		}
		for _, c := range nr.resp.Chains {
			row := WebNodeRow{Node: nr.node.Name, Location: nr.node.Location, URL: c.Start, Hops: len(c.Hops), OK: chainOK(&c)}
			if f := c.Final(); f != nil {
				row.FinalURL, row.Status, row.ErrorKind = f.URL, f.Status, f.ErrorKind
				for _, h := range c.Hops {
					row.TotalMS += h.Timing.TotalMS
				}
			}
			if c.Loop {
				row.ErrorKind = "redirect_loop"
			}
			det.Nodes = append(det.Nodes, row)
		}
	}
	if primary == nil {
		r.Add("web.no_data", Warning, "No measurement node could run the web check.", "all agents unreachable")
		return r.Finish("No measurements")
	}
	det.PrimaryNode = primary.node.Name
	det.Chains = primary.resp.Chains
	chains := map[string]*probe.Chain{}
	for i := range primary.resp.Chains {
		chains[primary.resp.Chains[i].Start] = &primary.resp.Chains[i]
	}
	mainHTTPS, mainHTTP := chains["https://"+hosts[0]+"/"], chains["http://"+hosts[0]+"/"]
	siteWorks := chainOK(mainHTTPS) || chainOK(mainHTTP)

	// Classify failing chains. Chains that end at the same URL with the same
	// outcome (e.g. http:// redirecting to a failing https://) are reported once.
	// Main-host chains go first so they win the dedupe with critical severity.
	classified := map[string]bool{}
	for _, u := range urls {
		c := chains[u]
		sev := Warning
		if !siteWorks && strings.Contains(u, "://"+hosts[0]+"/") {
			sev = Critical
		}
		if f := c.Final(); f != nil && !c.Loop {
			key := fmt.Sprintf("%s|%s|%d", f.URL, f.ErrorKind, f.Status)
			if classified[key] {
				continue
			}
			classified[key] = true
		}
		classifyChain(r, c, sev)
	}

	// HTTP -> HTTPS redirect.
	for _, h := range hosts {
		hc, sc := chains["http://"+h+"/"], chains["https://"+h+"/"]
		if chainOK(hc) && chainOK(sc) && strings.HasPrefix(hc.Final().URL, "http://") {
			r.Add("web.no_https_redirect", Warning, fmt.Sprintf("http://%s/ does not redirect to HTTPS, so visitors can stay on an unencrypted connection.", h), hc.Final().URL+" → "+fmt.Sprint(hc.Final().Status))
		}
	}

	// Apex / www consistency.
	if len(hosts) == 2 {
		a, w := chains["https://"+hosts[0]+"/"], chains["https://"+hosts[1]+"/"]
		if !chainOK(a) {
			a = chains["http://"+hosts[0]+"/"]
		}
		if !chainOK(w) {
			w = chains["http://"+hosts[1]+"/"]
		}
		aok, wok := chainOK(a), chainOK(w)
		switch {
		case aok != wok:
			bad := hosts[0]
			if aok {
				bad = hosts[1]
			}
			r.Add("web.apex_www_inconsistent", Warning, fmt.Sprintf("%s fails while the other name works; visitors using it get an error.", bad), "")
		case aok && wok && finalHost(a) != finalHost(w):
			r.Add("web.apex_www_inconsistent", Warning, "The bare domain and www serve the site separately instead of redirecting one to the other (duplicate content, split cookies).",
				fmt.Sprintf("%s → %s | %s → %s", a.Start, a.Final().URL, w.Start, w.Final().URL))
		}
	}

	// Security headers on the final HTTPS response.
	if sc := chains["https://"+hosts[0]+"/"]; chainOK(sc) && strings.HasPrefix(sc.Final().URL, "https://") {
		f := sc.Final()
		if f.Headers["Strict-Transport-Security"] == "" {
			r.Add("web.no_hsts", Warning, "No Strict-Transport-Security (HSTS) header: browsers may still try plain HTTP first.", f.URL)
		}
		var missing []string
		for _, hname := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"} {
			if f.Headers[hname] == "" {
				missing = append(missing, hname)
			}
		}
		if f.Headers["X-Frame-Options"] == "" && !strings.Contains(f.Headers["Content-Security-Policy"], "frame-ancestors") {
			missing = append(missing, "X-Frame-Options")
		}
		if len(missing) > 0 {
			r.Add("web.missing_security_headers", Info, "Recommended security headers are missing: "+strings.Join(missing, ", ")+".", f.URL)
		}
	}

	// TLS for each host's https start.
	for _, h := range hosts {
		c := chains["https://"+h+"/"]
		if c == nil || len(c.Hops) == 0 || c.Hops[0].TLS == nil {
			continue
		}
		info := c.Hops[0].TLS
		det.TLS[h] = info
		classifyTLS(r, h, info, now)
	}

	// Cross-node consistency for the main URL.
	var okNodes, badNodes []string
	for _, row := range det.Nodes {
		if row.ErrorKind == "agent_unreachable" || (mainHTTPS != nil && row.URL != mainHTTPS.Start) {
			continue
		}
		if row.OK {
			okNodes = append(okNodes, row.Node)
		} else {
			badNodes = append(badNodes, fmt.Sprintf("%s (%s)", row.Node, firstNonEmpty(row.ErrorKind, fmt.Sprint(row.Status))))
		}
	}
	if len(okNodes) > 0 && len(badNodes) > 0 {
		r.Add("web.partial", Warning, "The website works from some nodes but fails from others (regional outage, geo-blocking, or a CDN edge problem).",
			"failing: "+strings.Join(badNodes, ", "))
	}

	summary := "Website unreachable"
	if f := mainHTTPS.Final(); f != nil && f.Status > 0 && !chainOK(mainHTTPS) {
		summary = fmt.Sprintf("%s → %d %s", mainHTTPS.Start, f.Status, f.StatusText)
		if f.URL != mainHTTPS.Start {
			summary = fmt.Sprintf("%s → %s → %d %s", mainHTTPS.Start, f.URL, f.Status, f.StatusText)
		}
	} else if mainHTTPS.Loop {
		summary = mainHTTPS.Start + " → redirect loop"
	}
	if f := mainHTTPS.Final(); chainOK(mainHTTPS) {
		summary = fmt.Sprintf("%s → %d %s in %.0f ms (from %s)", mainHTTPS.Start, f.Status, f.StatusText, f.Timing.TotalMS, det.PrimaryNode)
	} else if chainOK(mainHTTP) {
		summary = fmt.Sprintf("%s → %d (HTTPS fails)", mainHTTP.Start, mainHTTP.Final().Status)
	}
	// The server may answer while browsers still refuse the certificate.
	for _, code := range []string{"tls.expired", "tls.hostname_mismatch", "tls.untrusted", "tls.not_yet_valid"} {
		if r.Has(code) {
			summary += " — but browsers reject the TLS certificate"
			break
		}
	}
	return r.Finish(summary)
}

// pinList keeps up to 2 IPv4 + 2 IPv6 addresses (agents accept at most 8 per host).
func pinList(v4, v6 []netip.Addr) []netip.Addr {
	out := append([]netip.Addr{}, v4[:min(2, len(v4))]...)
	return append(out, v6[:min(2, len(v6))]...)
}

func classifyChain(r *Result, c *probe.Chain, sev Severity) {
	if c == nil {
		return
	}
	if c.Loop {
		var path []string
		for _, h := range c.Hops {
			path = append(path, h.URL)
		}
		r.Add("web.redirect_loop", sev, c.Start+" redirects in a loop (or more than 10 times); browsers show ERR_TOO_MANY_REDIRECTS.", strings.Join(path, " → "))
		return
	}
	f := c.Final()
	if f == nil {
		return
	}
	ev := fmt.Sprintf("%s (from %s)", f.URL, c.Start)
	switch f.ErrorKind {
	case "":
	case "timeout":
		r.Add("web.timeout", sev, c.Start+" timed out: the server accepts no connection or never answers (firewall dropping packets or overloaded server).", ev)
		return
	case "refused":
		r.Add("web.refused", sev, c.Start+": connection refused — the host is up but nothing listens on the port (web server stopped or wrong port).", ev)
		return
	case "reset":
		r.Add("web.reset", sev, c.Start+": the connection was reset by the server (crashing server, protocol mismatch, or middlebox).", ev)
		return
	case "tls_handshake":
		r.Add("tls.handshake_failed", sev, c.Start+": the TLS handshake failed (no certificate for this name, outdated protocol/cipher, or plain HTTP on port 443).", ev)
		return
	case "dns":
		r.Add("web.redirect_dns", sev, c.Start+" redirects to a host name that does not resolve.", ev)
		return
	case "blocked":
		r.Add("web.redirect_private", Warning, c.Start+" redirects to a private or internal address, which is unreachable from the Internet.", ev)
		return
	case "bad_url":
		r.Add("web.bad_redirect", Warning, c.Start+" has an invalid or unsupported redirect.", ev+": "+f.Error)
		return
	default:
		r.Add("web.error", sev, c.Start+" failed: "+f.Error+".", ev)
		return
	}
	switch {
	case f.CDNError:
		r.Add("web.cdn_error", sev, fmt.Sprintf("%s returns a %s error page (%d): %s", c.Start, f.CDN, f.Status, cdnHint(f.CDN, f.Status)), ev)
	case f.Status >= 500:
		r.Add("web.5xx", sev, fmt.Sprintf("%s returns HTTP %d %s: %s", c.Start, f.Status, f.StatusText, statusHint(f.Status)), ev)
	case f.Status >= 400:
		r.Add("web.4xx", Warning, fmt.Sprintf("%s returns HTTP %d %s: %s", c.Start, f.Status, f.StatusText, statusHint(f.Status)), ev)
	}
}

func classifyTLS(r *Result, host string, t *probe.TLSInfo, now time.Time) {
	ev := fmt.Sprintf("subject=%s issuer=%s valid %s → %s SAN=[%s]", t.Subject, t.Issuer,
		t.NotBefore.Format("2006-01-02"), t.NotAfter.Format("2006-01-02"), strings.Join(t.SANs, ", "))
	expired := t.DaysLeft < 0 || now.After(t.NotAfter)
	switch {
	case expired:
		r.Add("tls.expired", Critical, fmt.Sprintf("The TLS certificate for %s expired on %s; browsers show a security error.", host, t.NotAfter.Format("2006-01-02")), ev)
	case now.Before(t.NotBefore):
		r.Add("tls.not_yet_valid", Critical, fmt.Sprintf("The TLS certificate for %s is not valid yet (starts %s); check the server clock or the certificate.", host, t.NotBefore.Format("2006-01-02")), ev)
	case t.DaysLeft < 14:
		r.Add("tls.expiring_soon", Warning, fmt.Sprintf("The TLS certificate for %s expires in %d day(s).", host, t.DaysLeft), ev)
	}
	if !t.HostnameMatch {
		r.Add("tls.hostname_mismatch", Critical, fmt.Sprintf("The certificate presented for %s does not cover that name.", host), ev)
	}
	if t.IncompleteChain {
		r.Add("tls.incomplete_chain", Warning, fmt.Sprintf("%s does not send the intermediate certificate(s); some clients (Android, curl, APIs) will reject the connection.", host), t.ChainError)
	} else if !t.ChainValid && !expired {
		r.Add("tls.untrusted", Critical, fmt.Sprintf("The certificate for %s is not trusted (%s).", host, t.ChainError), ev)
	}
	if t.Version == "TLS 1.0" || t.Version == "TLS 1.1" {
		r.Add("tls.old_protocol", Warning, fmt.Sprintf("%s negotiated %s, which is deprecated; enable TLS 1.2/1.3.", host, t.Version), "")
	}
}

func statusHint(code int) string {
	switch code {
	case 500:
		return "the application crashed or threw an error; check the application logs."
	case 502:
		return "the reverse proxy/load balancer could not get a valid response from the application server (backend down or crashing)."
	case 503:
		return "the service is unavailable (overloaded, maintenance mode, or no healthy backends)."
	case 504:
		return "the proxy timed out waiting for the backend application."
	case 401:
		return "authentication is required at the site root."
	case 403:
		return "access is forbidden — often a WAF, geo-blocking, or wrong file permissions/directory index."
	case 404:
		return "the root page is not found — the virtual host or document root is likely misconfigured."
	case 429:
		return "rate limited by the server or WAF."
	}
	if code >= 500 {
		return "server-side error."
	}
	return "client error."
}

func cdnHint(cdn string, code int) string {
	if cdn == "Cloudflare" {
		switch code {
		case 520:
			return "the origin returned an empty or unexpected response."
		case 521:
			return "the origin web server refused the connection from Cloudflare (web server down or firewall blocking Cloudflare IPs)."
		case 522:
			return "Cloudflare timed out connecting to the origin (origin down, overloaded, or firewall dropping Cloudflare)."
		case 523:
			return "the origin is unreachable (wrong origin IP in the Cloudflare DNS settings)."
		case 524:
			return "the origin accepted the connection but took too long to respond."
		case 525:
			return "the TLS handshake between Cloudflare and the origin failed."
		case 526:
			return "the origin certificate is invalid while Cloudflare SSL mode is Full (strict)."
		}
	}
	return "the CDN could not get a good response from the origin server; check that the origin is up and reachable from the CDN."
}

func finalHost(c *probe.Chain) string {
	u, err := url.Parse(c.Final().URL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
