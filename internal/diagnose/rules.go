package diagnose

// Rule describes how a finding code is treated by the diagnosis engine.
// Keep in sync with .claude/skills/dns-diagnostics/SKILL.md.
type Rule struct {
	Title string // short root-cause headline
	Fix   string // plain-language fix
}

var rules = map[string]Rule{
	// Registration
	"reg.not_registered": {"The domain is not registered", "Register the domain at any registrar (or check the spelling). Nothing else can work until it exists."},
	"reg.expired":        {"The domain registration has expired", "Renew the domain at your registrar now and turn on auto-renew. The registry usually reactivates it within minutes to a few hours."},
	"reg.expiring_soon":  {"The domain expires soon", "Renew the domain and enable auto-renew; make sure the registrar's billing and contact e-mail are current."},
	"reg.redemption":     {"The domain was deleted after expiring (redemption period)", "Ask your registrar to restore the domain from redemption (there is a restore fee). After restore, renew it."},
	"reg.pending_delete": {"The domain is about to be deleted by the registry", "It cannot be restored anymore. Wait for it to drop and register it again (or use a back-order service)."},
	"reg.client_hold":    {"The registrar put the domain on hold", "Contact your registrar: common causes are an unpaid invoice, an unverified registrant e-mail (ICANN verification), or an abuse complaint. Verify the e-mail / pay, then ask them to remove clientHold."},
	"reg.server_hold":    {"The registry put the domain on hold", "Contact your registrar to find out why the registry applied serverHold (legal, abuse, or policy issue) and what is required to lift it."},
	"reg.inactive":       {"The registry shows no name servers for the domain", "Set at least two name servers for the domain at your registrar."},
	"reg.lookup_failed":  {"Registration data could not be retrieved", "Usually a temporary RDAP/WHOIS problem; retry later. It does not affect the other checks."},

	// Name servers
	"ns.checker_dns_blocked":   {"This checker cannot send DNS queries", "Not a problem with the domain. Run Domain Doctor (master or CLI) on a network that allows outbound UDP and TCP port 53 — e.g. a VPS — or ask your network administrator to allow it."},
	"ns.parent_unreachable":    {"The TLD name servers could not be queried", "Retry later; if it persists from several networks the TLD may have an outage."},
	"ns.no_delegation":         {"The domain is not delegated to any name servers", "Set the name servers at your registrar (the NS records your DNS provider gives you). If the domain is on hold or expired, fix that first."},
	"ns.none_usable":           {"None of the domain's name servers answer for it", "Add the zone at your DNS provider so the listed name servers answer authoritatively, or change the name servers at the registrar to the ones that actually host the zone."},
	"ns.lame":                  {"Lame delegation: a listed name server does not serve the zone", "Either create the zone on that server or remove it from the name-server list at the registrar."},
	"ns.unreachable":           {"A name server does not respond", "Check that the server is running and that UDP and TCP port 53 are open, or replace it in the delegation."},
	"ns.no_address":            {"A name server has no IP address", "Create the A/AAAA record for the name-server host name, or correct a misspelled name server at the registrar."},
	"ns.missing_glue":          {"Glue records are missing for an in-domain name server", "At the registrar, register the name server host (\"child name server\"/glue) with its IP address."},
	"ns.glue_mismatch":         {"Glue IPs at the registrar differ from the zone", "Update the glue (child name server) IP at the registrar to match the A record in the zone, or vice versa."},
	"ns.parent_child_mismatch": {"Registrar NS list differs from the zone's NS records", "Make the NS records inside the zone identical to the name servers set at the registrar."},
	"ns.too_few":               {"Only one name server", "Add a second name server, ideally with a different provider or network."},
	"ns.single_network":        {"All name servers are in one network", "Add a name server in a different network/ASN (secondary DNS service) for resilience."},
	"ns.serial_mismatch":       {"Name servers serve different versions of the zone", "Check zone transfers: allow AXFR/IXFR from the primary to the secondaries, enable NOTIFY, and make sure the secondaries can reach the primary."},
	"ns.private_ip":            {"A name server resolves to a private IP", "Publish the name server's public IP address."},

	// Zone
	"dns.nxdomain":              {"The host name does not exist in the zone", "Create the record (A/AAAA or CNAME) for this name in your DNS zone."},
	"dns.no_address":            {"The domain has no A/AAAA records", "Add an A record (and AAAA if you have IPv6) pointing to your web server, or an ALIAS/flattened CNAME at the apex if you use a hosting platform."},
	"dns.no_address_apex":       {"The bare domain has no address", "Add an A/AAAA (or ALIAS) record for the bare domain, then redirect it to www if www is canonical."},
	"dns.cname_at_apex":         {"CNAME at the zone apex", "Replace the apex CNAME with A/AAAA records or your DNS provider's ALIAS/ANAME/CNAME-flattening feature."},
	"dns.dangling_cname":        {"A CNAME points to a name that does not exist", "Fix the CNAME target or delete the record; a dangling CNAME can let others take over the subdomain."},
	"dns.cname_unresolved":      {"A CNAME target could not be resolved", "Check the CNAME target's DNS."},
	"dns.mx_cname":              {"MX points to a CNAME", "Point the MX record directly at a host name that has A/AAAA records."},
	"dns.mx_unresolvable":       {"A mail server name does not resolve", "Fix the MX target host name or create its A/AAAA record."},
	"dns.private_address":       {"A record points to a private IP", "Replace the private address with the server's public IP."},
	"dns.auth_inconsistent":     {"Authoritative servers disagree", "Make all name servers serve the same zone data (fix zone transfers or update every provider)."},
	"dns.propagation":           {"Public resolvers still have old data", "Wait for the TTL shown to expire; for a changed name server set allow up to 48 hours. You can purge caches at 1.1.1.1/purge-cache and Google Public DNS flush."},
	"dns.resolver_servfail":     {"Public resolvers fail to resolve the domain", "Check DNSSEC and name-server health; resolvers return SERVFAIL when validation fails or no server answers."},
	"mail.spf_missing":          {"No SPF record", "Publish one TXT record like: v=spf1 include:<your mail provider> -all"},
	"mail.spf_multiple":         {"Multiple SPF records", "Merge them into a single v=spf1 TXT record."},
	"mail.spf_syntax":           {"SPF syntax errors", "Correct the listed SPF errors."},
	"mail.spf_too_many_lookups": {"SPF exceeds 10 DNS lookups", "Reduce include:/a/mx mechanisms (flatten to ip4/ip6 or remove unused providers) to 10 or fewer lookups."},
	"mail.spf_plus_all":         {"SPF allows everyone (+all)", "End the SPF record with -all or ~all instead of +all."},
	"mail.dmarc_missing":        {"No DMARC record", "Publish TXT at _dmarc: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain (start with p=none to monitor)."},
	"mail.dmarc_invalid":        {"DMARC record is invalid", "Keep exactly one _dmarc TXT record with a valid p= policy (none, quarantine or reject)."},
	"dnssec.broken":             {"DNSSEC is broken", "If you changed DNS provider, remove the old DS record at your registrar (or publish the new provider's DS). Otherwise re-sign the zone and make sure the DS matches the current KSK."},
	"dnssec.sig_expiring":       {"DNSSEC signatures about to expire", "Check that automatic zone re-signing is running at your DNS provider."},

	// Reachability
	"reach.down_all":         {"The server is unreachable", "Check that the server is running, that its firewall/security group allows ports 80 and 443, and that the A/AAAA records point to the right IP."},
	"reach.partial":          {"The server is unreachable from some regions", "Compare traceroutes from the failing nodes; check geo-blocking/firewall rules and ask your hosting provider about routing problems."},
	"reach.v6_broken":        {"IPv6 is published but broken", "Fix IPv6 connectivity/firewall on the server, or remove the AAAA record until IPv6 works."},
	"reach.web_ports_closed": {"Ports 80/443 are closed", "Start the web server and open ports 80 and 443 in the firewall."},
	"reach.no_data":          {"No measurement node responded", "Retry; if it persists, check the agents."},

	// Web
	"web.timeout":               {"The web server does not answer (timeout)", "Check the firewall (ports 80/443), that the web server is running, and server load."},
	"web.refused":               {"The web server refuses connections", "Start the web server (nginx/Apache/app) or make it listen on ports 80/443 on the public interface."},
	"web.reset":                 {"The web server resets connections", "Check the web server error logs, crashing workers, or a middlebox/WAF dropping connections."},
	"tls.handshake_failed":      {"The TLS handshake fails", "Install a certificate for this host name on port 443, enable TLS 1.2/1.3, and make sure port 443 speaks HTTPS (not plain HTTP)."},
	"web.5xx":                   {"The website returns a server error", "Check the application and reverse-proxy logs; restart the backend; for 502/504 verify the upstream address and timeouts."},
	"web.cdn_error":             {"The CDN cannot reach your origin server", "Make sure the origin server is up, allows the CDN's IP ranges, and has a valid certificate if the CDN connects over HTTPS."},
	"web.4xx":                   {"The website returns a client error at the root", "Check the virtual host / document root, index file, and WAF or geo-blocking rules."},
	"web.redirect_loop":         {"Redirect loop", "Remove the duplicate redirect. A common cause is HTTPS redirect at the origin while the CDN connects over HTTP (Cloudflare 'Flexible' SSL): use 'Full (strict)' instead."},
	"web.no_https_redirect":     {"HTTP does not redirect to HTTPS", "Add a permanent (301) redirect from http:// to https://."},
	"web.apex_www_inconsistent": {"Bare domain and www behave differently", "Pick one canonical host and 301-redirect the other to it; make sure both have DNS records and a certificate."},
	"web.no_hsts":               {"HSTS is not enabled", "Add the header Strict-Transport-Security: max-age=31536000; includeSubDomains once HTTPS works everywhere."},
	"web.partial":               {"The website fails from some regions", "Check CDN/edge status and geo-blocking rules; compare the failing nodes' results."},
	"web.redirect_dns":          {"A redirect points to a host that does not resolve", "Fix the redirect target or create DNS records for it."},
	"web.redirect_private":      {"A redirect points to an internal address", "Redirect to the public host name instead of an internal one."},
	"web.bad_redirect":          {"Invalid redirect", "Return a valid absolute or relative Location header on a standard port."},
	"web.error":                 {"The web request failed", "Check the server and network path."},
	"tls.expired":               {"The TLS certificate has expired", "Renew the certificate now (e.g. certbot renew) and fix automatic renewal; reload the web server afterwards."},
	"tls.not_yet_valid":         {"The TLS certificate is not valid yet", "Check the server clock and the certificate's start date."},
	"tls.expiring_soon":         {"The TLS certificate expires soon", "Renew the certificate and verify automatic renewal works."},
	"tls.hostname_mismatch":     {"The TLS certificate does not match the host name", "Issue a certificate that includes this name (and www), or fix the virtual host/SNI so the right certificate is served."},
	"tls.incomplete_chain":      {"The certificate chain is incomplete", "Configure the server with the full chain (e.g. fullchain.pem in nginx ssl_certificate)."},
	"tls.untrusted":             {"The TLS certificate is not trusted", "Replace the self-signed/private-CA certificate with one from a public CA such as Let's Encrypt."},
	"tls.old_protocol":          {"Outdated TLS version", "Enable TLS 1.2 and 1.3 and disable TLS 1.0/1.1."},
}

// RuleFor returns the rule for a code, if any.
func RuleFor(code string) (Rule, bool) {
	r, ok := rules[code]
	return r, ok
}
