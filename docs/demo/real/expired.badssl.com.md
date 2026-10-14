# Domain Doctor report: expired.badssl.com

- Checked: 2026-10-14 21:03:07 UTC
- Request ID: `e34ebb17d8e3725c6b85ccc03eb14bf8e4034adb`
- Measurement nodes: Master node (local)

## Diagnosis

**The TLS certificate has expired**

- Root cause (web): The TLS certificate for expired.badssl.com expired on 2015-04-12; browsers show a security error.
- Evidence: `subject=*.badssl.com issuer=COMODO RSA Domain Validation Secure Server CA valid 2015-04-09 → 2015-04-12 SAN=[*.badssl.com, badssl.com]`

### Fixes (in priority order)

1. **The TLS certificate has expired** — Renew the certificate now (e.g. certbot renew) and fix automatic renewal; reload the web server afterwards.
2. **No SPF record** — Publish one TXT record like: v=spf1 include:<your mail provider> -all
3. **No DMARC record** — Publish TXT at _dmarc: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain (start with p=none to monitor).
4. **HSTS is not enabled** — Add the header Strict-Transport-Security: max-age=31536000; includeSubDomains once HTTPS works everywhere.

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with MarkMonitor Inc., 175 days left |
| Name servers | ✅ OK | 4 name server(s) seen via public resolvers (direct checks unavailable) |
| DNS zone | ⚠️ WARN | 14 records from public resolvers over HTTPS (TTLs are cache-remaining; direct queries unavailable) |
| Reachability | ✅ OK | Reachable from 1 of 1 node(s) |
| Web server | ❌ FAIL | https://expired.badssl.com/ → 200 OK in 990 ms (from Master node) — but browsers reject the TLS certificate |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-04-07 (175 days left).

### ✅ Name servers — OK

- **INFO** `ns.limited_mode` This checker cannot query name servers directly (outbound port 53 is blocked), so DNS data comes from public resolvers over HTTPS. Lame-delegation, AA, glue and SOA-serial checks were not possible. (`DNS-over-HTTPS via Cloudflare, Google, Quad9`)

| Name server | IP | Status | AA | Serial | RTT ms |
|---|---|---|---|---|---|
| ns-cloud-c1.googledomains.com. | 216.239.32.108 | not tested | false | 0 | 0.0 |
| ns-cloud-c1.googledomains.com. | 2001:4860:4802:32::6c | not tested | false | 0 | 0.0 |
| ns-cloud-c2.googledomains.com. | 216.239.34.108 | not tested | false | 0 | 0.0 |
| ns-cloud-c2.googledomains.com. | 2001:4860:4802:34::6c | not tested | false | 0 | 0.0 |
| ns-cloud-c3.googledomains.com. | 216.239.36.108 | not tested | false | 0 | 0.0 |
| ns-cloud-c3.googledomains.com. | 2001:4860:4802:36::6c | not tested | false | 0 | 0.0 |
| ns-cloud-c4.googledomains.com. | 216.239.38.108 | not tested | false | 0 | 0.0 |
| ns-cloud-c4.googledomains.com. | 2001:4860:4802:38::6c | not tested | false | 0 | 0.0 |

### ⚠️ DNS zone — WARN

- **WARN** `mail.spf_missing` No SPF record: receivers cannot verify which servers may send mail for this domain. (`no TXT starting with v=spf1`)
- **WARN** `mail.dmarc_missing` No DMARC record: spoofed mail using this domain is not rejected or reported. (`no TXT at _dmarc.badssl.com`)
- **INFO** `dns.no_ipv6` No AAAA (IPv6) record.
- **INFO** `mail.dkim_none_found` No DKIM key found under common selectors (your provider may use a custom selector).
- **INFO** `dnssec.unsigned` DNSSEC is not enabled for this domain. (`no DS at parent`)

| Name | Type | TTL | Value |
|---|---|---|---|
| badssl.com | A | 300 | 104.154.89.105 |
| badssl.com | MX | 3600 | 40 alt4.gmr-smtp-in.l.google.com. |
| badssl.com | MX | 3600 | 5 gmr-smtp-in.l.google.com. |
| badssl.com | MX | 3600 | 20 alt2.gmr-smtp-in.l.google.com. |
| badssl.com | MX | 3600 | 10 alt1.gmr-smtp-in.l.google.com. |
| badssl.com | MX | 3600 | 30 alt3.gmr-smtp-in.l.google.com. |
| badssl.com | NS | 21600 | ns-cloud-c2.googledomains.com. |
| badssl.com | NS | 21600 | ns-cloud-c4.googledomains.com. |
| badssl.com | NS | 21600 | ns-cloud-c3.googledomains.com. |
| badssl.com | NS | 21600 | ns-cloud-c1.googledomains.com. |
| badssl.com | SOA | 21600 | ns-cloud-c1.googledomains.com. cloud-dns-hostmaster.google.com. 2 21600 3600 259200 300 |
| badssl.com | TXT | 300 | "_4wahjzefs6if6al9ai0ukockra7wb9c" |
| www.badssl.com | A | 300 | 104.154.89.105 |
| expired.badssl.com | A | 300 | 104.154.89.105 |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Master node | 104.154.89.105 | 4 | 4 | 0% | 0.0/0.0/0.0 | open | open | ok |

### ❌ Web server — FAIL

- **FAIL** `tls.expired` The TLS certificate for expired.badssl.com expired on 2015-04-12; browsers show a security error. (`subject=*.badssl.com issuer=COMODO RSA Domain Validation Secure Server CA valid 2015-04-09 → 2015-04-12 SAN=[*.badssl.com, badssl.com]`)
- **WARN** `web.no_hsts` No Strict-Transport-Security (HSTS) header: browsers may still try plain HTTP first. (`https://expired.badssl.com/`)
- **INFO** `web.missing_security_headers` Recommended security headers are missing: Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, X-Frame-Options. (`https://expired.badssl.com/`)

`http://expired.badssl.com/`

- http://expired.badssl.com/ → 301 Moved Permanently (547 ms) Location: https://expired.badssl.com/
- https://expired.badssl.com/ → 200 OK (1061 ms)

`https://expired.badssl.com/`

- https://expired.badssl.com/ → 200 OK (990 ms)

| Node | URL | Final | Status | Total ms |
|---|---|---|---|---|
| Master node | http://expired.badssl.com/ | https://expired.badssl.com/ | 200 | 1608 |
| Master node | https://expired.badssl.com/ | https://expired.badssl.com/ | 200 | 990 |
