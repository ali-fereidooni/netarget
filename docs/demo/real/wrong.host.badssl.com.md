# Domain Doctor report: wrong.host.badssl.com

- Checked: 2026-10-14 21:03:23 UTC
- Request ID: `b2e681c18d4f5d7f6f350909219886b588fee975`
- Measurement nodes: Master node (local)

## Diagnosis

**The TLS certificate does not match the host name**

- Root cause (web): The certificate presented for wrong.host.badssl.com does not cover that name.
- Evidence: `subject=*.badssl.com issuer=YR1 valid 2026-09-29 → 2026-12-28 SAN=[*.badssl.com, badssl.com]`

### Fixes (in priority order)

1. **The TLS certificate does not match the host name** — Issue a certificate that includes this name (and www), or fix the virtual host/SNI so the right certificate is served.
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
| Web server | ❌ FAIL | https://wrong.host.badssl.com/ → 200 OK in 992 ms (from Master node) — but browsers reject the TLS certificate |

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
| badssl.com | MX | 3600 | 30 alt3.gmr-smtp-in.l.google.com. |
| badssl.com | MX | 3600 | 40 alt4.gmr-smtp-in.l.google.com. |
| badssl.com | MX | 3600 | 5 gmr-smtp-in.l.google.com. |
| badssl.com | MX | 3600 | 10 alt1.gmr-smtp-in.l.google.com. |
| badssl.com | MX | 3600 | 20 alt2.gmr-smtp-in.l.google.com. |
| badssl.com | NS | 21600 | ns-cloud-c4.googledomains.com. |
| badssl.com | NS | 21600 | ns-cloud-c3.googledomains.com. |
| badssl.com | NS | 21600 | ns-cloud-c2.googledomains.com. |
| badssl.com | NS | 21600 | ns-cloud-c1.googledomains.com. |
| badssl.com | SOA | 21600 | ns-cloud-c1.googledomains.com. cloud-dns-hostmaster.google.com. 2 21600 3600 259200 300 |
| badssl.com | TXT | 300 | "_4wahjzefs6if6al9ai0ukockra7wb9c" |
| www.badssl.com | A | 300 | 104.154.89.105 |
| wrong.host.badssl.com | A | 300 | 104.154.89.105 |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Master node | 104.154.89.105 | 4 | 4 | 0% | 0.0/0.0/3.0 | open | open | ok |

### ❌ Web server — FAIL

- **FAIL** `tls.hostname_mismatch` The certificate presented for wrong.host.badssl.com does not cover that name. (`subject=*.badssl.com issuer=YR1 valid 2026-09-29 → 2026-12-28 SAN=[*.badssl.com, badssl.com]`)
- **WARN** `web.no_hsts` No Strict-Transport-Security (HSTS) header: browsers may still try plain HTTP first. (`https://wrong.host.badssl.com/`)
- **INFO** `web.missing_security_headers` Recommended security headers are missing: Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, X-Frame-Options. (`https://wrong.host.badssl.com/`)

`http://wrong.host.badssl.com/`

- http://wrong.host.badssl.com/ → 301 Moved Permanently (493 ms) Location: https://wrong.host.badssl.com/
- https://wrong.host.badssl.com/ → 200 OK (1177 ms)

`https://wrong.host.badssl.com/`

- https://wrong.host.badssl.com/ → 200 OK (992 ms)

| Node | URL | Final | Status | Total ms |
|---|---|---|---|---|
| Master node | http://wrong.host.badssl.com/ | https://wrong.host.badssl.com/ | 200 | 1670 |
| Master node | https://wrong.host.badssl.com/ | https://wrong.host.badssl.com/ | 200 | 992 |
