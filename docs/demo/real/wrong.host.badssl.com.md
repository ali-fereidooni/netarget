# netarget report: wrong.host.badssl.com

- Checked: 2026-10-15 01:32:26 UTC
- Request ID: `67bf7be79ebb588c11d2ff99f8e0b65222f58862`
- Measurement nodes: Master node (local)

## Diagnosis

**Certificate does not match the host name**

- Root cause (web): The server presents a certificate for a different name than wrong.host.badssl.com; the request probably reaches the wrong virtual host
- Evidence: `certificate for *.badssl.com does not cover wrong.host.badssl.com (SAN *.badssl.com, badssl.com)`

### Fixes (in priority order)

1. **Certificate does not match the host name** — Issue a certificate that covers {host} (and www.{host} if visitors use it). (see the Website load section for all steps and server-specific snippets)
2. **No SPF record** — Publish one TXT record like: v=spf1 include:<your mail provider> -all
3. **No DMARC record** — Publish TXT at _dmarc: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain (start with p=none to monitor).

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with MarkMonitor Inc., 174 days left |
| Name servers | ✅ OK | 4 name server(s) seen via public resolvers (direct checks unavailable) |
| DNS zone | ⚠️ WARN | 14 records from public resolvers over HTTPS (TTLs are cache-remaining; direct queries unavailable) |
| Reachability | ✅ OK | Reachable from 1 of 1 node(s) |
| Website load | ❌ FAIL | https://wrong.host.badssl.com/ → 200 in 980 ms — The server presents a certificate for a different name than wrong.host.badssl.com; the request probably reaches the wrong virtual host |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-04-07 (174 days left).

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
| badssl.com | MX | 3600 | 20 alt2.gmr-smtp-in.l.google.com. |
| badssl.com | MX | 3600 | 5 gmr-smtp-in.l.google.com. |
| badssl.com | MX | 3600 | 10 alt1.gmr-smtp-in.l.google.com. |
| badssl.com | MX | 3600 | 40 alt4.gmr-smtp-in.l.google.com. |
| badssl.com | NS | 21600 | ns-cloud-c4.googledomains.com. |
| badssl.com | NS | 21600 | ns-cloud-c2.googledomains.com. |
| badssl.com | NS | 21600 | ns-cloud-c3.googledomains.com. |
| badssl.com | NS | 21600 | ns-cloud-c1.googledomains.com. |
| badssl.com | SOA | 21600 | ns-cloud-c1.googledomains.com. cloud-dns-hostmaster.google.com. 2 21600 3600 259200 300 |
| badssl.com | TXT | 300 | "_4wahjzefs6if6al9ai0ukockra7wb9c" |
| www.badssl.com | A | 300 | 104.154.89.105 |
| wrong.host.badssl.com | A | 300 | 104.154.89.105 |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Master node | 104.154.89.105 | 4 | 4 | 0% | 0.0/0.0/0.0 | open | open | ok |

### ❌ Website load — FAIL

- **FAIL** `load.tls.hostname-mismatch` The server presents a certificate for a different name than wrong.host.badssl.com; the request probably reaches the wrong virtual host (`certificate for *.badssl.com does not cover wrong.host.badssl.com (SAN *.badssl.com, badssl.com)`)
- **INFO** `load.content.hsts-missing` HTTPS works but the site does not send Strict-Transport-Security, so browsers may still try plain HTTP first (`no Strict-Transport-Security header on https://wrong.host.badssl.com/`)
- **INFO** `load.content.no-compression` HTML, CSS or JavaScript is sent uncompressed, making pages slower than necessary (`1 text resource(s) sent uncompressed: https://wrong.host.badssl.com/style.css`)
- **INFO** `load.content.no-http2` The server only speaks HTTP/1.1; HTTP/2 would load pages with many resources faster (`the server negotiated HTTP/1.1 when HTTP/2 was offered`)
- **INFO** `load.content.security-headers` Some recommended security headers are missing (see evidence) (`missing: content-security-policy, x-content-type-options, referrer-policy`)
- **INFO** `load.content.weak-cache` Static files have no or very short cache lifetimes, so repeat visits download them again (`3 static resource(s) without useful caching: https://wrong.host.badssl.com/style.css, https://wrong.host.badssl.com/icons/favicon-red.ico, https://wrong.host.badssl.com/icons/icon-red.png`)

**Verdict:** The server presents a certificate for a different name than wrong.host.badssl.com; the request probably reaches the wrong virtual host

- Layer at fault: **tls** (confidence high, 85%)

Evidence:

- `certificate for *.badssl.com does not cover wrong.host.badssl.com (SAN *.badssl.com, badssl.com)`

Likely causes:

- (high) {host} (or www) is missing from the certificate's names (SAN).
- (high) The TLS virtual host for {host} is missing, so the server's default certificate/site answers.

Fix steps:

1. Issue a certificate that covers wrong.host.badssl.com (and www.wrong.host.badssl.com if visitors use it).

   nginx:

   ```
   sudo certbot --nginx -d wrong.host.badssl.com   # add -d www.wrong.host.badssl.com only if www points to this server
   ```

   - Verify: The certificate's SAN list contains the host name.
2. Make sure a 443 virtual host has server_name/ServerName wrong.host.badssl.com and uses that certificate.

   nginx:

   ```
   server { listen 443 ssl; server_name wrong.host.badssl.com www.wrong.host.badssl.com; ... }
   ```

   - Verify: openssl s_client -connect wrong.host.badssl.com:443 -servername wrong.host.badssl.com shows the right subject.

Could not determine from outside:

- Which virtual host currently answers on the server.

| Kind | Detected | Confidence | Evidence |
|---|---|---|---|
| server | nginx | medium | header server: nginx/1.10.3 (Ubuntu) (GET http://wrong.host.badssl.com/) |

| Node | Request | Final | Result | Proto | TTFB ms | Total ms | Differs |
|---|---|---|---|---|---|---|---|
| Master node | GET https://wrong.host.badssl.com/ | https://wrong.host.badssl.com/ | 200 | HTTP/1.1 | 980 | 980 |  |
| Master node | GET http://wrong.host.badssl.com/ | https://wrong.host.badssl.com/ | 200 | HTTP/1.1 | 974 | 974 |  |
| Master node | HEAD https://wrong.host.badssl.com/ | https://wrong.host.badssl.com/ | 200 | HTTP/1.1 | 965 | 965 |  |
| Master node | GET https://wrong.host.badssl.com/ curl UA | https://wrong.host.badssl.com/ | 200 | HTTP/1.1 | 1056 | 1056 |  |
| Master node | GET https://wrong.host.badssl.com/ googlebot UA | https://wrong.host.badssl.com/ | 200 | HTTP/1.1 | 1025 | 1025 |  |
| Master node | GET https://wrong.host.badssl.com/ HTTP/1.1 | https://wrong.host.badssl.com/ | 200 | HTTP/1.1 | 1018 | 1018 |  |
| Master node | GET https://wrong.host.badssl.com/ HTTP/2 | https://wrong.host.badssl.com/ | 200 | HTTP/1.1 | 1051 | 1051 |  |
| Master node | GET https://wrong.host.badssl.com/ gzip | https://wrong.host.badssl.com/ | 200 | HTTP/1.1 | 959 | 959 |  |
| Master node | GET https://wrong.host.badssl.com/ no compression | https://wrong.host.badssl.com/ | 200 | HTTP/1.1 | 1031 | 1031 |  |

Resources (3 found, 3 checked):

| Kind | URL | Status | ms | Size | Issues |
|---|---|---|---|---|---|
| stylesheet | https://wrong.host.badssl.com/style.css | 200 | 1030 | 1506 | uncompressed, weak_cache |
| icon | https://wrong.host.badssl.com/icons/favicon-red.ico | 200 | 1027 | 5430 | weak_cache |
| icon | https://wrong.host.badssl.com/icons/icon-red.png | 200 | 1023 | 3858 | weak_cache |

- Also: **HSTS not enabled** — HTTPS works but the site does not send Strict-Transport-Security, so browsers may still try plain HTTP first (info, high)

- Also: **Text responses are not compressed** — HTML, CSS or JavaScript is sent uncompressed, making pages slower than necessary (info, high)

- Also: **HTTP/2 not available** — The server only speaks HTTP/1.1; HTTP/2 would load pages with many resources faster (info, high)

- Also: **Recommended security headers missing** — Some recommended security headers are missing (see evidence) (info, high)

- Also: **Static assets are not cacheable** — Static files have no or very short cache lifetimes, so repeat visits download them again (info, medium)
