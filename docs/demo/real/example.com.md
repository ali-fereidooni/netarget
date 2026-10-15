# netarget report: example.com

- Checked: 2026-10-15 01:31:39 UTC
- Request ID: `516d4d36f09904496f2429b403abbe9aedd29933`
- Measurement nodes: Master node (local)

## Diagnosis

**No blocking problem found, but there are warnings worth fixing.**


### Fixes (in priority order)

1. **HTTP does not redirect to HTTPS** — Add a permanent redirect from HTTP to HTTPS.
2. **Bare domain and www serve separate copies** — Pick one canonical host and 301-redirect the other.

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with RESERVED-Internet Assigned Numbers Authority, 302 days left |
| Name servers | ✅ OK | 2 name server(s) seen via public resolvers (direct checks unavailable) |
| DNS zone | ✅ OK | 14 records from public resolvers over HTTPS (TTLs are cache-remaining; direct queries unavailable) |
| Reachability | ✅ OK | Reachable from 1 of 1 node(s) |
| Website load | ⚠️ WARN | https://example.com/ → 200 in 450 ms — http://example.com/ serves the site unencrypted instead of redirecting to HTTPS |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-08-13 (302 days left).

### ✅ Name servers — OK

- **INFO** `ns.limited_mode` This checker cannot query name servers directly (outbound port 53 is blocked), so DNS data comes from public resolvers over HTTPS. Lame-delegation, AA, glue and SOA-serial checks were not possible. (`DNS-over-HTTPS via Cloudflare, Google, Quad9`)

| Name server | IP | Status | AA | Serial | RTT ms |
|---|---|---|---|---|---|
| elliott.ns.cloudflare.com. | 108.162.195.228 | not tested | false | 0 | 0.0 |
| elliott.ns.cloudflare.com. | 162.159.44.228 | not tested | false | 0 | 0.0 |
| elliott.ns.cloudflare.com. | 172.64.35.228 | not tested | false | 0 | 0.0 |
| elliott.ns.cloudflare.com. | 2606:4700:58::a29f:2ce4 | not tested | false | 0 | 0.0 |
| hera.ns.cloudflare.com. | 108.162.192.162 | not tested | false | 0 | 0.0 |
| hera.ns.cloudflare.com. | 172.64.32.162 | not tested | false | 0 | 0.0 |
| hera.ns.cloudflare.com. | 173.245.58.162 | not tested | false | 0 | 0.0 |
| hera.ns.cloudflare.com. | 2606:4700:50::adf5:3aa2 | not tested | false | 0 | 0.0 |

### ✅ DNS zone — OK

- **INFO** `dns.null_mx` Null MX published: the domain declares it accepts no mail.
- **INFO** `dnssec.valid` DNSSEC chain DS → DNSKEY → RRSIG validates. (`parent publishes 1 DS record(s); DS matches DNSKEY 2371; DNSKEY RRset signed by 2371: valid; SOA signed by 34505: valid`)

| Name | Type | TTL | Value |
|---|---|---|---|
| example.com | A | 34 | 104.20.23.154 |
| example.com | A | 34 | 172.66.147.243 |
| example.com | AAAA | 16 | 2606:4700:10::ac42:93f3 |
| example.com | AAAA | 16 | 2606:4700:10::6814:179a |
| example.com | MX | 48 | 0 . |
| example.com | NS | 86400 | hera.ns.cloudflare.com. |
| example.com | NS | 86400 | elliott.ns.cloudflare.com. |
| example.com | SOA | 1800 | elliott.ns.cloudflare.com. dns.cloudflare.com. 2416374680 10000 2400 604800 1800 |
| example.com | TXT | 166 | "v=spf1 -all" |
| example.com | TXT | 166 | "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9" |
| www.example.com | A | 300 | 104.20.23.154 |
| www.example.com | A | 300 | 172.66.147.243 |
| www.example.com | AAAA | 194 | 2606:4700:10::6814:179a |
| www.example.com | AAAA | 194 | 2606:4700:10::ac42:93f3 |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Master node | 104.20.23.154 | 4 | 4 | 0% | 0.0/0.0/0.0 | open | open | ok |
| Master node | 172.66.147.243 | 4 | 4 | 0% | 0.0/0.0/0.0 | open | open | ok |
| Master node | 2606:4700:10::ac42:93f3 | — | — | — | this node has no IPv6 connectivity | — | — | n/a |
| Master node | 2606:4700:10::6814:179a | — | — | — | this node has no IPv6 connectivity | — | — | n/a |

### ⚠️ Website load — WARN

- **WARN** `load.site.no-https-redirect` http://example.com/ serves the site unencrypted instead of redirecting to HTTPS (`GET http://example.com/ → 200 (stays on http://)`)
- **WARN** `load.site.apex-www-split` The bare domain and www both serve the site without redirecting to one canonical address (`https://example.com/ and https://www.example.com/ end at different hosts`)
- **INFO** `load.content.hsts-missing` HTTPS works but the site does not send Strict-Transport-Security, so browsers may still try plain HTTP first (`no Strict-Transport-Security header on https://example.com/`)
- **INFO** `load.content.security-headers` Some recommended security headers are missing (see evidence) (`missing: content-security-policy, x-content-type-options, referrer-policy`)
- **INFO** `load.content.weak-cache` Static files have no or very short cache lifetimes, so repeat visits download them again (`1 static resource(s) without useful caching: https://example.com/s.js`)

**Verdict:** http://example.com/ serves the site unencrypted instead of redirecting to HTTPS

- Layer at fault: **server** (confidence high, 85%)

Evidence:

- `GET http://example.com/ → 200 (stays on http://)`

Likely causes:

- (high) No HTTP → HTTPS redirect is configured.

Fix steps:

1. Add a permanent redirect from HTTP to HTTPS.

   apache:

   ```
   RewriteEngine On
   RewriteCond %{HTTPS} off
   RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
   ```


   cloudflare:

   ```
   SSL/TLS → Edge Certificates → Always Use HTTPS: On
   ```


   iis:

   ```
   <rule name="HTTPS" stopProcessing="true"><match url="(.*)" /><conditions><add input="{HTTPS}" pattern="off" /></conditions><action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" /></rule>
   ```


   litespeed:

   ```
   RewriteEngine On
   RewriteCond %{HTTPS} off
   RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
   ```


   nginx:

   ```
   server { listen 80; server_name example.com www.example.com; return 301 https://$host$request_uri; }
   ```

   - Verify: curl -sI http://example.com/ returns 301 with Location: https://…

Could not determine from outside:

- Whether some HTTP-only clients must keep working.

| Kind | Detected | Confidence | Evidence |
|---|---|---|---|
| cdn | Cloudflare | high | header cf-ray: a4ab1107eeb2365b-FRA (GET http://example.com/); header server: cloudflare (GET http://example.com/); header cf-cache-status: HIT (GET http://example.com/); address 104.20.23.154 is in 104.16.0.0/13 |

| Node | Request | Final | Result | Proto | TTFB ms | Total ms | Differs |
|---|---|---|---|---|---|---|---|
| Master node | GET https://example.com/ | https://example.com/ | 200 | HTTP/2.0 | 450 | 450 |  |
| Master node | GET http://example.com/ | http://example.com/ | 200 | HTTP/1.1 | 348 | 349 |  |
| Master node | GET https://www.example.com/ | https://www.example.com/ | 200 | HTTP/2.0 | 501 | 501 |  |
| Master node | GET http://www.example.com/ | http://www.example.com/ | 200 | HTTP/1.1 | 276 | 276 |  |
| Master node | HEAD https://example.com/ | https://example.com/ | 200 | HTTP/2.0 | 497 | 497 |  |
| Master node | GET https://example.com/ curl UA | https://example.com/ | 200 | HTTP/2.0 | 497 | 497 |  |
| Master node | GET https://example.com/ googlebot UA | https://example.com/ | 200 | HTTP/2.0 | 424 | 424 |  |
| Master node | GET https://example.com/ HTTP/1.1 | https://example.com/ | 200 | HTTP/1.1 | 494 | 494 |  |
| Master node | GET https://example.com/ HTTP/2 | https://example.com/ | 200 | HTTP/2.0 | 440 | 440 |  |
| Master node | GET https://example.com/ gzip | https://example.com/ | 200 | HTTP/2.0 | 434 | 434 |  |
| Master node | GET https://example.com/ no compression | https://example.com/ | 200 | HTTP/2.0 | 495 | 495 |  |

Resources (1 found, 1 checked):

| Kind | URL | Status | ms | Size | Issues |
|---|---|---|---|---|---|
| script | https://example.com/s.js | 200 | 441 | 1333 | weak_cache |

- Also: **Bare domain and www serve separate copies** — The bare domain and www both serve the site without redirecting to one canonical address (warn, medium)

- Also: **HSTS not enabled** — HTTPS works but the site does not send Strict-Transport-Security, so browsers may still try plain HTTP first (info, high)

- Also: **Recommended security headers missing** — Some recommended security headers are missing (see evidence) (info, high)

- Also: **Static assets are not cacheable** — Static files have no or very short cache lifetimes, so repeat visits download them again (info, medium)
