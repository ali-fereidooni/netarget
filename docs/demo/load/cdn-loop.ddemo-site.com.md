# Domain Doctor report: cdn-loop.ddemo-site.com

- Checked: 2026-10-15 01:28:07 UTC
- Request ID: `0ca49ef589f35ec114200847b692efe9fbd386a5`
- Measurement nodes: Frankfurt (DE (demo)), Tehran (IR (demo))

## Diagnosis

**Redirect loop caused by Cloudflare Flexible SSL**

- Root cause (web): The site redirects forever: Cloudflare connects to the origin over HTTP while the origin forces HTTPS (Flexible SSL loop)
- Evidence: `GET https://cdn-loop.ddemo-site.com/ → redirect loop after 1 hops; CDN/WAF detected: Cloudflare`

### Fixes (in priority order)

1. **Redirect loop caused by Cloudflare Flexible SSL** — Install a certificate on the origin and set Cloudflare → SSL/TLS to Full (strict). (see the Website load section for all steps and server-specific snippets)

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with Demo Registrar Ltd., 199 days left |
| Name servers | ✅ OK | 2 name server(s) delegated by com, 2 of 2 addresses answer authoritatively |
| DNS zone | ✅ OK | 5 records from ns1.ddemo-site.com. (3.0.0.1) |
| Reachability | ✅ OK | Reachable from 2 of 2 node(s) |
| Website load | ❌ FAIL | https://cdn-loop.ddemo-site.com/ → 301 in 18 ms — The site redirects forever: Cloudflare connects to the origin over HTTP while the origin forces HTTPS (Flexible SSL loop) |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-05-03 (199 days left).

### ✅ Name servers — OK


| Name server | IP | Status | AA | Serial | RTT ms |
|---|---|---|---|---|---|
| ns1.ddemo-site.com. | 3.0.0.1 | ok | true | 1 | 0.6 |
| ns2.ddemo-dns.net. | 3.0.1.1 | ok | true | 1 | 0.6 |

### ✅ DNS zone — OK

- **INFO** `dns.no_www` www has no address record; visitors typing www. will get an error.
- **INFO** `dns.no_ipv6` No AAAA (IPv6) record.
- **INFO** `dns.no_mx` No MX record: the domain cannot receive email (fine if intended).
- **INFO** `dnssec.unsigned` DNSSEC is not enabled for this domain. (`no DS at parent`)

| Name | Type | TTL | Value |
|---|---|---|---|
| ddemo-site.com | NS | 3600 | ns1.ddemo-site.com. |
| ddemo-site.com | NS | 3600 | ns2.ddemo-dns.net. |
| ddemo-site.com | SOA | 3600 | ns1.ddemo-site.com. hostmaster.ddemo-site.com. 1 7200 3600 1209600 300 |
| ddemo-site.com | TXT | 3600 | "v=spf1 -all" |
| cdn-loop.ddemo-site.com | A | 300 | 127.0.0.1 |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Frankfurt | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |
| Tehran | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |

### ❌ Website load — FAIL

- **FAIL** `load.cf.flexible-loop` The site redirects forever: Cloudflare connects to the origin over HTTP while the origin forces HTTPS (Flexible SSL loop) (`GET https://cdn-loop.ddemo-site.com/ → redirect loop after 1 hops; CDN/WAF detected: Cloudflare`)

**Verdict:** The site redirects forever: Cloudflare connects to the origin over HTTP while the origin forces HTTPS (Flexible SSL loop)

- Layer at fault: **cdn** (confidence high, 85%)

Evidence:

- `GET https://cdn-loop.ddemo-site.com/ → redirect loop after 1 hops`
- `CDN/WAF detected: Cloudflare`

Likely causes:

- (high) Cloudflare SSL mode is Flexible, and the origin redirects HTTP to HTTPS, so every request bounces back.
- (medium) Both a Cloudflare redirect rule and the origin redirect to different canonical hosts (www vs apex).

Fix steps:

1. Install a certificate on the origin and set Cloudflare → SSL/TLS to Full (strict).
   - Verify: curl -sIL https://cdn-loop.ddemo-site.com/ ends with HTTP 200 after at most one redirect.
2. Keep exactly one place that redirects to the canonical URL (either Cloudflare 'Always Use HTTPS' or the origin), not two that disagree.

   apache:

   ```
   RewriteEngine On
   RewriteCond %{HTTPS} off
   RewriteCond %{HTTP:X-Forwarded-Proto} !https
   RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
   ```


   nginx:

   ```
   # only redirect when the original client request was HTTP
   if ($http_x_forwarded_proto = "http") { return 301 https://$host$request_uri; }
   ```

   - Verify: The redirect chain is http → https → 200 with no repeats.

Could not determine from outside:

- The Cloudflare SSL mode and redirect rules in your dashboard.

| Kind | Detected | Confidence | Evidence |
|---|---|---|---|
| cdn | Cloudflare | high | header cf-ray: 8c1d2e3f4a5b6c7d-FRA (GET http://cdn-loop.ddemo-site.com/); header server: cloudflare (GET http://cdn-loop.ddemo-site.com/); header cf-cache-status: DYNAMIC (GET http://cdn-loop.ddemo-site.com/) |

| Node | Request | Final | Result | Proto | TTFB ms | Total ms | Differs |
|---|---|---|---|---|---|---|---|
| Frankfurt | GET https://cdn-loop.ddemo-site.com/ | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 18 | 18 |  |
| Frankfurt | GET http://cdn-loop.ddemo-site.com/ | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 11 | 11 |  |
| Frankfurt | HEAD https://cdn-loop.ddemo-site.com/ | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 20 | 21 |  |
| Frankfurt | GET https://cdn-loop.ddemo-site.com/ curl UA | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 26 | 27 |  |
| Frankfurt | GET https://cdn-loop.ddemo-site.com/ googlebot UA | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 17 | 17 |  |
| Frankfurt | GET https://cdn-loop.ddemo-site.com/ HTTP/1.1 | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/1.1 | 32 | 33 |  |
| Frankfurt | GET https://cdn-loop.ddemo-site.com/ HTTP/2 | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 28 | 28 |  |
| Frankfurt | GET https://cdn-loop.ddemo-site.com/ gzip | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 19 | 20 |  |
| Frankfurt | GET https://cdn-loop.ddemo-site.com/ no compression | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 20 | 21 |  |
| Tehran | GET https://cdn-loop.ddemo-site.com/ | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 18 | 18 |  |
| Tehran | GET http://cdn-loop.ddemo-site.com/ | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 17 | 17 |  |
| Tehran | HEAD https://cdn-loop.ddemo-site.com/ | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 20 | 21 |  |
| Tehran | GET https://cdn-loop.ddemo-site.com/ curl UA | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 17 | 17 |  |
| Tehran | GET https://cdn-loop.ddemo-site.com/ googlebot UA | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 19 | 20 |  |
| Tehran | GET https://cdn-loop.ddemo-site.com/ HTTP/1.1 | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/1.1 | 17 | 18 |  |
| Tehran | GET https://cdn-loop.ddemo-site.com/ HTTP/2 | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 30 | 30 |  |
| Tehran | GET https://cdn-loop.ddemo-site.com/ gzip | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 18 | 18 |  |
| Tehran | GET https://cdn-loop.ddemo-site.com/ no compression | https://cdn-loop.ddemo-site.com/ | redirect loop | HTTP/2.0 | 32 | 32 |  |
