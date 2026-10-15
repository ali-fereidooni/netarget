# netarget report: mixed.ddemo-site.com

- Checked: 2026-10-15 01:28:06 UTC
- Request ID: `fb931d19274b80da0e770de5daba78524aba4d69`
- Measurement nodes: Frankfurt (DE (demo)), Tehran (IR (demo))

## Diagnosis

**No blocking problem found, but there are warnings worth fixing.**


### Fixes (in priority order)

1. **Mixed content (HTTP resources on an HTTPS page)** — Change the resource URLs to https:// (or protocol-relative/relative URLs). (see the Website load section for all steps and server-specific snippets)
2. **Page resources fail to load** — Fix or remove the failing URLs; for third-party files, self-host critical assets or add fallbacks.

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with Demo Registrar Ltd., 199 days left |
| Name servers | ✅ OK | 2 name server(s) delegated by com, 2 of 2 addresses answer authoritatively |
| DNS zone | ✅ OK | 5 records from ns1.ddemo-site.com. (3.0.0.1) |
| Reachability | ✅ OK | Reachable from 2 of 2 node(s) |
| Website load | ⚠️ WARN | https://mixed.ddemo-site.com/ → 200 in 29 ms — The HTTPS page loads resources over plain HTTP; browsers block scripts/styles and mark the page as not secure |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-05-03 (199 days left).

### ✅ Name servers — OK


| Name server | IP | Status | AA | Serial | RTT ms |
|---|---|---|---|---|---|
| ns1.ddemo-site.com. | 3.0.0.1 | ok | true | 1 | 0.0 |
| ns2.ddemo-dns.net. | 3.0.1.1 | ok | true | 1 | 0.0 |

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
| mixed.ddemo-site.com | A | 300 | 127.0.0.1 |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Frankfurt | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |
| Tehran | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |

### ⚠️ Website load — WARN

- **WARN** `load.content.mixed` The HTTPS page loads resources over plain HTTP; browsers block scripts/styles and mark the page as not secure (`1 HTTP resource(s) on the HTTPS page: http://mixed.ddemo-site.com/app.js`)
- **WARN** `load.content.res-failed` Some CSS, JavaScript, image or font files on the page fail to load (see the resource table for hosts and statuses) (`1 resource(s) failed to load: https://mixed.ddemo-site.com/missing.png`)
- **INFO** `load.content.hsts-missing` HTTPS works but the site does not send Strict-Transport-Security, so browsers may still try plain HTTP first (`no Strict-Transport-Security header on https://mixed.ddemo-site.com/`)
- **INFO** `load.content.security-headers` Some recommended security headers are missing (see evidence) (`missing: content-security-policy, x-content-type-options, referrer-policy`)
- **INFO** `load.content.weak-cache` Static files have no or very short cache lifetimes, so repeat visits download them again (`2 static resource(s) without useful caching: https://mixed.ddemo-site.com/style.css, http://mixed.ddemo-site.com/app.js`)

**Verdict:** The HTTPS page loads resources over plain HTTP; browsers block scripts/styles and mark the page as not secure

- Layer at fault: **content** (confidence high, 90%)

Evidence:

- `1 HTTP resource(s) on the HTTPS page: http://mixed.ddemo-site.com/app.js`

Likely causes:

- (high) Hard-coded http:// URLs in templates, content or the database (common after moving to HTTPS).

Fix steps:

1. Change the resource URLs to https:// (or protocol-relative/relative URLs).

   wordpress:

   ```
   wp db export before-https.sql   # backup first
   wp search-replace 'http://mixed.ddemo-site.com' 'https://mixed.ddemo-site.com' --all-tables --dry-run
   # then without --dry-run
   ```

   - Verify: The resource table shows no mixed_content items; the browser console has no mixed-content warnings.
2. As a safety net, ask browsers to upgrade remaining requests.

   nginx:

   ```
   add_header Content-Security-Policy "upgrade-insecure-requests" always;
   ```

   - Verify: Remaining http:// resources load over https.

Could not determine from outside:

- Resources added later by JavaScript (only the static HTML is analysed).

| Kind | Detected | Confidence | Evidence |
|---|---|---|---|
| server | nginx | medium | header server: nginx/1.27.5 (GET http://mixed.ddemo-site.com/) |

| Node | Request | Final | Result | Proto | TTFB ms | Total ms | Differs |
|---|---|---|---|---|---|---|---|
| Frankfurt | GET https://mixed.ddemo-site.com/ | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 29 | 29 |  |
| Frankfurt | GET http://mixed.ddemo-site.com/ | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 16 | 16 |  |
| Frankfurt | HEAD https://mixed.ddemo-site.com/ | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 21 | 21 |  |
| Frankfurt | GET https://mixed.ddemo-site.com/ curl UA | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 46 | 46 |  |
| Frankfurt | GET https://mixed.ddemo-site.com/ googlebot UA | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 38 | 38 |  |
| Frankfurt | GET https://mixed.ddemo-site.com/ HTTP/1.1 | https://mixed.ddemo-site.com/ | 200 | HTTP/1.1 | 45 | 45 |  |
| Frankfurt | GET https://mixed.ddemo-site.com/ HTTP/2 | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 53 | 53 |  |
| Frankfurt | GET https://mixed.ddemo-site.com/ gzip | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 53 | 54 |  |
| Frankfurt | GET https://mixed.ddemo-site.com/ no compression | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 42 | 42 |  |
| Tehran | GET https://mixed.ddemo-site.com/ | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 39 | 40 |  |
| Tehran | GET http://mixed.ddemo-site.com/ | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 23 | 23 |  |
| Tehran | HEAD https://mixed.ddemo-site.com/ | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 55 | 55 |  |
| Tehran | GET https://mixed.ddemo-site.com/ curl UA | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 38 | 38 |  |
| Tehran | GET https://mixed.ddemo-site.com/ googlebot UA | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 45 | 45 |  |
| Tehran | GET https://mixed.ddemo-site.com/ HTTP/1.1 | https://mixed.ddemo-site.com/ | 200 | HTTP/1.1 | 27 | 27 |  |
| Tehran | GET https://mixed.ddemo-site.com/ HTTP/2 | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 22 | 22 |  |
| Tehran | GET https://mixed.ddemo-site.com/ gzip | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 18 | 18 |  |
| Tehran | GET https://mixed.ddemo-site.com/ no compression | https://mixed.ddemo-site.com/ | 200 | HTTP/2.0 | 43 | 43 |  |

Resources (3 found, 3 checked):

| Kind | URL | Status | ms | Size | Issues |
|---|---|---|---|---|---|
| stylesheet | https://mixed.ddemo-site.com/style.css | 200 | 13 | 29 | weak_cache |
| script | http://mixed.ddemo-site.com/app.js | 200 | 11 | 21 | mixed_content, weak_cache |
| image | https://mixed.ddemo-site.com/missing.png | 404 | 7 | 555 | failed |

- Also: **Page resources fail to load** — Some CSS, JavaScript, image or font files on the page fail to load (see the resource table for hosts and statuses) (warn, high)

- Also: **HSTS not enabled** — HTTPS works but the site does not send Strict-Transport-Security, so browsers may still try plain HTTP first (info, high)

- Also: **Recommended security headers missing** — Some recommended security headers are missing (see evidence) (info, high)

- Also: **Static assets are not cacheable** — Static files have no or very short cache lifetimes, so repeat visits download them again (info, medium)
