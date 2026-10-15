# netarget report: nginx-503.ddemo-site.com

- Checked: 2026-10-15 01:28:06 UTC
- Request ID: `a0bc28777965159ac6a850d835e2ea463b24cd43`
- Measurement nodes: Frankfurt (DE (demo)), Tehran (IR (demo))

## Diagnosis

**No blocking problem found, but there are warnings worth fixing.**


### Fixes (in priority order)

1. **503 — the site is in maintenance mode** — Finish or abort the update and switch maintenance mode off.

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with Demo Registrar Ltd., 199 days left |
| Name servers | ✅ OK | 2 name server(s) delegated by com, 2 of 2 addresses answer authoritatively |
| DNS zone | ✅ OK | 5 records from ns1.ddemo-site.com. (3.0.0.1) |
| Reachability | ✅ OK | Reachable from 2 of 2 node(s) |
| Website load | ⚠️ WARN | https://nginx-503.ddemo-site.com/ → 503 in 41 ms — The site is deliberately in maintenance mode (503) |

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
| nginx-503.ddemo-site.com | A | 300 | 127.0.0.1 |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Frankfurt | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |
| Tehran | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |

### ⚠️ Website load — WARN

- **WARN** `load.http.503.maintenance` The site is deliberately in maintenance mode (503) (`HTTP 503 on GET https://nginx-503.ddemo-site.com/ (browser UA); the page says the site is in maintenance: Briefly unavailable for scheduled maintenance; Retry-After: 120 (Retry-After header present)`)

**Verdict:** The site is deliberately in maintenance mode (503)

- Layer at fault: **application** (confidence high, 90%)

Evidence:

- `HTTP 503 on GET https://nginx-503.ddemo-site.com/ (browser UA)`
- `the page says the site is in maintenance: Briefly unavailable for scheduled maintenance`
- `Retry-After: 120 (Retry-After header present)`

Likely causes:

- (high) A maintenance mode left on after an update (WordPress .maintenance file, Laravel 'php artisan down').

Fix steps:

1. Finish or abort the update and switch maintenance mode off.

   laravel:

   ```
   php artisan up
   ```


   wordpress:

   ```
   rm .maintenance    # in the WordPress root, after the update finished
   ```

   - Verify: curl -sI https://nginx-503.ddemo-site.com/ returns 200.

Could not determine from outside:

- Whether an update is still running.

| Kind | Detected | Confidence | Evidence |
|---|---|---|---|
| server | nginx | medium | header server: nginx/1.27.5 (GET http://nginx-503.ddemo-site.com/) |

| Node | Request | Final | Result | Proto | TTFB ms | Total ms | Differs |
|---|---|---|---|---|---|---|---|
| Frankfurt | GET https://nginx-503.ddemo-site.com/ | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 41 | 41 |  |
| Frankfurt | GET http://nginx-503.ddemo-site.com/ | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 15 | 15 |  |
| Frankfurt | HEAD https://nginx-503.ddemo-site.com/ | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 33 | 33 |  |
| Frankfurt | GET https://nginx-503.ddemo-site.com/ curl UA | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 25 | 25 |  |
| Frankfurt | GET https://nginx-503.ddemo-site.com/ googlebot UA | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 17 | 17 |  |
| Frankfurt | GET https://nginx-503.ddemo-site.com/ HTTP/1.1 | https://nginx-503.ddemo-site.com/ | 503 | HTTP/1.1 | 23 | 23 |  |
| Frankfurt | GET https://nginx-503.ddemo-site.com/ HTTP/2 | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 30 | 30 |  |
| Frankfurt | GET https://nginx-503.ddemo-site.com/ gzip | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 16 | 17 |  |
| Frankfurt | GET https://nginx-503.ddemo-site.com/ no compression | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 22 | 22 |  |
| Tehran | GET https://nginx-503.ddemo-site.com/ | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 15 | 16 |  |
| Tehran | GET http://nginx-503.ddemo-site.com/ | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 18 | 18 |  |
| Tehran | HEAD https://nginx-503.ddemo-site.com/ | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 40 | 40 |  |
| Tehran | GET https://nginx-503.ddemo-site.com/ curl UA | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 42 | 42 |  |
| Tehran | GET https://nginx-503.ddemo-site.com/ googlebot UA | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 39 | 39 |  |
| Tehran | GET https://nginx-503.ddemo-site.com/ HTTP/1.1 | https://nginx-503.ddemo-site.com/ | 503 | HTTP/1.1 | 29 | 29 |  |
| Tehran | GET https://nginx-503.ddemo-site.com/ HTTP/2 | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 49 | 49 |  |
| Tehran | GET https://nginx-503.ddemo-site.com/ gzip | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 20 | 20 |  |
| Tehran | GET https://nginx-503.ddemo-site.com/ no compression | https://nginx-503.ddemo-site.com/ | 503 | HTTP/2.0 | 20 | 20 |  |
