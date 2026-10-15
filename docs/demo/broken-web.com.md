# netarget report: broken-web.com

- Checked: 2026-10-15 01:28:06 UTC
- Request ID: `5cda6b21c8a9db698932ece3dbeef0104829246f`
- Measurement nodes: Frankfurt (DE (demo)), Tehran (IR (demo))

## Diagnosis

**Expired TLS certificate**

- Root cause (web): The TLS certificate for broken-web.com has expired; browsers show a security warning instead of the site
- Evidence: `certificate expired 2026-10-12 (issuer netarget Demo CA)`
- Also a cause (web): nginx cannot get a response from the application behind it (502 Bad Gateway)

### Fixes (in priority order)

1. **Expired TLS certificate** — Renew the certificate and reload the web server. (see the Website load section for all steps and server-specific snippets)
2. **502 Bad Gateway from the origin's reverse proxy** — Check that the upstream service is running and listening where the proxy expects it. (see the Website load section for all steps and server-specific snippets)

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with Demo Registrar Ltd., 94 days left |
| Name servers | ✅ OK | 2 name server(s) delegated by com, 2 of 2 addresses answer authoritatively |
| DNS zone | ✅ OK | 5 records from ns1.dns-host.net. (3.0.1.1) |
| Reachability | ✅ OK | Reachable from 2 of 2 node(s) |
| Website load | ❌ FAIL | https://broken-web.com/ → 502 in 12 ms — The TLS certificate for broken-web.com has expired; browsers show a security warning instead of the site |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-01-18 (94 days left).

### ✅ Name servers — OK


| Name server | IP | Status | AA | Serial | RTT ms |
|---|---|---|---|---|---|
| ns1.dns-host.net. | 3.0.1.1 | ok | true | 7 | 0.0 |
| ns2.dns-host.net. | 3.0.2.1 | ok | true | 7 | 0.0 |

### ✅ DNS zone — OK

- **INFO** `dns.no_www` www has no address record; visitors typing www. will get an error.
- **INFO** `dns.no_ipv6` No AAAA (IPv6) record.
- **INFO** `dns.no_mx` No MX record: the domain cannot receive email (fine if intended).
- **INFO** `dnssec.unsigned` DNSSEC is not enabled for this domain. (`no DS at parent`)

| Name | Type | TTL | Value |
|---|---|---|---|
| broken-web.com | A | 300 | 127.0.0.1 |
| broken-web.com | NS | 3600 | ns1.dns-host.net. |
| broken-web.com | NS | 3600 | ns2.dns-host.net. |
| broken-web.com | SOA | 3600 | ns1.dns-host.net. hostmaster.broken-web.com. 7 7200 3600 1209600 300 |
| broken-web.com | TXT | 3600 | "v=spf1 -all" |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Frankfurt | 127.0.0.1 | 4 | 4 | 0% | 0.0/0.1/0.1 | open | open | ok |
| Tehran | 127.0.0.1 | 4 | 4 | 0% | 0.0/0.1/0.1 | open | open | ok |

### ❌ Website load — FAIL

- **FAIL** `load.tls.expired` The TLS certificate for broken-web.com has expired; browsers show a security warning instead of the site (`certificate expired 2026-10-12 (issuer netarget Demo CA)`)
- **FAIL** `load.http.502.origin` nginx cannot get a response from the application behind it (502 Bad Gateway) (`HTTP 502 on GET https://broken-web.com/ (browser UA); no CDN or WAF detected in front of the site; web server detected: nginx (nginx in front of an application (PHP-FPM, Node, Gunicorn…))`)
- **INFO** `load.content.no-http2` The server only speaks HTTP/1.1; HTTP/2 would load pages with many resources faster (`the server negotiated HTTP/1.1 when HTTP/2 was offered`)

**Verdict:** The TLS certificate for broken-web.com has expired; browsers show a security warning instead of the site

- Layer at fault: **tls** (confidence high, 95%)

Evidence:

- `certificate expired 2026-10-12 (issuer netarget Demo CA)`

Likely causes:

- (high) Automatic renewal (certbot/ACME) stopped working: a failed validation, a removed cron/timer, or a firewall blocking port 80.
- (medium) The certificate was renewed on disk but the web server was not reloaded.

Fix steps:

1. Renew the certificate and reload the web server.

   nginx:

   ```
   sudo certbot renew && sudo systemctl reload nginx
   ```

   - Verify: echo | openssl s_client -connect broken-web.com:443 -servername broken-web.com 2>/dev/null | openssl x509 -noout -enddate
2. Fix automatic renewal so it does not happen again.

   any:

   ```
   sudo certbot renew --dry-run
   systemctl list-timers | grep certbot
   ```

   - Verify: The dry run succeeds.

Could not determine from outside:

- Why the renewal job failed (see the ACME client's log).

| Kind | Detected | Confidence | Evidence |
|---|---|---|---|
| server | nginx | medium | header server: nginx/1.24.0 (GET https://broken-web.com/) |

| Node | Request | Final | Result | Proto | TTFB ms | Total ms | Differs |
|---|---|---|---|---|---|---|---|
| Frankfurt | GET https://broken-web.com/ | https://broken-web.com/ | 502 | HTTP/1.1 | 12 | 12 |  |
| Frankfurt | GET http://broken-web.com/ | https://broken-web.com/ | 502 | HTTP/1.1 | 3 | 3 |  |
| Frankfurt | HEAD https://broken-web.com/ | https://broken-web.com/ | 502 | HTTP/1.1 | 7 | 8 |  |
| Frankfurt | GET https://broken-web.com/ curl UA | https://broken-web.com/ | 502 | HTTP/1.1 | 5 | 5 |  |
| Frankfurt | GET https://broken-web.com/ googlebot UA | https://broken-web.com/ | 502 | HTTP/1.1 | 8 | 9 |  |
| Frankfurt | GET https://broken-web.com/ HTTP/1.1 | https://broken-web.com/ | 502 | HTTP/1.1 | 7 | 7 |  |
| Frankfurt | GET https://broken-web.com/ HTTP/2 | https://broken-web.com/ | 502 | HTTP/1.1 | 7 | 8 |  |
| Frankfurt | GET https://broken-web.com/ gzip | https://broken-web.com/ | 502 | HTTP/1.1 | 5 | 5 |  |
| Frankfurt | GET https://broken-web.com/ no compression | https://broken-web.com/ | 502 | HTTP/1.1 | 9 | 9 |  |
| Tehran | GET https://broken-web.com/ | https://broken-web.com/ | 502 | HTTP/1.1 | 5 | 5 |  |
| Tehran | GET http://broken-web.com/ | https://broken-web.com/ | 502 | HTTP/1.1 | 5 | 5 |  |
| Tehran | HEAD https://broken-web.com/ | https://broken-web.com/ | 502 | HTTP/1.1 | 6 | 6 |  |
| Tehran | GET https://broken-web.com/ curl UA | https://broken-web.com/ | 502 | HTTP/1.1 | 6 | 6 |  |
| Tehran | GET https://broken-web.com/ googlebot UA | https://broken-web.com/ | 502 | HTTP/1.1 | 6 | 7 |  |
| Tehran | GET https://broken-web.com/ HTTP/1.1 | https://broken-web.com/ | 502 | HTTP/1.1 | 7 | 7 |  |
| Tehran | GET https://broken-web.com/ HTTP/2 | https://broken-web.com/ | 502 | HTTP/1.1 | 7 | 7 |  |
| Tehran | GET https://broken-web.com/ gzip | https://broken-web.com/ | 502 | HTTP/1.1 | 7 | 7 |  |
| Tehran | GET https://broken-web.com/ no compression | https://broken-web.com/ | 502 | HTTP/1.1 | 9 | 9 |  |

- Also: **502 Bad Gateway from the origin's reverse proxy** — nginx cannot get a response from the application behind it (502 Bad Gateway) (fail, high)

- Also: **HTTP/2 not available** — The server only speaks HTTP/1.1; HTTP/2 would load pages with many resources faster (info, high)
