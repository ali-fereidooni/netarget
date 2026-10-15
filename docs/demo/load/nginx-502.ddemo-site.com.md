# Domain Doctor report: nginx-502.ddemo-site.com

- Checked: 2026-10-15 01:28:06 UTC
- Request ID: `e37ecaaf69026376255ecf25967e95d1c80e7b45`
- Measurement nodes: Frankfurt (DE (demo)), Tehran (IR (demo))

## Diagnosis

**502 Bad Gateway from the origin's reverse proxy**

- Root cause (web): nginx cannot get a response from the application behind it (502 Bad Gateway)
- Evidence: `HTTP 502 on GET https://nginx-502.ddemo-site.com/ (browser UA); no CDN or WAF detected in front of the site; web server detected: nginx (nginx in front of an application (PHP-FPM, Node, Gunicorn…))`

### Fixes (in priority order)

1. **502 Bad Gateway from the origin's reverse proxy** — Check that the upstream service is running and listening where the proxy expects it. (see the Website load section for all steps and server-specific snippets)

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with Demo Registrar Ltd., 199 days left |
| Name servers | ✅ OK | 2 name server(s) delegated by com, 2 of 2 addresses answer authoritatively |
| DNS zone | ✅ OK | 5 records from ns1.ddemo-site.com. (3.0.0.1) |
| Reachability | ✅ OK | Reachable from 2 of 2 node(s) |
| Website load | ❌ FAIL | https://nginx-502.ddemo-site.com/ → 502 in 28 ms — nginx cannot get a response from the application behind it (502 Bad Gateway) |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-05-03 (199 days left).

### ✅ Name servers — OK


| Name server | IP | Status | AA | Serial | RTT ms |
|---|---|---|---|---|---|
| ns1.ddemo-site.com. | 3.0.0.1 | ok | true | 1 | 2.4 |
| ns2.ddemo-dns.net. | 3.0.1.1 | ok | true | 1 | 0.7 |

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
| nginx-502.ddemo-site.com | A | 300 | 127.0.0.1 |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Frankfurt | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |
| Tehran | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |

### ❌ Website load — FAIL

- **FAIL** `load.http.502.origin` nginx cannot get a response from the application behind it (502 Bad Gateway) (`HTTP 502 on GET https://nginx-502.ddemo-site.com/ (browser UA); no CDN or WAF detected in front of the site; web server detected: nginx (nginx in front of an application (PHP-FPM, Node, Gunicorn…))`)

**Verdict:** nginx cannot get a response from the application behind it (502 Bad Gateway)

- Layer at fault: **application** (confidence high, 80%)

Evidence:

- `HTTP 502 on GET https://nginx-502.ddemo-site.com/ (browser UA)`
- `no CDN or WAF detected in front of the site`
- `web server detected: nginx (nginx in front of an application (PHP-FPM, Node, Gunicorn…))`

Likely causes:

- (high) The application process (PHP-FPM, Node, Python, Java) is stopped or crashed.
- (high) The proxy points to the wrong socket or port (e.g. PHP version changed the php-fpm socket path).
- (medium) The application closes connections or returns headers that are too large for the proxy buffers.

Fix steps:

1. Check that the upstream service is running and listening where the proxy expects it.

   nginx:

   ```
   sudo tail -n 30 /var/log/nginx/error.log      # 'connect() failed', 'upstream prematurely closed'
   sudo systemctl status php8.3-fpm               # or your app service
   grep -R 'fastcgi_pass\|proxy_pass' /etc/nginx/sites-enabled/
   ```

   - Verify: The upstream is active and its socket/port matches fastcgi_pass/proxy_pass.
2. If headers are too large, increase proxy buffers.

   nginx:

   ```
   proxy_buffer_size 16k;
   proxy_buffers 8 16k;
   fastcgi_buffer_size 32k;
   fastcgi_buffers 16 16k;
   ```

   - Verify: No 'upstream sent too big header' in the error log.

Could not determine from outside:

- The upstream service state and the proxy error log.

| Kind | Detected | Confidence | Evidence |
|---|---|---|---|
| server | nginx | high | header server: nginx/1.27.5 (GET http://nginx-502.ddemo-site.com/); page content "<center>nginx/1.27.5</center>" (GET https://nginx-502.ddemo-site.com/) |

| Node | Request | Final | Result | Proto | TTFB ms | Total ms | Differs |
|---|---|---|---|---|---|---|---|
| Frankfurt | GET https://nginx-502.ddemo-site.com/ | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 28 | 28 |  |
| Frankfurt | GET http://nginx-502.ddemo-site.com/ | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 20 | 20 |  |
| Frankfurt | HEAD https://nginx-502.ddemo-site.com/ | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 27 | 27 |  |
| Frankfurt | GET https://nginx-502.ddemo-site.com/ curl UA | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 23 | 23 |  |
| Frankfurt | GET https://nginx-502.ddemo-site.com/ googlebot UA | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 28 | 28 |  |
| Frankfurt | GET https://nginx-502.ddemo-site.com/ HTTP/1.1 | https://nginx-502.ddemo-site.com/ | 502 | HTTP/1.1 | 15 | 15 |  |
| Frankfurt | GET https://nginx-502.ddemo-site.com/ HTTP/2 | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 13 | 13 |  |
| Frankfurt | GET https://nginx-502.ddemo-site.com/ gzip | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 13 | 13 |  |
| Frankfurt | GET https://nginx-502.ddemo-site.com/ no compression | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 31 | 31 |  |
| Tehran | GET https://nginx-502.ddemo-site.com/ | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 15 | 15 |  |
| Tehran | GET http://nginx-502.ddemo-site.com/ | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 11 | 11 |  |
| Tehran | HEAD https://nginx-502.ddemo-site.com/ | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 17 | 17 |  |
| Tehran | GET https://nginx-502.ddemo-site.com/ curl UA | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 29 | 29 |  |
| Tehran | GET https://nginx-502.ddemo-site.com/ googlebot UA | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 21 | 21 |  |
| Tehran | GET https://nginx-502.ddemo-site.com/ HTTP/1.1 | https://nginx-502.ddemo-site.com/ | 502 | HTTP/1.1 | 29 | 29 |  |
| Tehran | GET https://nginx-502.ddemo-site.com/ HTTP/2 | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 24 | 24 |  |
| Tehran | GET https://nginx-502.ddemo-site.com/ gzip | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 23 | 23 |  |
| Tehran | GET https://nginx-502.ddemo-site.com/ no compression | https://nginx-502.ddemo-site.com/ | 502 | HTTP/2.0 | 30 | 30 |  |
