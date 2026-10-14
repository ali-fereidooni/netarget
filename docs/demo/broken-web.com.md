# Domain Doctor report: broken-web.com

- Checked: 2026-10-14 20:46:38 UTC
- Request ID: `9a4cfce89e89e9890a19cdbcd7b483e662ae1d58`
- Measurement nodes: Frankfurt (DE (demo)), Tehran (IR (demo))

## Diagnosis

**The TLS certificate has expired**

- Root cause (web): The TLS certificate for broken-web.com expired on 2026-10-11; browsers show a security error.
- Evidence: `subject=broken-web.com issuer=Domain Doctor Demo CA valid 2026-06-16 → 2026-10-11 SAN=[broken-web.com]`
- Also a cause (web): http://broken-web.com/ returns HTTP 502 Bad Gateway: the reverse proxy/load balancer could not get a valid response from the application server (backend down or crashing).

### Fixes (in priority order)

1. **The TLS certificate has expired** — Renew the certificate now (e.g. certbot renew) and fix automatic renewal; reload the web server afterwards.
2. **The website returns a server error** — Check the application and reverse-proxy logs; restart the backend; for 502/504 verify the upstream address and timeouts.

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with Demo Registrar Ltd., 94 days left |
| Name servers | ✅ OK | 2 name server(s) delegated by com, 2 of 2 addresses answer authoritatively |
| DNS zone | ✅ OK | 5 records from ns1.dns-host.net. (3.0.1.1) |
| Reachability | ✅ OK | Reachable from 2 of 2 node(s) |
| Web server | ❌ FAIL | https://broken-web.com/ → 502 Bad Gateway |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-01-17 (94 days left).

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

### ❌ Web server — FAIL

- **FAIL** `web.5xx` http://broken-web.com/ returns HTTP 502 Bad Gateway: the reverse proxy/load balancer could not get a valid response from the application server (backend down or crashing). (`https://broken-web.com/ (from http://broken-web.com/)`)
- **FAIL** `tls.expired` The TLS certificate for broken-web.com expired on 2026-10-11; browsers show a security error. (`subject=broken-web.com issuer=Domain Doctor Demo CA valid 2026-06-16 → 2026-10-11 SAN=[broken-web.com]`)

`http://broken-web.com/`

- http://broken-web.com/ → 301 Moved Permanently (1 ms) Location: https://broken-web.com/
- https://broken-web.com/ → 502 Bad Gateway (3 ms)

`https://broken-web.com/`

- https://broken-web.com/ → 502 Bad Gateway (4 ms)

| Node | URL | Final | Status | Total ms |
|---|---|---|---|---|
| Frankfurt | http://broken-web.com/ | https://broken-web.com/ | 502 | 4 |
| Frankfurt | https://broken-web.com/ | https://broken-web.com/ | 502 | 4 |
| Tehran | http://broken-web.com/ | https://broken-web.com/ | 502 | 4 |
| Tehran | https://broken-web.com/ | https://broken-web.com/ | 502 | 4 |
