# Domain Doctor report: healthy.ddemo-site.com

- Checked: 2026-10-15 01:28:06 UTC
- Request ID: `fff0c83b2df76046a3723f315159fe91f005d16a`
- Measurement nodes: Frankfurt (DE (demo)), Tehran (IR (demo))

## Diagnosis

**No problems found: the domain is registered, delegated, resolves, and the website responds.**


## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with Demo Registrar Ltd., 199 days left |
| Name servers | ✅ OK | 2 name server(s) delegated by com, 2 of 2 addresses answer authoritatively |
| DNS zone | ✅ OK | 5 records from ns1.ddemo-site.com. (3.0.0.1) |
| Reachability | ✅ OK | Reachable from 2 of 2 node(s) |
| Website load | ✅ OK | https://healthy.ddemo-site.com/ → 200 in 25 ms — The website loads normally from every measurement node |

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
| healthy.ddemo-site.com | A | 300 | 127.0.0.1 |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Frankfurt | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |
| Tehran | 127.0.0.1 | 4 | 4 | 0% | 0.1/0.2/0.3 | open | open | ok |

### ✅ Website load — OK


**Verdict:** The website loads normally from every measurement node

- Layer at fault: **none** (confidence high, 90%)

Evidence:

- `GET https://healthy.ddemo-site.com/ → 200`

Could not determine from outside:

- Problems that only appear for logged-in users, specific pages or after JavaScript runs.

| Kind | Detected | Confidence | Evidence |
|---|---|---|---|
| server | nginx | medium | header server: nginx/1.27.5 (GET http://healthy.ddemo-site.com/) |
| server | Apache httpd | medium | header server: Apache (GET https://healthy.ddemo-site.com/) |

| Node | Request | Final | Result | Proto | TTFB ms | Total ms | Differs |
|---|---|---|---|---|---|---|---|
| Frankfurt | GET https://healthy.ddemo-site.com/ | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 25 | 25 |  |
| Frankfurt | GET http://healthy.ddemo-site.com/ | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 18 | 18 |  |
| Frankfurt | HEAD https://healthy.ddemo-site.com/ | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 16 | 16 |  |
| Frankfurt | GET https://healthy.ddemo-site.com/ curl UA | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 26 | 27 |  |
| Frankfurt | GET https://healthy.ddemo-site.com/ googlebot UA | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 25 | 25 |  |
| Frankfurt | GET https://healthy.ddemo-site.com/ HTTP/1.1 | https://healthy.ddemo-site.com/ | 200 | HTTP/1.1 | 24 | 24 |  |
| Frankfurt | GET https://healthy.ddemo-site.com/ HTTP/2 | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 26 | 26 |  |
| Frankfurt | GET https://healthy.ddemo-site.com/ gzip | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 21 | 22 |  |
| Frankfurt | GET https://healthy.ddemo-site.com/ no compression | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 27 | 27 |  |
| Tehran | GET https://healthy.ddemo-site.com/ | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 25 | 25 |  |
| Tehran | GET http://healthy.ddemo-site.com/ | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 16 | 16 |  |
| Tehran | HEAD https://healthy.ddemo-site.com/ | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 17 | 20 |  |
| Tehran | GET https://healthy.ddemo-site.com/ curl UA | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 26 | 26 |  |
| Tehran | GET https://healthy.ddemo-site.com/ googlebot UA | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 25 | 26 |  |
| Tehran | GET https://healthy.ddemo-site.com/ HTTP/1.1 | https://healthy.ddemo-site.com/ | 200 | HTTP/1.1 | 25 | 27 |  |
| Tehran | GET https://healthy.ddemo-site.com/ HTTP/2 | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 25 | 27 |  |
| Tehran | GET https://healthy.ddemo-site.com/ gzip | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 18 | 18 |  |
| Tehran | GET https://healthy.ddemo-site.com/ no compression | https://healthy.ddemo-site.com/ | 200 | HTTP/2.0 | 26 | 26 |  |
