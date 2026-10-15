# Domain Doctor report: healthy-shop.com

- Checked: 2026-10-15 01:28:05 UTC
- Request ID: `e454bb075757f22f7e6488babec38d6cdcf22eb1`
- Measurement nodes: Frankfurt (DE (demo)), Tehran (IR (demo))

## Diagnosis

**No problems found: the domain is registered, delegated, resolves, and the website responds.**


## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with Demo Registrar Ltd., 209 days left |
| Name servers | ✅ OK | 2 name server(s) delegated by com, 2 of 2 addresses answer authoritatively |
| DNS zone | ✅ OK | 8 records from ns1.healthy-shop.com. (3.0.0.1) |
| Reachability | ✅ OK | Reachable from 2 of 2 node(s) |
| Website load | ✅ OK | https://healthy-shop.com/ → 200 in 7 ms — The website loads normally from every measurement node |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-05-13 (209 days left).

### ✅ Name servers — OK


| Name server | IP | Status | AA | Serial | RTT ms |
|---|---|---|---|---|---|
| ns1.healthy-shop.com. | 3.0.0.1 | ok | true | 2026101401 | 0.0 |
| ns2.dns-host.net. | 3.0.2.1 | ok | true | 2026101401 | 0.0 |

### ✅ DNS zone — OK

- **INFO** `dns.no_ipv6` No AAAA (IPv6) record.
- **INFO** `dnssec.valid` DNSSEC chain DS → DNSKEY → RRSIG validates. (`parent publishes 1 DS record(s); DS matches DNSKEY 23689; DNSKEY RRset signed by 23689: valid; SOA signed by 23689: valid`)

| Name | Type | TTL | Value |
|---|---|---|---|
| healthy-shop.com | A | 300 | 127.0.0.1 |
| healthy-shop.com | CAA | 3600 | 0 issue "letsencrypt.org" |
| healthy-shop.com | MX | 3600 | 10 mail.healthy-shop.com. |
| healthy-shop.com | NS | 3600 | ns1.healthy-shop.com. |
| healthy-shop.com | NS | 3600 | ns2.dns-host.net. |
| healthy-shop.com | SOA | 3600 | ns1.dns-host.net. hostmaster.healthy-shop.com. 2026101401 7200 3600 1209600 300 |
| healthy-shop.com | TXT | 3600 | "v=spf1 mx include:_spf.mailer.net -all" |
| www.healthy-shop.com | CNAME | 300 | healthy-shop.com. |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Frankfurt | 127.0.0.1 | 4 | 4 | 0% | 0.0/0.1/0.1 | open | open | ok |
| Tehran | 127.0.0.1 | 4 | 4 | 0% | 0.0/0.1/0.1 | open | open | ok |

### ✅ Website load — OK

- **INFO** `load.content.no-http2` The server only speaks HTTP/1.1; HTTP/2 would load pages with many resources faster (`the server negotiated HTTP/1.1 when HTTP/2 was offered`)

**Verdict:** The website loads normally from every measurement node

- Layer at fault: **none** (confidence high, 90%)

Evidence:

- `GET https://healthy-shop.com/ → 200`

Could not determine from outside:

- Problems that only appear for logged-in users, specific pages or after JavaScript runs.

| Kind | Detected | Confidence | Evidence |
|---|---|---|---|
| server | nginx | medium | header server: nginx (GET https://healthy-shop.com/) |

| Node | Request | Final | Result | Proto | TTFB ms | Total ms | Differs |
|---|---|---|---|---|---|---|---|
| Frankfurt | GET https://healthy-shop.com/ | https://healthy-shop.com/ | 200 | HTTP/1.1 | 6 | 7 |  |
| Frankfurt | GET http://healthy-shop.com/ | https://healthy-shop.com/ | 200 | HTTP/1.1 | 7 | 7 |  |
| Frankfurt | GET https://www.healthy-shop.com/ | https://healthy-shop.com/ | 200 | HTTP/1.1 | 7 | 8 |  |
| Frankfurt | GET http://www.healthy-shop.com/ | https://healthy-shop.com/ | 200 | HTTP/1.1 | 7 | 7 |  |
| Frankfurt | HEAD https://healthy-shop.com/ | https://healthy-shop.com/ | 200 | HTTP/1.1 | 8 | 9 |  |
| Frankfurt | GET https://healthy-shop.com/ curl UA | https://healthy-shop.com/ | 200 | HTTP/1.1 | 6 | 9 |  |
| Frankfurt | GET https://healthy-shop.com/ googlebot UA | https://healthy-shop.com/ | 200 | HTTP/1.1 | 7 | 7 |  |
| Frankfurt | GET https://healthy-shop.com/ HTTP/1.1 | https://healthy-shop.com/ | 200 | HTTP/1.1 | 9 | 10 |  |
| Frankfurt | GET https://healthy-shop.com/ HTTP/2 | https://healthy-shop.com/ | 200 | HTTP/1.1 | 9 | 9 |  |
| Frankfurt | GET https://healthy-shop.com/ gzip | https://healthy-shop.com/ | 200 | HTTP/1.1 | 12 | 12 |  |
| Frankfurt | GET https://healthy-shop.com/ no compression | https://healthy-shop.com/ | 200 | HTTP/1.1 | 15 | 16 |  |
| Tehran | GET https://healthy-shop.com/ | https://healthy-shop.com/ | 200 | HTTP/1.1 | 7 | 7 |  |
| Tehran | GET http://healthy-shop.com/ | https://healthy-shop.com/ | 200 | HTTP/1.1 | 6 | 6 |  |
| Tehran | GET https://www.healthy-shop.com/ | https://healthy-shop.com/ | 200 | HTTP/1.1 | 3 | 3 |  |
| Tehran | GET http://www.healthy-shop.com/ | https://healthy-shop.com/ | 200 | HTTP/1.1 | 4 | 4 |  |
| Tehran | HEAD https://healthy-shop.com/ | https://healthy-shop.com/ | 200 | HTTP/1.1 | 15 | 16 |  |
| Tehran | GET https://healthy-shop.com/ curl UA | https://healthy-shop.com/ | 200 | HTTP/1.1 | 11 | 13 |  |
| Tehran | GET https://healthy-shop.com/ googlebot UA | https://healthy-shop.com/ | 200 | HTTP/1.1 | 5 | 7 |  |
| Tehran | GET https://healthy-shop.com/ HTTP/1.1 | https://healthy-shop.com/ | 200 | HTTP/1.1 | 11 | 13 |  |
| Tehran | GET https://healthy-shop.com/ HTTP/2 | https://healthy-shop.com/ | 200 | HTTP/1.1 | 8 | 10 |  |
| Tehran | GET https://healthy-shop.com/ gzip | https://healthy-shop.com/ | 200 | HTTP/1.1 | 15 | 17 |  |
| Tehran | GET https://healthy-shop.com/ no compression | https://healthy-shop.com/ | 200 | HTTP/1.1 | 10 | 10 |  |

- Also: **HTTP/2 not available** — The server only speaks HTTP/1.1; HTTP/2 would load pages with many resources faster (info, high)
