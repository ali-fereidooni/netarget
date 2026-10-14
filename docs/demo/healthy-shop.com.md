# Domain Doctor report: healthy-shop.com

- Checked: 2026-10-14 20:46:38 UTC
- Request ID: `8566f084df20d76362c753f88e056648e1fd4320`
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
| Web server | ✅ OK | https://healthy-shop.com/ → 200 OK in 6 ms (from Frankfurt) |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-05-12 (209 days left).

### ✅ Name servers — OK


| Name server | IP | Status | AA | Serial | RTT ms |
|---|---|---|---|---|---|
| ns1.healthy-shop.com. | 3.0.0.1 | ok | true | 2026101401 | 0.0 |
| ns2.dns-host.net. | 3.0.2.1 | ok | true | 2026101401 | 0.0 |

### ✅ DNS zone — OK

- **INFO** `dns.no_ipv6` No AAAA (IPv6) record.
- **INFO** `dnssec.valid` DNSSEC chain DS → DNSKEY → RRSIG validates. (`parent publishes 1 DS record(s); DS matches DNSKEY 23155; DNSKEY RRset signed by 23155: valid; SOA signed by 23155: valid`)

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

### ✅ Web server — OK


`http://healthy-shop.com/`

- http://healthy-shop.com/ → 301 Moved Permanently (3 ms) Location: https://healthy-shop.com/
- https://healthy-shop.com/ → 200 OK (9 ms)

`https://healthy-shop.com/`

- https://healthy-shop.com/ → 200 OK (6 ms)

`http://www.healthy-shop.com/`

- http://www.healthy-shop.com/ → 301 Moved Permanently (4 ms) Location: https://healthy-shop.com/
- https://healthy-shop.com/ → 200 OK (7 ms)

`https://www.healthy-shop.com/`

- https://www.healthy-shop.com/ → 301 Moved Permanently (7 ms) Location: https://healthy-shop.com/
- https://healthy-shop.com/ → 200 OK (5 ms)

| Node | URL | Final | Status | Total ms |
|---|---|---|---|---|
| Frankfurt | http://healthy-shop.com/ | https://healthy-shop.com/ | 200 | 11 |
| Frankfurt | https://healthy-shop.com/ | https://healthy-shop.com/ | 200 | 6 |
| Frankfurt | http://www.healthy-shop.com/ | https://healthy-shop.com/ | 200 | 11 |
| Frankfurt | https://www.healthy-shop.com/ | https://healthy-shop.com/ | 200 | 12 |
| Tehran | http://healthy-shop.com/ | https://healthy-shop.com/ | 200 | 10 |
| Tehran | https://healthy-shop.com/ | https://healthy-shop.com/ | 200 | 10 |
| Tehran | http://www.healthy-shop.com/ | https://healthy-shop.com/ | 200 | 11 |
| Tehran | https://www.healthy-shop.com/ | https://healthy-shop.com/ | 200 | 10 |
