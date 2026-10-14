# Domain Doctor report: example.com

- Checked: 2026-10-14 20:58:01 UTC
- Request ID: `655511f23e773d3afa17cfe2ea98447ee0fe4601`
- Measurement nodes: Master node (local)

## Diagnosis

**No blocking problem found, but there are warnings worth fixing.**


### Fixes (in priority order)

1. **HTTP does not redirect to HTTPS** — Add a permanent (301) redirect from http:// to https://.
2. **Bare domain and www behave differently** — Pick one canonical host and 301-redirect the other to it; make sure both have DNS records and a certificate.
3. **HSTS is not enabled** — Add the header Strict-Transport-Security: max-age=31536000; includeSubDomains once HTTPS works everywhere.

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with RESERVED-Internet Assigned Numbers Authority, 302 days left |
| Name servers | ✅ OK | 2 name server(s) seen via public resolvers (direct checks unavailable) |
| DNS zone | ✅ OK | 14 records from public resolvers over HTTPS (TTLs are cache-remaining; direct queries unavailable) |
| Reachability | ✅ OK | Reachable from 1 of 1 node(s) |
| Web server | ⚠️ WARN | https://example.com/ → 200 OK in 466 ms (from Master node) |

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
| example.com | A | 235 | 104.20.23.154 |
| example.com | A | 235 | 172.66.147.243 |
| example.com | AAAA | 189 | 2606:4700:10::6814:179a |
| example.com | AAAA | 189 | 2606:4700:10::ac42:93f3 |
| example.com | MX | 300 | 0 . |
| example.com | NS | 86400 | hera.ns.cloudflare.com. |
| example.com | NS | 86400 | elliott.ns.cloudflare.com. |
| example.com | SOA | 1800 | elliott.ns.cloudflare.com. dns.cloudflare.com. 2416374680 10000 2400 604800 1800 |
| example.com | TXT | 300 | "v=spf1 -all" |
| example.com | TXT | 300 | "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9" |
| www.example.com | A | 91 | 104.20.23.154 |
| www.example.com | A | 91 | 172.66.147.243 |
| www.example.com | AAAA | 185 | 2606:4700:10::6814:179a |
| www.example.com | AAAA | 185 | 2606:4700:10::ac42:93f3 |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Master node | 104.20.23.154 | 4 | 4 | 0% | 0.0/0.0/0.0 | open | open | ok |
| Master node | 172.66.147.243 | 4 | 4 | 0% | 0.0/0.0/0.0 | open | open | ok |
| Master node | 2606:4700:10::6814:179a | 0 | 0 | 0% | 0.0/0.0/0.0 |  |  | n/a |
| Master node | 2606:4700:10::ac42:93f3 | 0 | 0 | 0% | 0.0/0.0/0.0 |  |  | n/a |

### ⚠️ Web server — WARN

- **WARN** `web.no_https_redirect` http://example.com/ does not redirect to HTTPS, so visitors can stay on an unencrypted connection. (`http://example.com/ → 200`)
- **WARN** `web.no_https_redirect` http://www.example.com/ does not redirect to HTTPS, so visitors can stay on an unencrypted connection. (`http://www.example.com/ → 200`)
- **WARN** `web.apex_www_inconsistent` The bare domain and www serve the site separately instead of redirecting one to the other (duplicate content, split cookies). (`https://example.com/ → https://example.com/ \| https://www.example.com/ → https://www.example.com/`)
- **WARN** `web.no_hsts` No Strict-Transport-Security (HSTS) header: browsers may still try plain HTTP first. (`https://example.com/`)
- **INFO** `web.missing_security_headers` Recommended security headers are missing: Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, X-Frame-Options. (`https://example.com/`)

`http://example.com/`

- http://example.com/ → 200 OK (300 ms)

`https://example.com/`

- https://example.com/ → 200 OK (466 ms)

`http://www.example.com/`

- http://www.example.com/ → 200 OK (316 ms)

`https://www.example.com/`

- https://www.example.com/ → 200 OK (463 ms)

| Node | URL | Final | Status | Total ms |
|---|---|---|---|---|
| Master node | http://example.com/ | http://example.com/ | 200 | 300 |
| Master node | https://example.com/ | https://example.com/ | 200 | 466 |
| Master node | http://www.example.com/ | http://www.example.com/ | 200 | 316 |
| Master node | https://www.example.com/ | https://www.example.com/ | 200 | 463 |
