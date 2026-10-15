# netarget report: dnssec-failed.org

- Checked: 2026-10-14 20:58:45 UTC
- Request ID: `3470fd765168f559cbcff77b49995c4a2582c9d5`
- Measurement nodes: Master node (local)

## Diagnosis

**DNSSEC is broken**

- Root cause (zone): DNSSEC is broken: no DNSKEY in the zone matches the DS at the parent (often a DS left behind after changing DNS provider). Validating resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9) will return SERVFAIL.
- Evidence: `DS: 42069 ECDSAP256SHA256 2 \| DNSKEY: 50719 flags=257 ECDSAP256SHA256; 32784 flags=256 ECDSAP256SHA256`

Symptoms explained by the cause:

- http://dnssec-failed.org/ returns HTTP 504 Gateway Timeout: the proxy timed out waiting for the backend application. — explained by `dnssec.broken`
- https://dnssec-failed.org/ timed out: the server accepts no connection or never answers (firewall dropping packets or overloaded server). — explained by `dnssec.broken`

### Fixes (in priority order)

1. **DNSSEC is broken** — If you changed DNS provider, remove the old DS record at your registrar (or publish the new provider's DS). Otherwise re-sign the zone and make sure the DS matches the current KSK.
2. **No DMARC record** — Publish TXT at _dmarc: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain (start with p=none to monitor).
3. **The web server does not answer (timeout)** — Check the firewall (ports 80/443), that the web server is running, and server load.

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with CSC Corporate Domains, Inc., 365 days left |
| Name servers | ⚠️ WARN | 5 name server(s) seen via public resolvers (direct checks unavailable) |
| DNS zone | ❌ FAIL | 10 records from public resolvers over HTTPS (TTLs are cache-remaining; direct queries unavailable) |
| Reachability | ✅ OK | Reachable from 1 of 1 node(s) |
| Web server | ❌ FAIL | Website unreachable |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-10-15 (365 days left).

### ⚠️ Name servers — WARN

- **WARN** `dns.resolver_servfail` Validating resolvers return SERVFAIL, but the data is reachable with DNSSEC checking disabled: the DNSSEC chain is likely broken. (`Cloudflare: SERVFAIL; Google: SERVFAIL; Quad9: lookup failed`)
- **INFO** `ns.limited_mode` This checker cannot query name servers directly (outbound port 53 is blocked), so DNS data comes from public resolvers over HTTPS. Lame-delegation, AA, glue and SOA-serial checks were not possible. (`DNS-over-HTTPS via Cloudflare, Google, Quad9`)

| Name server | IP | Status | AA | Serial | RTT ms |
|---|---|---|---|---|---|
| dns101.comcast.net. | 69.252.250.103 | not tested | false | 0 | 0.0 |
| dns101.comcast.net. | 2001:558:fe23:8:69:252:250:103 | not tested | false | 0 | 0.0 |
| dns102.comcast.net. | 68.87.85.132 | not tested | false | 0 | 0.0 |
| dns102.comcast.net. | 2001:558:1004:7:68:87:85:132 | not tested | false | 0 | 0.0 |
| dns103.comcast.net. | 68.87.76.228 | not tested | false | 0 | 0.0 |
| dns103.comcast.net. | 2001:558:1014:c:68:87:76:228 | not tested | false | 0 | 0.0 |
| dns104.comcast.net. | 68.87.68.244 | not tested | false | 0 | 0.0 |
| dns104.comcast.net. | 2001:558:100a:5:68:87:68:244 | not tested | false | 0 | 0.0 |
| dns105.comcast.net. | 68.87.72.244 | not tested | false | 0 | 0.0 |
| dns105.comcast.net. | 2001:558:100e:5:68:87:72:244 | not tested | false | 0 | 0.0 |

### ❌ DNS zone — FAIL

- **FAIL** `dnssec.broken` DNSSEC is broken: no DNSKEY in the zone matches the DS at the parent (often a DS left behind after changing DNS provider). Validating resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9) will return SERVFAIL. (`DS: 42069 ECDSAP256SHA256 2 \| DNSKEY: 50719 flags=257 ECDSAP256SHA256; 32784 flags=256 ECDSAP256SHA256`)
- **WARN** `mail.dmarc_missing` No DMARC record: spoofed mail using this domain is not rejected or reported. (`no TXT at _dmarc.dnssec-failed.org`)
- **INFO** `dns.no_ipv6` No AAAA (IPv6) record.
- **INFO** `dns.no_mx` No MX record: the domain cannot receive email (fine if intended).

| Name | Type | TTL | Value |
|---|---|---|---|
| dnssec-failed.org | A | 300 | 96.99.227.255 |
| dnssec-failed.org | NS | 298 | dns104.comcast.net. |
| dnssec-failed.org | NS | 298 | dns105.comcast.net. |
| dnssec-failed.org | NS | 298 | dns101.comcast.net. |
| dnssec-failed.org | NS | 298 | dns102.comcast.net. |
| dnssec-failed.org | NS | 298 | dns103.comcast.net. |
| dnssec-failed.org | SOA | 300 | dns101.comcast.org. dnsadmin.comcast.net. 2010102610 900 180 604800 7200 |
| dnssec-failed.org | TXT | 300 | "v=spf1 -all" |
| www.dnssec-failed.org | A | 189 | 68.87.109.242 |
| www.dnssec-failed.org | A | 189 | 69.252.193.191 |

### ✅ Reachability — OK


| Node | IP | Sent | Recv | Loss | RTT min/avg/max | TCP 80 | TCP 443 | Status |
|---|---|---|---|---|---|---|---|---|
| Master node | 96.99.227.255 | 4 | 4 | 0% | 0.0/0.0/0.0 | open | open | ok |

### ❌ Web server — FAIL

- **FAIL** `web.5xx` http://dnssec-failed.org/ returns HTTP 504 Gateway Timeout: the proxy timed out waiting for the backend application. (`http://dnssec-failed.org/ (from http://dnssec-failed.org/)`)
- **FAIL** `web.timeout` https://dnssec-failed.org/ timed out: the server accepts no connection or never answers (firewall dropping packets or overloaded server). (`https://dnssec-failed.org/ (from https://dnssec-failed.org/)`)
- **WARN** `web.timeout` http://www.dnssec-failed.org/ timed out: the server accepts no connection or never answers (firewall dropping packets or overloaded server). (`http://www.dnssec-failed.org/ (from http://www.dnssec-failed.org/)`)
- **WARN** `web.timeout` https://www.dnssec-failed.org/ timed out: the server accepts no connection or never answers (firewall dropping packets or overloaded server). (`https://www.dnssec-failed.org/ (from https://www.dnssec-failed.org/)`)

`http://dnssec-failed.org/`

- http://dnssec-failed.org/ → 504 Gateway Timeout (534 ms)

`https://dnssec-failed.org/`

- https://dnssec-failed.org/ → error: timeout

`http://www.dnssec-failed.org/`

- http://www.dnssec-failed.org/ → error: timeout

`https://www.dnssec-failed.org/`

- https://www.dnssec-failed.org/ → error: timeout

| Node | URL | Final | Status | Total ms |
|---|---|---|---|---|
| Master node | http://dnssec-failed.org/ | http://dnssec-failed.org/ | 504 | 534 |
| Master node | https://dnssec-failed.org/ | https://dnssec-failed.org/ | timeout | 10001 |
| Master node | http://www.dnssec-failed.org/ | http://www.dnssec-failed.org/ | timeout | 10001 |
| Master node | https://www.dnssec-failed.org/ | https://www.dnssec-failed.org/ | timeout | 10001 |
