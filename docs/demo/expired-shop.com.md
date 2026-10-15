# Domain Doctor report: expired-shop.com

- Checked: 2026-10-15 01:28:05 UTC
- Request ID: `1476c2292fe05d4b49b874b2d2e9a5153fc4b9fc`
- Measurement nodes: Frankfurt (DE (demo)), Tehran (IR (demo))

## Diagnosis

**The domain registration has expired**

- Root cause (registration): The domain expired 13 day(s) ago (2026-10-03).
- Evidence: `expiry date 2026-10-03`

Symptoms explained by the cause:

- ns1.parking-host.net. is listed as a name server but is not authoritative for the domain (lame delegation). — explained by `ns.none_usable`
- ns2.parking-host.net. is listed as a name server but is not authoritative for the domain (lame delegation). — explained by `ns.none_usable`
- None of the delegated name servers answers authoritatively for the domain, so it cannot resolve anywhere. — explained by `reg.expired`
- DNS zone was not checked: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively) — explained by `reg.expired`
- Reachability was not checked: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively) — explained by `reg.expired`
- Website load was not checked: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively) — explained by `reg.expired`

### Fixes (in priority order)

1. **The domain registration has expired** — Renew the domain at your registrar now and turn on auto-renew. The registry usually reactivates it within minutes to a few hours.

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ❌ FAIL | Expired 13 day(s) ago (registrar: Demo Registrar Ltd.) |
| Name servers | ❌ FAIL | 2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively |
| DNS zone | ⏭️ SKIPPED | Skipped: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively) |
| Reachability | ⏭️ SKIPPED | Skipped: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively) |
| Website load | ⏭️ SKIPPED | Skipped: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively) |

### ❌ Domain registration — FAIL

- **FAIL** `reg.expired` The domain expired 13 day(s) ago (2026-10-03). (`expiry date 2026-10-03`)
- **INFO** `reg.auto_renew_grace` The registry auto-renewed the domain; the registrar may still delete it if unpaid. (`EPP status autoRenewPeriod`)

### ❌ Name servers — FAIL

- **FAIL** `ns.lame` ns1.parking-host.net. is listed as a name server but is not authoritative for the domain (lame delegation). (`4.0.0.1: rcode=REFUSED aa=false`)
- **FAIL** `ns.lame` ns2.parking-host.net. is listed as a name server but is not authoritative for the domain (lame delegation). (`4.0.1.1: rcode=REFUSED aa=false`)
- **FAIL** `ns.none_usable` None of the delegated name servers answers authoritatively for the domain, so it cannot resolve anywhere.

| Name server | IP | Status | AA | Serial | RTT ms |
|---|---|---|---|---|---|
| ns1.parking-host.net. | 4.0.0.1 | lame | false | 0 | 0.5 |
| ns2.parking-host.net. | 4.0.1.1 | lame | false | 0 | 0.5 |

### ⏭️ DNS zone — SKIPPED

Skipped: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively)

### ⏭️ Reachability — SKIPPED

Skipped: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively)

### ⏭️ Website load — SKIPPED

Skipped: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively)
