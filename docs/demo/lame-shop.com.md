# Domain Doctor report: lame-shop.com

- Checked: 2026-10-15 01:28:05 UTC
- Request ID: `4d61783049504a1381667064f871ffb34e709470`
- Measurement nodes: Frankfurt (DE (demo)), Tehran (IR (demo))

## Diagnosis

**None of the domain's name servers answer for it**

- Root cause (nameservers): None of the delegated name servers answers authoritatively for the domain, so it cannot resolve anywhere.

Symptoms explained by the cause:

- ns1.lame-shop.com. is listed as a name server but is not authoritative for the domain (lame delegation). — explained by `ns.none_usable`
- ns2.lame-shop.com. does not answer DNS queries (timeout). — explained by `ns.none_usable`
- DNS zone was not checked: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively) — explained by `ns.none_usable`
- Reachability was not checked: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively) — explained by `ns.none_usable`
- Website load was not checked: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively) — explained by `ns.none_usable`

### Fixes (in priority order)

1. **None of the domain's name servers answer for it** — Add the zone at your DNS provider so the listed name servers answer authoritatively, or change the name servers at the registrar to the ones that actually host the zone.

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ✅ OK | Registered with Demo Registrar Ltd., 304 days left |
| Name servers | ❌ FAIL | 2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively |
| DNS zone | ⏭️ SKIPPED | Skipped: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively) |
| Reachability | ⏭️ SKIPPED | Skipped: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively) |
| Website load | ⏭️ SKIPPED | Skipped: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively) |

### ✅ Domain registration — OK

- **INFO** `reg.ok` Registered until 2027-08-16 (304 days left).

### ❌ Name servers — FAIL

- **FAIL** `ns.lame` ns1.lame-shop.com. is listed as a name server but is not authoritative for the domain (lame delegation). (`5.0.0.1: rcode=REFUSED aa=false`)
- **FAIL** `ns.unreachable` ns2.lame-shop.com. does not answer DNS queries (timeout). (`5.0.1.1: timeout`)
- **FAIL** `ns.none_usable` None of the delegated name servers answers authoritatively for the domain, so it cannot resolve anywhere.

| Name server | IP | Status | AA | Serial | RTT ms |
|---|---|---|---|---|---|
| ns1.lame-shop.com. | 5.0.0.1 | lame | false | 0 | 0.0 |
| ns2.lame-shop.com. | 5.0.1.1 | unreachable | false | 0 | 0.0 |

### ⏭️ DNS zone — SKIPPED

Skipped: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively)

### ⏭️ Reachability — SKIPPED

Skipped: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively)

### ⏭️ Website load — SKIPPED

Skipped: Name servers failed (2 name server(s) delegated by com, 0 of 2 addresses answer authoritatively)
