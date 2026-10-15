# netarget report: dd-unregistered-test-8f3k2.com

- Checked: 2026-10-14 20:59:13 UTC
- Request ID: `ec63fc5a9d191f1438bec06bed60f832cb94f9c9`
- Measurement nodes: Master node (local)

## Diagnosis

**The domain is not registered**

- Root cause (registration): dd-unregistered-test-8f3k2.com is not registered: the registry has no record of it.
- Evidence: `registry lookup returned "not found"`

Symptoms explained by the cause:

- Name servers was not checked: Domain registration failed (Domain is not registered) — explained by `reg.not_registered`
- DNS zone was not checked: Domain registration failed (Domain is not registered) — explained by `reg.not_registered`
- Reachability was not checked: Domain registration failed (Domain is not registered) — explained by `reg.not_registered`
- Web server was not checked: Domain registration failed (Domain is not registered) — explained by `reg.not_registered`

### Fixes (in priority order)

1. **The domain is not registered** — Register the domain at any registrar (or check the spelling). Nothing else can work until it exists.

## Checks

| Step | Status | Summary |
|---|---|---|
| Domain registration | ❌ FAIL | Domain is not registered |
| Name servers | ⏭️ SKIPPED | Skipped: Domain registration failed (Domain is not registered) |
| DNS zone | ⏭️ SKIPPED | Skipped: Domain registration failed (Domain is not registered) |
| Reachability | ⏭️ SKIPPED | Skipped: Domain registration failed (Domain is not registered) |
| Web server | ⏭️ SKIPPED | Skipped: Domain registration failed (Domain is not registered) |

### ❌ Domain registration — FAIL

- **FAIL** `reg.not_registered` dd-unregistered-test-8f3k2.com is not registered: the registry has no record of it. (`registry lookup returned "not found"`)

### ⏭️ Name servers — SKIPPED

Skipped: Domain registration failed (Domain is not registered)

### ⏭️ DNS zone — SKIPPED

Skipped: Domain registration failed (Domain is not registered)

### ⏭️ Reachability — SKIPPED

Skipped: Domain registration failed (Domain is not registered)

### ⏭️ Web server — SKIPPED

Skipped: Domain registration failed (Domain is not registered)
