---
name: http-error-knowledge
description: How to add, change and test Website Load knowledge-base rules (rules/kb/*.yaml) and fingerprints (rules/fingerprints.yaml) in netarget — schema, conditions, signals, confidence, safe-advice rules and fixtures. Use whenever a website/HTTP/CDN/TLS failure is misdiagnosed, a new error page or CDN must be recognised, or fix advice needs to change.
---

# Website Load knowledge base

Go code only collects **facts**; every verdict and every piece of advice lives in YAML:

| File | What it holds |
|---|---|
| `rules/fingerprints.yaml` | Signatures for CDN/WAF, web server and platform detection |
| `rules/kb/*.yaml` | Failure rules (one YAML list per file, grouped by area) |
| `internal/kb` | Loader, schema validation, safety lint, matching engine |
| `internal/checks/load_matrix.go` | Request matrix + derived **signals** |
| `internal/checks/web.go` | Runs matrix/resources/fingerprints, builds the Observation, evaluates rules |

Rules are embedded in the binary; an invalid rule fails `go test ./internal/kb` and stops the master at startup.

## What a rule matches against (the Observation)

The canonical request — `GET https://<host>/` with a browser User-Agent from the primary node, after
redirects — plus fingerprints and signals:

- `status`, `status_range: "500-599"`, `error_kind` (`timeout`, `refused`, `reset`, `tls_handshake`, `dns`, `blocked`, `bad_url`, `unreachable`, `other`)
- `cdn: [cloudflare, …]` (`none` = no CDN, `any` = some CDN), `server: [nginx, apache, litespeed, iis, caddy, unknown]`, `platform: [wordpress, …]` — ids from `fingerprints.yaml`, only detections with medium/high confidence count
- `header: {name, regex}`, `body: '<regex>'` (RE2, case-insensitive, on the ≤64 KB body sample)
- `signal: <name>` — must be one of `kb.KnownSignals` (`internal/kb/engine.go`); each signal carries its own evidence text

A rule has `match.all` (every condition), optional `match.any` (at least one) and `match.none` (none may hold).
**Each condition sets exactly one field.**

## Rule schema

```yaml
- id: area.name                 # lowercase, dotted; finding code becomes load.<id>
  title: Short title
  layer: dns|cdn|network|tls|server|application|content   # layer at fault
  severity: fail|warn|info
  group: status-403             # optional: only the best match per group is reported
  priority: 2                   # optional tie-breaker (lower wins); generic fallbacks use 9
  match:
    all: [{status: [525]}, {cdn: [cloudflare]}]
  confidence:
    base: 0.85                  # (0,1]
    boosts: [{when: {signal: origin_https_fail}, add: 0.1, why: "explain the extra evidence"}]
  verdict: "One line, may use {cdn} {server} {platform} {status} {host} {url} {cf_code} {error_kind}"
  causes: [{text: "...", likelihood: high|medium|low}]       # ranked by probability
  fixes:
    - step: "What to do"
      why: "optional"
      applies_to: [cloudflare]                                # optional targets
      snippets: {nginx: "...", apache: "...", litespeed: "...", iis: "...", any: "..."}
      verify: "How to confirm the fix worked"                  # required
      warning: "required for any risky step"
  warnings: ["shown under the fixes"]
  cannot_determine: ["What the check cannot see from outside"]  # required, ≥1
  tests:                                                        # ≥1 with expect: match
    - name: describes the scenario
      given: {status: 525, cdn: cloudflare, server: unknown, headers: {server: [cloudflare]}, body: "...", signals: [origin_https_fail]}
      expect: match            # or no_match
      min_confidence: 0.9      # optional
```

Snippet keys and `applies_to` must be in `kb.Targets`. Snippets may use `{host}`; everything else in
braces is left untouched (Apache `%{HTTPS}` and nginx `$host` are safe).

## Safe advice (enforced by the lint in `internal/kb/kb.go`)

- **Never** `chmod 777`/`0777` — not even with a warning. Use 755 for directories and 644 for files,
  owned by the site user; put "never 777" text in `warnings`, not in fixes.
- Risky steps — disabling a WAF/ModSecurity/SELinux/firewall, `SecRuleEngine Off`, turning off TLS
  verification (`curl -k`, `proxy_ssl_verify off`), enabling directory listing — are only allowed in a
  **later** fix that carries a `warning`, after a safer fix. Prefer narrow exceptions
  (`SecRuleRemoveById` for one rule and path).
- Do not recommend lowering CDN SSL modes (Flexible) to hide certificate problems.
- Only advise read-only diagnostics on systems you do not own; the tool itself only sends GET/HEAD.

## Adding a rule — checklist

1. Reproduce: run the site (or an `httptest` fixture) and look at the Website load JSON
   (`matrix`, `signals`, `fingerprints`) to see which facts are available.
2. If a needed fact does not exist, add a **signal** in `deriveSignals`/`resourceSignals`, register
   its name in `kb.KnownSignals`, and unit-test it in `internal/checks/load_matrix_test.go`.
3. Write the rule in the right `rules/kb/*.yaml` file; use a `group` if it competes with an existing
   rule for the same failure, and give generic fallbacks `priority: 9`.
4. Add fixtures: at least one positive, and a `no_match` for the nearest look-alike.
5. Run `go test ./internal/kb ./internal/checks ./internal/e2e`; then ask the **rule-reviewer**
   agent to review the new rule.
6. If a new CDN or server must be recognised, add signals to `fingerprints.yaml` (strong/medium/weak;
   a lone weak signal never exceeds "low") and a test in `internal/fingerprint`.

## Testing commands

```bash
go test ./internal/kb -run TestRuleFixtures -v     # every rule's fixtures
go test ./internal/kb -run TestValidate            # schema + safety lint
go test ./internal/fingerprint ./internal/checks ./internal/e2e
```
