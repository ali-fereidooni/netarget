# Domain Doctor — project conventions

Layered domain troubleshooter: registration → name servers → DNS zone → reachability → web,
with a cause-vs-symptom diagnosis engine. Master/agent design inspired by komyl/looking-glass
(AGPL — **design only, never copy its code**; a read-only clone may exist in `ref/`, gitignored).

## Run commands
```bash
go build ./...                                   # everything
go vet ./... && go test ./...                    # all tests (no network needed)
go test -race ./...                              # needs cgo/gcc; run in CI/Linux
go run ./cmd/domaindoctor check example.com --json
AGENT_SECRET=$(openssl rand -hex 32) go run ./cmd/agent           # agent on 127.0.0.1:9090
LOCAL_AGENT=1 AGENT_SECRET=... go run ./cmd/master                # single-node mode, UI on :8082
docker compose up --build                        # 1 master + 2 agents
```

## Layout
- `cmd/master`, `cmd/agent`, `cmd/domaindoctor` — binaries (master embeds `web/` via go:embed).
- `internal/input` normalize user input → `input.Domain` (ASCII name, apex).
- `internal/safenet` **the SSRF boundary**: `Resolve` (resolve once, reject any blocked IP),
  `PinnedDialContext`, `Control` hook. Every outbound connection to a user-influenced host uses it.
- `internal/checks` one file per layer; each returns `checks.Result` with `Findings`.
- `internal/diagnose` maps finding codes → cause/symptom, root cause, prioritized fixes.
- `internal/orchestrator` runs layers, skip logic, progress events. `internal/api` HTTP + SSE.
- `internal/agent` server+client, `internal/nodes` registry/liveness/fan-out, `internal/probe` ping/tcp/http/tls/traceroute.

## Conventions
- Status values: `OK`, `WARN`, `FAIL`, `SKIPPED`. Findings have a stable `code` (e.g. `ns.lame`);
  the diagnosis rule table and the dns-diagnostics skill key off these codes — add both together.
- No network in unit tests: use `dnsx` mock servers (miekg `dns.Server` on 127.0.0.1), `httptest`,
  and injected resolvers. Checks take interfaces/clients so tests can swap them. Tests that need to
  dial loopback must use the test-only `AllowLoopback` hooks, never weaken `safenet` defaults.
- Never `exec` through a shell; argument slices only, targets pre-validated. Never return internal
  error text (agent URLs, IPs, secrets) to clients — use the fixed "agent unreachable" message.
- Client-supplied IDs pass `report.ValidID` before any lookup or path join.
- Secrets only from env (`AGENT_SECRET`) or files; never in code, config examples use placeholders.
- Comments explain *why*; keep package doc comments current.

## Claude tooling in .claude/
- skill `dns-diagnostics`: failure → explanation → fix knowledge; consult when adding findings.
- skill `impeccable` (vendored, Apache-2.0): use for any UI work; the panel is an **Operate** surface.
  Its `scripts/impeccable` launcher downloads a native binary — not run here; read PRODUCT.md and
  DESIGN.md directly instead. Read `reference/craft-floor.md` before editing UI.
- skill `design-taste-frontend` (vendored, MIT): landing-page art direction; its house rules (no
  eyebrows, no gradients, no glows, no emoji icons) apply to the panel too, its draw/inspect loop does not.
- UI: `web/static/` (vanilla, strict CSP, self-hosted Vazirmatn). Design tokens and rules: DESIGN.md.
  EN/FA strings live in `STRINGS` in app.js; `?lang=fa` / `?theme=light` override per link.
  Dev preview: `.claude/launch.json` runs the master on :8083 (Docker uses :8082).
- agents `test-writer`, `security-reviewer`; commands `/check <domain>`, `/test-all`.
