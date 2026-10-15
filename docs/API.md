# API reference

All master endpoints are served on `LISTEN_ADDR` (default `127.0.0.1:8082`) behind nginx.
Errors are always JSON: `{"error": "<human-readable message>"}`. No error ever contains agent
URLs, agent IPs, secrets or raw network errors from agents (they surface as `agent unreachable`).

IDs (`request_id`, report `id`) are 40 lowercase hex characters (20 bytes from `crypto/rand`).
Any other string is rejected before it is used for a lookup or a file path.

## Rate limits

| Limit | Scope | Applies to |
|---|---|---|
| Token bucket 20/min, burst 5 | per client IP | `POST /api/check`, `POST /api/web-diagnose`, `GET /api/traceroute`, `GET /api/report` |
| One active job | per client IP | `POST /api/check` / `POST /api/web-diagnose` (until the check finishes), `GET /api/traceroute` (while streaming) |
| Global cap (`MAX_CONCURRENT_CHECKS`, default 30) | whole master | checks + traceroutes |
| Token bucket 10/hour, burst 3 | per client IP | `POST /api/report/promote` |

| 4 open SSE streams / 32 subscribers per check | per client / per check | `GET /api/check/{id}?stream=1` |
| Global 300/hour | whole master | `POST /api/report/promote` |

Clients are keyed by IPv4 address or IPv6 /64.
`GET /api/check/{id}` (JSON) and `GET /api/nodes` are not throttled (cheap in-memory reads).
The client IP is derived as described in [ARCHITECTURE.md](ARCHITECTURE.md#client-ip-behind-proxies).

---

## POST /api/check

Start a check. Body (max 4 KB): `{"domain": "<anything a user might paste>"}`.

Input is normalized: scheme, user-info, port, path, query, fragment, trailing dot and a leading
`www.` are removed; it is lower-cased and IDNs are converted to punycode. IP addresses,
`localhost` and special-use names (`.local`, `.internal`, `.test`, …) are rejected.

`202 Accepted`:
```json
{
  "request_id": "d749e104b288a96caef3aebb3de70158bd12b245",
  "domain": {"input": "https://www.Bücher.de/x", "name": "xn--bcher-kva.de", "unicode": "bücher.de", "apex": "xn--bcher-kva.de"},
  "status": "running",
  "stream_url": "/api/check/d749e104b288a96caef3aebb3de70158bd12b245?stream=1"
}
```

| Code | Body `error` | When |
|---|---|---|
| 400 | `IP addresses are not supported — enter a domain name such as example.com` | IP input |
| 400 | `local or reserved names (localhost, .local, .internal, ...) cannot be checked` | reserved names |
| 400 | `this does not look like a valid domain name…` | syntax / IDNA errors |
| 400 | `invalid request body` | not JSON |
| 429 | `rate limited — try again in a minute` | token bucket |
| 429 | `a check from your address is already running — wait for it to finish` | per-IP job limit |
| 503 | `the server is busy — please try again shortly` | global cap |
| 400 | `originIp is only accepted by /api/web-diagnose` | `originIp` sent to `/api/check` |

## POST /api/web-diagnose

The same check (all five layers, same job, SSE, report, permalink and limits as
`/api/check`), with an optional **origin-direct** test for the Website load layer.
Body (max 4 KB): `{"domain": "example.com", "originIp": "93.184.215.14"}`; `originIp` may be
omitted or empty. The response is the same `202` as `/api/check`; follow `stream_url`.

With `originIp`, the agents additionally request `https://<host>/` and `http://<host>/` with the
connection pinned to that IP (correct SNI and `Host`), so the result shows whether the origin
works when the CDN is bypassed. Only the start host is pinned; redirects are re-resolved and
re-validated as usual. Only test origins you own or are allowed to test — the UI says so.

| Code | Body `error` | When |
|---|---|---|
| 400 | `originIp must be an IP address (for example 93.184.215.14)` | not an IP literal |
| 400 | `originIp must not contain an IPv6 zone` | `fe80::1%eth0` |
| 400 | `originIp must be a public address; private, loopback, link-local and metadata addresses are not allowed` | any address `safenet` blocks (incl. NAT64/6to4/Teredo/IPv4-mapped forms) |

Plus every error of `POST /api/check`. The agents re-check the address themselves.

## GET /api/check/{id}

Returns the report. While running: `status: "running"` and the layers finished so far.

Query parameters:
- `stream=1` (or `Accept: text/event-stream`) — Server-Sent Events, see below.
- `format=md` — Markdown export (409 while still running).
- `download=1` — adds `Content-Disposition: attachment` (JSON or Markdown).

Report shape (abridged):
```json
{
  "request_id": "…", "status": "done",
  "domain": {"name": "broken-web.com", "apex": "broken-web.com", "unicode": "broken-web.com", "input": "…"},
  "started_at": "2026-10-14T20:36:02Z", "finished_at": "2026-10-14T20:36:03Z",
  "nodes": [{"id": "fra1", "name": "Frankfurt", "location": "DE"}],
  "layers": [
    {"layer": "registration", "title": "Domain registration", "status": "OK",
     "summary": "Registered with …, 94 days left",
     "findings": [{"code": "reg.ok", "severity": "info", "message": "…", "evidence": ""}],
     "details": { "…": "layer-specific, see below" },
     "started_at": "…", "duration_ms": 41, "skip_reason": ""}
  ],
  "diagnosis": {
    "healthy": false,
    "headline": "The TLS certificate has expired",
    "root_cause": {"code": "load.tls.expired", "layer": "web", "title": "…", "explanation": "…", "evidence": "…"},
    "other_causes": [{"code": "load.http.502.origin", "…": "…"}],
    "symptoms": [{"code": "…", "layer": "…", "message": "…", "explained_by": "reg.expired"}],
    "fixes": [{"priority": 1, "title": "…", "action": "…", "code": "load.tls.expired", "layer": "web"}]
  }
}
```

Layers, in order: `registration`, `nameservers`, `zone`, `reachability`, `web`.
Status: `OK`, `WARN`, `FAIL`, `SKIPPED`. Finding severity: `info`, `warn`, `fail`.
Finding codes are stable: DNS-side codes are documented in `.claude/skills/dns-diagnostics/SKILL.md`;
Website load codes are `load.<rule id>` from `rules/kb/*.yaml` (see `.claude/skills/http-error-knowledge/SKILL.md`).

`details` per layer:
- `registration`: `{domain, registered, info{source, server, registrar, created, expires, updated, status[], nameservers[]}, days_left, rdap_error, whois_error}`
- `nameservers`: `{delegation{parent, parent_server, ns[], glue{}, nxdomain, no_delegation}, servers[{name, in_bailiwick, glue[], addrs[], probes[{ip, status, rcode, aa, rtt_ms, serial, ns[], asn, as_name, error}]}], child_ns[]}`
- `zone`: `{queried_server, records[{name, type, ttl, value}], email{spf{record, records, lookups, errors[], all}, dmarc{record, policy}, dkim_selectors_found[]}, dnssec{signed, ds[], dnskeys[], chain[], valid}, propagation[{type, name, authoritative[], values[{value, count, resolvers[]}], errors{}, consistent}]}`
- `reachability`: `{targets[], rows[{node_id, node, location, ip, family, sent, received, loss, rtt_min, rtt_avg, rtt_max, ping_error, tcp_80, tcp_443, status, note}]}` — row `status`: `ok`, `icmp_blocked` (ICMP filtered but TCP answers), `down`, `error`.
- `web` (title "Website load"): see below.

#### Website load details

```json
{
  "primary_node": "Frankfurt",
  "canonical": "https://example.com/",
  "origin_ip": "93.184.215.14",
  "verdict": {
    "text": "Cloudflare cannot complete an SSL handshake with your origin over HTTPS (error 525)",
    "layer": "tls", "confidence": 0.95, "level": "high", "rule_id": "cf.525",
    "evidence": ["HTTP 525 on GET https://example.com/ (browser UA)", "CDN detected: Cloudflare (high)"],
    "causes": [{"text": "…", "likelihood": "high"}],
    "fixes": [{"step": "…", "why": "…", "applies_to": ["cloudflare"],
               "snippets": {"nginx": "…", "apache": "…", "litespeed": "…", "iis": "…"},
               "verify": "…", "warning": "…"}],
    "cannot_determine": ["…"], "warnings": ["…"],
    "symptom_of": "reg.expired"
  },
  "matches": [{"rule_id", "title", "layer", "severity", "confidence", "level", "verdict", "evidence", "causes", "fixes", "cannot_determine", "warnings", "group"}],
  "fingerprints": {"cdn": [{"id", "kind", "name", "confidence", "level", "evidence": []}], "server": [], "platform": [], "no_cdn": false},
  "signals": [{"name": "origin_https_fail", "evidence": "…"}],
  "matrix": [{"node", "spec", "label", "url", "final_url", "status", "error_kind", "hops", "loop", "proto", "encoding", "body_size", "ttfb_ms", "total_ms", "server", "diff"}],
  "resources": {"page": {"url", "status", "error_kind", "size", "truncated", "content_type", "ttfb_ms", "found", "checked", "skipped"},
                "resources": [{"url", "host", "kind", "third_party", "status", "error_kind", "ttfb_ms", "total_ms", "size", "content_type", "encoding", "cache_control", "issues": []}]},
  "chains": [{"start", "loop", "hops": [{"url", "ip", "method", "proto", "status", "status_text", "location", "server", "headers": {}, "timing": {"dns_ms", "connect_ms", "tls_ms", "ttfb_ms", "total_ms"}, "tls": {}, "cdn", "cdn_error", "error_kind", "error"}]}],
  "nodes": [{"node", "location", "url", "final_url", "status", "error_kind", "hops", "total_ms", "ok"}],
  "tls": {"example.com": {"version", "cipher", "subject", "issuer", "not_before", "not_after", "days_left", "sans": [], "hostname_match", "chain_valid", "chain_error", "incomplete_chain"}}
}
```

- `verdict.layer` — where it fails: `dns`, `cdn`, `network`, `tls`, `server`, `application`,
  `content`, or `none` (loads normally / no rule matched). `level`: `high` ≥ 0.8, `medium` ≥ 0.5.
- `verdict.symptom_of` — set when an earlier layer's root cause (expired domain, lame NS, no A
  record…) explains the web failure; the web advice is then secondary.
- `fixes[].snippets` keys: `apache`, `nginx`, `litespeed`, `iis`, `cloudflare`, `firewall`, `php`,
  `wordpress`, `laravel`, `dns`, `any`, …; the UI shows the one for the detected (or chosen)
  server. All advice comes from the rule files in `rules/kb/`.
- Finding codes for this layer are `load.<rule id>` (e.g. `load.cf.525`, `load.http.403.apache`).
- `matrix[].spec`: `base:https:apex`, `base:http:www`, `head`, `ua:curl`, `ua:googlebot`,
  `proto:h1`, `proto:h2`, `enc:gzip`, `enc:identity`, `origin:https`, `origin:http`; `diff` marks
  rows that differ from the baseline browser request.
- `resources[].issues`: `failed`, `slow`, `mixed_content`, `wrong_mime`, `blocked_mime`,
  `uncompressed`, `weak_cache`, `cors`, `blocked` (host resolves to a non-public address; never
  fetched). Response bodies are never included in reports.
- `error_kind`: `timeout`, `refused`, `reset`, `tls_handshake`, `dns`, `blocked`, `bad_url`,
  `unreachable`, `other`.

### SSE stream

`GET /api/check/{id}?stream=1` — `Content-Type: text/event-stream`, `X-Accel-Buffering: no`.
Late subscribers get the full history replayed. Events:

| event | data |
|---|---|
| `request_id` | `{"request_id", "domain", "layers": [...], "titles": {...}}` — always first |
| `layer_start` | `{"type":"layer_start","layer":"zone","title":"DNS zone"}` |
| `layer_done` | `{"type":"layer_done","layer":"zone","result":{…Result…}}` |
| `done` | `{"type":"done","report":{…Report…}}` — stream ends |

Skipped layers emit only `layer_done` (status `SKIPPED`). A `: keep-alive` comment is sent every 15 s.

## GET /api/nodes

Live nodes only (dead nodes are omitted, not flagged). Exactly `id`, `name`, `location`:
```json
[{"id":"fra1","name":"Frankfurt","location":"DE"}]
```

## GET /api/traceroute

SSE traceroute from one node. Parameters: `id` (a finished check's `request_id`), `node` (node
id), `ip` (must be one of the addresses that check resolved — listed in the reachability
layer's `targets`), `maxhops` (5–64, default 30). Free-form targets are not accepted.

Events: `start` `{node, ip, max_hops}`, then one `hop` per output line
`{line, hop, ip, asn, as_name}` (ASN fields only when the optional dataset is loaded), then
`done`, or `error` `{"error": "agent unreachable" | "traceroute is not available on this node"}`.

Errors before streaming: 404 (unknown/unfinished check), 400 (ip not in the check, unknown node),
502 `agent unreachable` (node is dead), 429/503 (limits).

## POST /api/report/promote

Turn a finished check into a read-only report kept for 24 hours. Body (≤ 4 KB):
`{"request_id": "<40 hex>"}` → `200 {"id": "<new 40 hex>", "url": "/r/<id>"}`.
The permanent ID is freshly generated (not the request ID).

| Code | error | When |
|---|---|---|
| 400 | `invalid request body` / `invalid request id` | |
| 404 | `this result is no longer available to make permanent — please re-run the check` | unknown, unfinished, or older than 30 min |
| 429 | `too many permanent links requested — try again later` | 10/hour/IP |
| 503 | `too many active shared links right now — please try again later` | store full (`REPORTS_CAP`); nothing is evicted |
| 503 | `permanent links are unavailable` | `REPORTS_DIR` unusable |
| 500 | `failed to save permanent link` | disk error |

## GET /api/report?id=…

`200 {"id", "kind": "check", "target": "<domain>", "captured_at": "<RFC3339 UTC>", "data": {…Report…}}`.
`format=md` and `download=1` work as for `/api/check/{id}`. 404 `report not found or expired`.

## UI routes

`/` (new check), `/c/{request_id}` (live/recent check, valid ~30 min), `/r/{id}` (permanent report).
`/healthz` returns `ok`.

---

## Agent API (master → agent only)

Every request needs `X-Agent-Secret: <secret>` (constant-time compare; 401 otherwise).
The agent serves plain HTTP by default, or HTTPS (TLS 1.2+) when `AGENT_TLS_CERT` and
`AGENT_TLS_KEY` are set; over the public internet use HTTPS. The master pins an HTTPS agent's
self-signed certificate by SHA-256 (`cert_sha256` in `nodes.json`) and drops the connection on a
mismatch before any request (or the secret) is sent.
The agent re-validates everything it receives and refuses non-public IPs itself.
Errors are `400 {"error":"invalid request"}` without detail.

| Method/path | Body / params | Response |
|---|---|---|
| `GET /health` | — | `ok` |
| `POST /v1/probe` | `{"host":"example.com","ips":["93.184.215.14"],"ping_count":4,"ports":[80,443]}` (≤ 8 IPs; ports ⊂ {80,443}) | `{"results":[{"ip","ping":{sent,received,loss,rtt_min,rtt_avg,rtt_max},"ping_error","tcp":[{"port","status":"open|closed|filtered","latency_ms"}]}]}` |
| `POST /v1/http` | `{"urls":["https://example.com/"],"pinned":{"example.com":["93.184.215.14"]},"max_hops":10,"specs":[…ReqSpec…]}` | `{"chains":[…Chain…],"results":[{"spec":…,"chain":…}]}` |
| `POST /v1/resources` | `{"page_url":"https://example.com/","pinned":{…},"max":30,"site":"example.com"}` | `{"page":{…},"resources":[…]}` |
| `GET /v1/traceroute?ip=…&maxhops=…` | — | SSE: `data: <line>` …, then `event: done` or `event: error` |

`ReqSpec` (request matrix): `{"id","url","method":"GET|HEAD","ua":"browser|curl|googlebot","proto":"auto|h1|h2","compress":true|false|null,"origin_ip":"<public IP>","sample":true}`.
The agent rejects anything else: methods other than GET/HEAD, free-form User-Agents, non-http(s)
URLs, URLs with credentials, non-public `origin_ip`. Limits: ≤ 20 specs per call, 6 in parallel,
40 s per call, redirect depth ≤ 10, body read ≤ 64 KB per request, ≤ 1 MB of body samples per
call. Body samples, full headers and the requested User-Agent are used only on the checked site
(same registrable domain): a redirect to another site is followed with the default User-Agent
and nothing from its response is kept beyond status and timing.

`/v1/resources` fetches the page (≤ 512 KB), parses it and checks ≤ 30 subresources (6 at a
time, 8 s each). Every host is resolved through `safenet`; third-party assets get a HEAD without
the query string; a page that redirects off-site is not crawled (`page.skipped`).
