# API reference

All master endpoints are served on `LISTEN_ADDR` (default `127.0.0.1:8082`) behind nginx.
Errors are always JSON: `{"error": "<human-readable message>"}`. No error ever contains agent
URLs, agent IPs, secrets or raw network errors from agents (they surface as `agent unreachable`).

IDs (`request_id`, report `id`) are 40 lowercase hex characters (20 bytes from `crypto/rand`).
Any other string is rejected before it is used for a lookup or a file path.

## Rate limits

| Limit | Scope | Applies to |
|---|---|---|
| Token bucket 20/min, burst 5 | per client IP | `POST /api/check`, `GET /api/traceroute`, `GET /api/report` |
| One active job | per client IP | `POST /api/check` (until the check finishes), `GET /api/traceroute` (while streaming) |
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
    "root_cause": {"code": "tls.expired", "layer": "web", "title": "…", "explanation": "…", "evidence": "…"},
    "other_causes": [{"code": "web.5xx", "…": "…"}],
    "symptoms": [{"code": "…", "layer": "…", "message": "…", "explained_by": "reg.expired"}],
    "fixes": [{"priority": 1, "title": "…", "action": "…", "code": "tls.expired", "layer": "web"}]
  }
}
```

Layers, in order: `registration`, `nameservers`, `zone`, `reachability`, `web`.
Status: `OK`, `WARN`, `FAIL`, `SKIPPED`. Finding severity: `info`, `warn`, `fail`.
Finding codes are stable and documented in `.claude/skills/dns-diagnostics/SKILL.md`.

`details` per layer:
- `registration`: `{domain, registered, info{source, server, registrar, created, expires, updated, status[], nameservers[]}, days_left, rdap_error, whois_error}`
- `nameservers`: `{delegation{parent, parent_server, ns[], glue{}, nxdomain, no_delegation}, servers[{name, in_bailiwick, glue[], addrs[], probes[{ip, status, rcode, aa, rtt_ms, serial, ns[], asn, as_name, error}]}], child_ns[]}`
- `zone`: `{queried_server, records[{name, type, ttl, value}], email{spf{record, records, lookups, errors[], all}, dmarc{record, policy}, dkim_selectors_found[]}, dnssec{signed, ds[], dnskeys[], chain[], valid}, propagation[{type, name, authoritative[], values[{value, count, resolvers[]}], errors{}, consistent}]}`
- `reachability`: `{targets[], rows[{node_id, node, location, ip, family, sent, received, loss, rtt_min, rtt_avg, rtt_max, ping_error, tcp_80, tcp_443, status, note}]}` — row `status`: `ok`, `icmp_blocked` (ICMP filtered but TCP answers), `down`, `error`.
- `web`: `{primary_node, chains[{start, loop, hops[{url, ip, status, status_text, location, server, headers{}, timing{dns_ms, connect_ms, tls_ms, ttfb_ms, total_ms}, tls{…}, cdn, cdn_error, error_kind, error}]}], nodes[{node, url, final_url, status, error_kind, total_ms, ok}], tls{host: {version, cipher, subject, issuer, not_before, not_after, days_left, sans[], hostname_match, chain_valid, chain_error, incomplete_chain}}}` — `error_kind`: `timeout`, `refused`, `reset`, `tls_handshake`, `dns`, `blocked`, `bad_url`, `unreachable`, `other`.

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
The agent re-validates everything it receives and refuses non-public IPs itself.
Errors are `400 {"error":"invalid request"}` without detail.

| Method/path | Body / params | Response |
|---|---|---|
| `GET /health` | — | `ok` |
| `POST /v1/probe` | `{"host":"example.com","ips":["93.184.215.14"],"ping_count":4,"ports":[80,443]}` (≤ 8 IPs; ports ⊂ {80,443}) | `{"results":[{"ip","ping":{sent,received,loss,rtt_min,rtt_avg,rtt_max},"ping_error","tcp":[{"port","status":"open|closed|filtered","latency_ms"}]}]}` |
| `POST /v1/http` | `{"urls":["https://example.com/"],"pinned":{"example.com":["93.184.215.14"]},"max_hops":10}` | `{"chains":[…Chain…]}` |
| `GET /v1/traceroute?ip=…&maxhops=…` | — | SSE: `data: <line>` …, then `event: done` or `event: error` |
