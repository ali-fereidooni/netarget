# Server Accessibility check

A support-desk feature: enter a customer's **IP address or hostname** and see,
in three streamed stages, who/where the host is and whether it is reachable.
It is layered on top of netarget's existing building blocks and is fully
self-contained — removing it touches nothing in the domain-troubleshooting
pipeline.

## What it does

1. **Identity** — validates and resolves the target through `safenet` (the
   SSRF boundary), then reports per address: reverse DNS (PTR), ASN / operator
   (when an ASN dataset is loaded), and IP-RDAP registration data (network /
   CIDR, organization, country, abuse contact, registration dates).
2. **Reachability (ping)** — ICMP ping plus a TCP fallback from every live
   measurement node, with a "reachable from X of N nodes" summary.
3. **Service ports** — plain TCP-connect reachability (open / closed /
   filtered / mixed) for a small, configured port set, aggregated across
   nodes. For open web ports it adds a best-effort TLS certificate / HTTP
   status summary (one GET/HEAD per port, capped).

Every probe is **read-only and non-intrusive**: no authentication, no payloads,
nothing executed on the target. One stage failing does not break the others.

## Running it

The master enables the feature automatically. With the local agent:

```bash
LOCAL_AGENT=1 AGENT_SECRET=$(openssl rand -hex 32) go run ./cmd/master
# open http://127.0.0.1:8082/server-check   (dev preview: :8083)
```

API (Server-Sent Events, one event per stage):

```
GET /api/server-access?target=<ip|hostname>&authorized=1[&port=<1-65535>]
```

`port` is an optional extra port for this one check (for example a customer's
panel port or SSH on 2222). It is tested alongside the standard ports and shown
as "custom" in the results.

`authorized=1` is the operator's confirmation that they own or may check the
target; every request is audit-logged (client IP + target + time, never any
secret). The UI is a standalone page at `/server-check`.

## Configuration (environment variables)

| Variable              | Default         | Meaning                                                                 |
|-----------------------|-----------------|-------------------------------------------------------------------------|
| `SERVER_CHECK_PORTS`  | `22,80,443,8443`| TCP ports the check tests (comma-separated, max 8). **Must be set to the same value on the master and on every agent** — each agent enforces its own allow-list and rejects ports outside it. |
| `SERVER_CHECK_CUSTOM_PORT` | `1`        | `1` lets each check add one operator-typed port outside `SERVER_CHECK_PORTS`; `0` turns that off. Set it the same on the master and every agent — an agent with `0` rejects checks that carry a custom port. |
| `ASN_CSV_PATH`        | *(unset)*       | Optional ipinfo-style CSV enabling ASN / operator enrichment.           |
| `DNS_TRANSPORT`       | `auto`          | Shared with the rest of netarget; PTR lookups use DoH when port 53 is blocked. |

Rate limits, the single-active-request-per-client gate, the global
concurrency cap, and the per-client stream limit are shared with the main
check API.

## Limitations / not included (by design)

- **Reachability and identity only.** No banner/version grabbing, no SSH
  host-key/cipher/auth-method enumeration, no vulnerability or brute-force
  probing. The port set is small, each node accepts at most one port outside
  its allow-list per request (`probe.Local.ExtraPorts`), and the per-request
  port count is capped (`probe.MaxProbePorts`). On netarget.ir the page and
  API are also limited to staff IPs by nginx.
- IP-RDAP data depends on the responsible RIR publishing it; some blocks
  return no organization/abuse data. ASN/operator requires a loaded dataset.
- The TLS/HTTP summary is best-effort; for an IP target there is no SNI host
  name, so it is a reachability/identity signal, not a hostname-validated TLS
  check.
- Nodes without IPv6 connectivity report IPv6 targets as "not applicable"
  rather than down.

## Layout

| File                                | Responsibility                                           |
|-------------------------------------|----------------------------------------------------------|
| `internal/serveraccess/`            | `types.go`, `target.go` (parse/validate), `identity.go` (stage 1 + deps), `run.go` (stages 2–3 + orchestration). |
| `internal/rdap/ip.go`               | IP-RDAP client (`LookupIP`).                             |
| `internal/dnsx` `LookupPTR`         | Reverse DNS over the existing resolver/DoH path.         |
| `internal/probe` allow-list         | `AllowPorts` on `Local`, `ParsePorts`, `MaxProbePorts`.  |
| `internal/api/serveraccess.go`      | `GET /api/server-access` SSE handler.                    |
| `web/static/servercheck.{html,js}`  | Standalone UI page (`/server-check`).                    |
| `internal/config` `ServerCheckPorts`| Shared port-set parsing for master and agent.            |
