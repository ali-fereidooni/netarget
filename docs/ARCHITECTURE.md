# Architecture

Domain Doctor's deployment design (master/agent split, liveness, SSE, report storage, security
layers) is modelled on [komyl/looking-glass](https://github.com/komyl/looking-glass). No code was
copied from it (it is AGPL-3.0); everything here is an independent implementation.

```
                       ┌──────────────────────────────────────┐
  Browser / CLI ─HTTPS─▶│ nginx → master :8082                  │
                       │   UI (embedded) · API · orchestrator  │
                       │   DNS/RDAP/WHOIS lookups (direct)     │
                       │   optional in-process local agent     │
                       └───────────────┬──────────────────────┘
                                       │ HTTP + X-Agent-Secret (private network)
                      ┌────────────────┼─────────────────┐
                      ▼                ▼                 ▼
                 agent :9090      agent :9090       agent :9090
             ping · tcp · http(s) · tls · traceroute (exec, argument slices)
```

## Check pipeline

`internal/orchestrator` runs five layers in dependency order and streams an event after each:

1. **Registration** (`checks/registration.go`): RDAP via the IANA bootstrap (`internal/rdap`,
   cached 24 h), WHOIS fallback via the IANA referral (`internal/whois`). EPP statuses are
   normalized to camelCase. `not registered`, `clientHold`, `serverHold`, `redemptionPeriod`
   and `pendingDelete` are *blocking*: later layers are skipped. An expired domain is FAIL but not
   blocking (registries often keep it delegated during grace periods).
2. **Name servers** (`checks/nameservers.go`): `dnsx.FindDelegation` walks from the root servers
   with non-recursive queries until the parent returns the referral for the apex, so the NS set
   and glue come from the TLD, not from a cache. Every NS address is queried directly for SOA and
   NS: no answer → unreachable, REFUSED/SERVFAIL/no AA/no SOA → lame. Also: missing/mismatched
   glue, parent/child NS mismatch, SOA serial skew, < 2 NS, all NS in one ASN (if the ASN dataset
   is loaded) or one /24 (/48). If root servers themselves don't answer, the finding is
   `ns.checker_dns_blocked` (the checker's network blocks port 53), not a domain problem.
3. **DNS zone** (`checks/zone.go`, `email.go`, `dnssec.go`): direct queries to the authoritative
   servers for SOA/NS/A/AAAA/CNAME/MX/TXT/CAA at the apex, A/AAAA/CNAME at www (and the requested
   sub-domain), and common SRV names. CNAME targets and MX hosts are resolved through public
   resolvers. SPF is parsed and DNS-lookup terms counted recursively (loop-safe, ≤ 25 fetches);
   DMARC policy parsed; common DKIM selectors probed. DNSSEC: DS from the parent server → matching
   DNSKEY (digest) → RRSIG over DNSKEY by that KSK → RRSIG over SOA, with validity windows.
   Finally the apex A/AAAA/MX/NS are compared between authoritative answers and each public
   resolver (1.1.1.1, 8.8.8.8, 9.9.9.9), grouped by how many resolvers returned each value.
4. **Reachability** (`checks/reach.go`): up to 2 IPv4 + 2 IPv6 addresses from the zone layer are
   sent (pinned) to every live agent: ICMP ping (`-c 4`, parsed) and TCP connect to 80/443
   (open = handshake, closed = RST, filtered = timeout). ICMP failing while TCP answers is OK with
   a note. Partial reachability across nodes and IPv6-only failures are flagged.
5. **Web** (`checks/web.go`, `probe/http.go`): from every agent, `http://` and `https://` for the
   host and `www`. Redirects are never followed automatically: each hop is requested explicitly,
   re-resolved and re-validated. Per hop: status, headers, timing (DNS, connect, TLS, TTFB, total
   via `httptrace`), TLS details (the client sets `InsecureSkipVerify` *only* so it can describe a
   bad certificate; verification is redone with `x509.Verify` and every failure is reported),
   CDN error-page detection (Cloudflare 52x, CloudFront, Akamai, Fastly).

### DNS-over-HTTPS resolver mode

Some networks (corporate, national filtering, VPN/TUN clients) block port 53 entirely. With
`DNS_TRANSPORT=auto` the master/CLI probes the root servers at startup; if they are silent and a
DoH resolver answers, `dnsx.Client.DoH` is set:

- Queries addressed to a configured public resolver go over HTTPS (RFC 8484 POST, wire format)
  to that resolver's endpoint; queries to any other server fail immediately with
  `ErrDirectUnavailable` (no timeouts).
- The name-server layer (`checks/ns_resolver.go`) asks every resolver for the apex NS set with and
  without CD (checking disabled): NXDOMAIN everywhere → not delegated; SERVFAIL only with
  validation → DNSSEC problem (the zone layer then validates the chain); SERVFAIL even with CD →
  the name servers don't answer (lame/down). NS addresses, count and network diversity are still
  checked. AA, glue, serial and parent/child checks are impossible and reported as such
  (`ns.limited_mode`).
- The zone layer reads records from the resolvers with CD set, so broken DNSSEC still shows the
  zone's data; TTLs are cache-remaining. DNSSEC validation (DS → DNSKEY → RRSIG) is unchanged.
  The propagation comparison uses the first resolver as the reference.

## Diagnosis engine

`internal/diagnose` separates **causes** from **symptoms**:

- The root cause is the earliest-layer critical finding; within a layer, the one a client hits
  first (`precedenceOrder`: e.g. connection refused < TLS failure < HTTP 502).
- Critical findings in later layers, and skipped layers, are symptoms *explained by* the root
  cause. Some same-layer pairs are also symptom/cause (`sameLayerSymptoms`, e.g. per-server
  `ns.lame` is explained by `ns.none_usable`; resolver SERVFAIL by `dnssec.broken`).
- Fixes: P1 root cause, P2 independent critical causes, P3 warnings — with plain-language actions
  from `diagnose/rules.go` (kept in sync with the `dns-diagnostics` skill).

## Master ↔ agent

- HTTP with `X-Agent-Secret` (32-byte random hex, constant-time compare) over private networking;
  the agent port is restricted to the master by ufw.
- Clients only ever see `id`, `name`, `location` of nodes. All agent failures map to the fixed
  string `agent unreachable`.
- **Single-node mode**: with no `NODES_FILE` (or `LOCAL_AGENT=1`) the master adds an in-process
  `probe.Local` node; the CLI uses the same.
- **Fan-out**: `nodes.Fanout` runs one goroutine per live node, at most 8 in flight, results in
  registry order.
- **Liveness**: a background loop calls `/health` on every node every 12 s with a 3 s timeout on
  a dedicated client (separate from probe calls). Dead after 2 consecutive failures, live again
  after 1 success. Dead nodes are omitted from `/api/nodes` and from fan-outs.

## SSRF and DNS rebinding

`internal/safenet` is the single boundary:

- `IsBlocked`: loopback, RFC 1918/4193, link-local (incl. 169.254.169.254 and fd00:ec2::254),
  CGNAT, multicast, unspecified, reserved/documentation ranges, and v4 addresses embedded in
  v4-mapped, NAT64 and 6to4 forms.
- `Resolve`: resolves **once**; if *any* answer is blocked the target is rejected.
- `PinnedDialContext`: connects only to the pinned IPs, ignoring the host in the dial address —
  there is no second lookup to rebind. A `net.Dialer.Control` hook re-checks the actual socket
  address on every connection as a last line of defence.
- **Agents close the rebinding gap themselves**: the master sends the IPs it resolved and pinned;
  `probe.Local` re-validates them (`safenet.CheckAddrs`) and dials only those. Redirect targets
  on other hosts are resolved once by the agent through `safenet.Resolve` and pinned for that hop.
- DNS queries to non-public server IPs (e.g. an NS that resolves to 10.0.0.1) are refused and
  reported as `ns.private_ip`. RDAP/WHOIS servers are reached through the same safe dialer.
- Ports: agents test only TCP 80/443; HTTP redirects to ports other than 80/443/8080/8443 are not
  followed. `exec` uses argument slices with an `netip`-formatted IP literal — no shell, no
  user text.
- Traceroute targets must be IPs already found by a finished check (no free-form targets).

## Abuse controls

Limits are keyed per client: the IPv4 address, or the IPv6 **/64** (a single subscriber usually
owns a whole /64, so per-address limits would be trivial to rotate around).

- Per-client token bucket (20/min, burst 5), one active job per client, global semaphore (default 30).
- Promote: 10/hour (burst 3) per client plus a global 300/hour budget; reports over 1 MB are not stored.
- SSE: at most 4 open progress streams per client and 32 subscribers per check.
- Work a hostile domain can cause is bounded: ≤ 32 records per DNS response section, ≤ 13 NS
  names, ≤ 4 addresses per NS and 32 overall (probed 16 at a time), ≤ 200 rows in the records
  table, record values ≤ 512 bytes, findings ≤ 100 with bounded text, DNSSEC: ≤ 8 candidate signer
  keys and ≤ 4 verification attempts per key/RRset (KeyTrap-style zones), SPF ≤ 25 fetches.
- Response size limits (RDAP 2 MB, WHOIS 256 KB, HTTP bodies 64 KB, headers 64 KB), timeouts on
  every network call, check timeout 3 min. nginx adds its own request limit as an outer boundary.
- Finding evidence never contains raw Go network errors (they embed local addresses); errors are
  mapped to a fixed vocabulary (`timeout`, `connection refused`, …).
- Traceroute hops in private/CGNAT ranges are shown as "(private address hidden)".
- The master→agent client ignores proxy environment variables and never follows redirects (a
  redirect would carry `X-Agent-Secret` elsewhere).

### Known limitation

An agent can be asked (via a redirect) to fetch `http://<its own public IP>:80|443|8080|8443/`.
On Linux that traffic goes over `lo`, which ufw accepts, so a service bound to the public IP on
those ports *on the agent host itself* is reachable. Keep agent hosts free of other web services
on those ports, or add an `iptables -A OUTPUT -d <own public IP> -m owner --uid-owner domaindoctor -j REJECT`
rule.

### Client IP behind proxies

`clientip.Extractor{Hops: N}` trusts exactly the right-most N `X-Forwarded-For` entries (each
trusted proxy appends what it saw); entries further left are client-controlled and ignored.
`TRUSTED_PROXY_CIDRS` additionally requires the TCP peer to be a known proxy before
`X-Forwarded-For` is consulted at all. `Hops=0` uses the socket address only.

## Results, links and storage

- Every check gets a `request_id` (20 bytes `crypto/rand`, hex). Jobs live in a capped in-memory
  cache (2000 entries, 30 min, evicts oldest — the client already has the result).
  `Get` enforces the age itself.
- **Permanent Link**: `POST /api/report/promote` writes the finished report as `<newid>.json`
  under `REPORTS_DIR` (atomic temp-file + rename), kept 24 h from the `captured_at` stored inside
  the file. Capped (`REPORTS_CAP`); when full, new promotions are rejected — existing links are
  never evicted. IDs are validated (`report.ValidID`) before any path is built.
- Stored reports round-trip into typed layer details (`checks.Result.UnmarshalJSON`), so `/r/{id}`
  and Markdown exports render exactly like live results.

## Streaming

Progress and traceroute use Server-Sent Events (not WebSocket: no upgrade, trivial to proxy).
`X-Accel-Buffering: no` disables nginx buffering; late subscribers get the event history replayed.

## Optional ASN dataset

`internal/asn` loads an ipinfo-style CSV/CSV.GZ (`network,…,asn,as_name,as_domain`) into IPv4 and
IPv6 binary radix tries (longest-prefix match). Used for NS network diversity and traceroute hop
enrichment. If `ASN_CSV_PATH` is unset or the file is invalid, the master logs it and runs
without enrichment.
