# Architecture

netarget's deployment design (master/agent split, liveness, SSE, report storage, security
layers) is modelled on [komyl/looking-glass](https://github.com/komyl/looking-glass). No code was
copied from it (it is AGPL-3.0); everything here is an independent implementation.

```
                       ┌──────────────────────────────────────┐
  Browser / CLI ─HTTPS─▶│ nginx → master :8082                  │
                       │   UI (embedded) · API · orchestrator  │
                       │   DNS/RDAP/WHOIS lookups (direct)     │
                       │   optional in-process local agent     │
                       └───────────────┬──────────────────────┘
                                       │ HTTP(S) + X-Agent-Secret (cert pinned)
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
5. **Website load** (`checks/web.go`, `checks/load_matrix.go`, `probe/http.go`,
   `probe/resources.go`, `fingerprint`, `kb`): finds *where* a site fails — CDN/WAF, origin web
   server, application, TLS, network or page content — see [Website load](#website-load) below.
   Redirects are never followed automatically: each hop is requested explicitly, re-resolved and
   re-validated. TLS details are gathered with `InsecureSkipVerify` *only* so a bad certificate
   can be described; verification is redone with `x509.Verify` and every failure is reported.

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

## Website load

Facts are computed in Go; **all advice comes from data files** (`rules/`, embedded with
`go:embed`). Pipeline: request matrix → fingerprints → derived signals → resources → knowledge
base → verdict.

1. **Request matrix** (`checks/load_matrix.go`): every live agent runs ~13 requests as
   `probe.ReqSpec`s in one `/v1/http` call — GET over http/https for apex and www (browser UA),
   then on the canonical URL: HEAD, curl and Googlebot User-Agents, forced HTTP/1.1 and HTTP/2,
   gzip vs identity, and (with `originIp`) https/http pinned to the origin. The agent keeps a
   ≤ 64 KB body sample, capped headers (≤ 60, ≤ 8 KB, Set-Cookie values dropped) and cookie names
   for the final hop, only while the chain stays on the checked site.
2. **Fingerprints** (`internal/fingerprint`, `rules/fingerprints.yaml`): CDN/WAF, origin server
   and platform from headers, cookies, error bodies, TLS issuer, CNAME suffixes (captured by the
   zone layer) and CIDR lists. Signal weights strong 0.7 / medium 0.4 / weak 0.15 combine as
   `1 − Π(1 − w)`; a detection made only of weak signals is capped at 0.45 ("low") so one weak
   hint never reads as certain. Every detection carries its evidence.
3. **Signals** (`deriveSignals`): cross-request facts with evidence — `ua_dependent_block`,
   `browser_ua_blocked`, `head_differs`, `h1_fail`/`h2_fail`, `redirect_loop`,
   `https_fail_http_ok`, `apex_fail`/`www_fail`/`apex_www_split`, `origin_ok_cdn_fail` /
   `origin_fail_too` / `origin_https_fail` (HTTPS compared with HTTPS), `regional`, page
   classifiers (default, parked, maintenance, directory listing, PHP error, Apache 500 page),
   TLS facts, cache status, slow TTFB, large page.
4. **Resources** (`/v1/resources`, primary node only): the canonical HTML is parsed with
   `x/net/html`; ≤ 30 stylesheets/scripts/images/icons/preloads and fonts from the first CSS are
   checked for failure, slowness, mixed content, wrong or `nosniff`-blocked MIME types,
   compression, cache lifetime and CORS. Third-party assets get a HEAD without query string.
5. **Knowledge base** (`internal/kb`, `rules/kb/*.yaml`): each rule has `match` (`all`/`any`/
   `none` conditions on status, error kind, CDN, server, platform, header, body regex, signal),
   `confidence` (base + boosts with reasons), a templated verdict, ranked causes, fixes with
   per-server snippets and verify steps, `cannot_determine`, warnings and fixtures. The loader
   decodes strictly (`KnownFields`), validates enums/regexes/templates, and lints advice:
   `chmod 777` is rejected outright and disabling a security feature is only allowed in a later
   fix that carries a warning. `go test ./internal/kb` runs every rule's fixtures. Matches sort
   by severity, confidence and priority; only the best match per `group` is kept.
6. **Verdict**: the top match gives the layer at fault, confidence, evidence, fixes and
   "could not determine" items; all matches become findings `load.<rule id>`. If an earlier
   layer holds the root cause, the orchestrator sets `verdict.symptom_of` and the diagnosis
   engine treats web findings as symptoms.

Safety: GET and HEAD only, a fixed set of User-Agents (only for diagnosing blocks), no logins,
forms, fuzzing or WAF/CDN bypass. `originIp` must pass the same `safenet` checks as any resolved
address, on the master (`input.ParseOriginIP`) and again on the agent; it pins only the first
host. Body samples are stripped from reports.

The Docker demo (`deploy/demo/`, driven by `DEMO_DOCKER=1 go test ./internal/e2e -run
TestLoadDemo`) runs nginx, Apache and a Caddy "CDN" behind one edge and checks ten scenarios;
its reports are in `docs/demo/load/`.

## Diagnosis engine

`internal/diagnose` separates **causes** from **symptoms**:

- The root cause is the earliest-layer critical finding; within a layer, the one a client hits
  first (`precedenceOrder`: e.g. connection refused < TLS failure < HTTP 502).
- Critical findings in later layers, and skipped layers, are symptoms *explained by* the root
  cause. Some same-layer pairs are also symptom/cause (`sameLayerSymptoms`, e.g. per-server
  `ns.lame` is explained by `ns.none_usable`; resolver SERVFAIL by `dnssec.broken`).
- Fixes: P1 root cause, P2 independent critical causes, P3 warnings — with plain-language actions
  from `diagnose/rules.go` (kept in sync with the `dns-diagnostics` skill); `load.*` codes take
  their title and first fix from the knowledge base.

## Master ↔ agent

- `X-Agent-Secret` (32-byte random hex, constant-time compare) on every request; the agent port
  is restricted to the master by ufw.
- Transport: plain HTTP on a private network, or HTTPS (TLS 1.2+, `AGENT_TLS_CERT`/`AGENT_TLS_KEY`)
  when master and agent talk over the public internet, so on-path observers see neither the
  secret nor probe results. Agents use self-signed ECDSA certs (`domaindoctor-agent gen-cert`); the
  master trusts each by the SHA-256 of its leaf certificate (`cert_sha256` per node) instead of a
  CA, checked in `tls.Config.VerifyConnection` so resumed sessions are checked too. Chain, name and
  expiry are not checked when pinned: the pin is the trust anchor, rotation means a new pin. A
  mismatch fails the handshake, so nothing is sent and the node is marked dead like any other
  failure. `cert_sha256` on an `http://` URL is a config error, not silently ignored. An `https://`
  node without a pin uses normal system-root verification.
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
  v4-mapped, NAT64, 6to4 and SIIT forms; Teredo (2001::/32) is blocked as a whole.
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
- Website load: URLs with credentials are never followed; a redirect to another site gets the
  default User-Agent and none of its body or headers are kept (the matrix is not an open proxy);
  per-call limits on specs, time, samples and resources are enforced by the agent.

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
  redirect would carry `X-Agent-Secret` elsewhere). With `cert_sha256` set it talks only to the
  agent holding that certificate's key.

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
