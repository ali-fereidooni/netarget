# netarget

Enter a domain; netarget checks it layer by layer —
**registration → name servers → DNS zone → reachability → website load** — stops to explain the
root cause when a layer fails, separates causes from symptoms, and gives a prioritized fix list.

- **Registration**: RDAP (IANA bootstrap) with WHOIS fallback; expiry, EPP holds, redemption.
- **Name servers**: delegation read from the TLD itself; every NS queried directly (AA flag, lame,
  unreachable, glue, parent/child mismatch, serial skew, network diversity).
- **DNS zone**: records with TTLs straight from the authoritative servers; apex CNAME, dangling
  CNAME, MX problems; SPF/DMARC/DKIM; DNSSEC chain validation; comparison with 1.1.1.1/8.8.8.8/9.9.9.9.
- **Reachability**: ICMP + TCP 80/443 from every measurement node; regional failures; IPv6.
- **Website load**: finds *where* a site fails — CDN/WAF, origin web server, application, TLS,
  network or page content. A request matrix from every node (GET/HEAD, apex/www, HTTP/HTTPS,
  browser/curl/Googlebot User-Agents, HTTP/1.1 vs HTTP/2, with/without compression, optional
  origin-IP test), CDN/server/platform fingerprints with confidence and evidence, subresource
  checks (failed/slow assets, mixed content, MIME, compression, caching, CORS), and a YAML
  knowledge base of 80+ rules (Cloudflare 52x/1xxx, CloudFront, Akamai, Fastly, Sucuri, origin
  4xx/5xx deep dives, TLS and connection failures) with safe, server-specific fixes
  (Apache/nginx/LiteSpeed/IIS) and verify steps.

Web UI (EN/FA) with live progress (SSE), per-node tables, a Website load verdict card with request
matrix, resource waterfall and a server-type selector, Copy Link / Permanent Link, JSON and
Markdown export; JSON API (`POST /api/check`, `POST /api/web-diagnose`); CLI
(`domaindoctor check example.com --json [--origin-ip IP]`); master/agent deployment.

```bash
go test ./...
go run ./cmd/domaindoctor check example.com
go run ./cmd/master          # single-node mode, http://127.0.0.1:8082
docker compose up --build    # master + 2 agents (see INSTALL.md)

# Website load demo: nginx + Apache + fake CDN (10 broken/healthy scenarios)
DEMO_CERTS=1 go test ./internal/e2e -run TestDemoCerts
docker compose -f deploy/demo/docker-compose.demo.yml up -d
DEMO_DOCKER=1 go test ./internal/e2e -run TestLoadDemo -v
```

Docs: [INSTALL.md](INSTALL.md) · [docs/API.md](docs/API.md) · [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
example reports in [docs/demo/](docs/demo/) and [docs/demo/load/](docs/demo/load/).

The deployment design follows [komyl/looking-glass](https://github.com/komyl/looking-glass)
(design only — no code was copied).
