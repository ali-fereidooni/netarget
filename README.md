# Domain Doctor

Enter a domain; Domain Doctor checks it layer by layer —
**registration → name servers → DNS zone → reachability → web server** — stops to explain the
root cause when a layer fails, separates causes from symptoms, and gives a prioritized fix list.

- **Registration**: RDAP (IANA bootstrap) with WHOIS fallback; expiry, EPP holds, redemption.
- **Name servers**: delegation read from the TLD itself; every NS queried directly (AA flag, lame,
  unreachable, glue, parent/child mismatch, serial skew, network diversity).
- **DNS zone**: records with TTLs straight from the authoritative servers; apex CNAME, dangling
  CNAME, MX problems; SPF/DMARC/DKIM; DNSSEC chain validation; comparison with 1.1.1.1/8.8.8.8/9.9.9.9.
- **Reachability**: ICMP + TCP 80/443 from every measurement node; regional failures; IPv6.
- **Web**: HTTP/HTTPS for apex and www with the full redirect chain, timing breakdown, security
  headers, TLS details, precise error classes (timeout/refused/reset/TLS/4xx/5xx/CDN pages).

Web UI with live progress (SSE), per-node tables, Copy Link / Permanent Link, JSON and Markdown
export; JSON API; CLI (`domaindoctor check example.com --json`); master/agent deployment.

```bash
go test ./...
go run ./cmd/domaindoctor check example.com
go run ./cmd/master          # single-node mode, http://127.0.0.1:8082
docker compose up --build    # master + 2 agents (see INSTALL.md)
```

Docs: [INSTALL.md](INSTALL.md) · [docs/API.md](docs/API.md) · [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
example reports in [docs/demo/](docs/demo/).

The deployment design follows [komyl/looking-glass](https://github.com/komyl/looking-glass)
(design only — no code was copied).
