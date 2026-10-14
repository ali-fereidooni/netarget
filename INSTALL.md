# Installing Domain Doctor

Two binaries: **master** (UI + API + DNS/RDAP lookups, embeds the web UI) and **agent**
(runs on each measurement node). Plus the **domaindoctor** CLI.

> **Network requirement:** for full checks the master (or CLI) must be able to send DNS queries
> directly to the Internet (UDP and TCP port 53 to root, TLD and authoritative servers) and HTTPS
> to RDAP servers. If port 53 is blocked, `DNS_TRANSPORT=auto` (the default) falls back to
> **DNS-over-HTTPS resolver mode**: DNS data comes from Cloudflare/Google/Quad9 over HTTPS, and the
> per-server name-server tests (AA flag, lame delegation, glue, SOA serials) are skipped — reports
> say so with the `ns.limited_mode` finding. Agents need outbound ICMP, TCP 80/443, and DNS (for
> redirect targets).
>
> Measurement nodes behind a VPN/TUN client (e.g. nekoray, sing-box, v2ray in TUN mode) get
> **fake ping and TCP results**: the tunnel answers ICMP and accepts every TCP connection locally
> (0 ms RTT). Run agents on hosts with a plain network path.

## 1. Build

Requires Go 1.26 (see `go.mod`).

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/domaindoctor-master ./cmd/master
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/domaindoctor-agent  ./cmd/agent
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/domaindoctor        ./cmd/domaindoctor
```

Cross-compile for a Linux server from anywhere with `GOOS=linux GOARCH=amd64`.
Run the tests with `go test ./...` (no network needed; DNS, RDAP and HTTP are mocked).

Agents need `ping` (iputils) and `traceroute`:
```bash
sudo apt install iputils-ping traceroute
```

## 2. Quick start

CLI, single machine:
```bash
./bin/domaindoctor check example.com
./bin/domaindoctor check https://www.example.com/path --json
./bin/domaindoctor check example.com --md > report.md
```
Exit status: 0 = no layer failed, 2 = at least one layer FAILed, 1 = bad input.

Single-node master (master probes from itself, no agents):
```bash
REPORTS_DIR=./data/reports ./bin/domaindoctor-master   # http://127.0.0.1:8082
```

Docker (one master + two agents):
```bash
cp deploy/env/compose.env.example .env
sed -i "s/REPLACE_WITH_64_HEX_CHARS/$(openssl rand -hex 32)/" .env
docker compose up --build
```

## 3. Production layout

```
/usr/local/bin/domaindoctor-master        master host
/usr/local/bin/domaindoctor-agent         every agent host
/etc/domaindoctor/master.env  (0600)      env config, contains the agent secret
/etc/domaindoctor/agent.env   (0600)
/etc/domaindoctor/nodes.json              node registry (no secrets)
/var/lib/domaindoctor/reports/            permanent links (systemd StateDirectory)
/var/lib/domaindoctor/ipinfo_lite.csv.gz  optional ASN dataset
```

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin domaindoctor
sudo install -m 0755 bin/domaindoctor-master /usr/local/bin/
sudo install -d -m 0750 -o root -g domaindoctor /etc/domaindoctor
sudo install -m 0640 -o root -g domaindoctor deploy/env/master.env.example /etc/domaindoctor/master.env
sudo install -m 0644 deploy/nodes.example.json /etc/domaindoctor/nodes.json
sudo install -m 0644 deploy/systemd/domaindoctor-master.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now domaindoctor-master
```
On each agent host the same with `domaindoctor-agent`, `agent.env` and
`domaindoctor-agent.service`.

### Secrets

Generate one secret and put the same value in `master.env` (`AGENT_SECRET`) and every
`agent.env`:
```bash
openssl rand -hex 32
```
For per-node secrets set `"secret_env": "AGENT_SECRET_THR1"` on that node in `nodes.json` and
define `AGENT_SECRET_THR1=…` in `master.env`. Agents can read the secret from a file with
`AGENT_SECRET_FILE`. Nothing secret goes into `nodes.json` or the repository.

## 4. Configuration (environment)

### Master

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `127.0.0.1:8082` | bind address (keep it on loopback behind nginx) |
| `NODES_FILE` | — | node registry JSON; unset = single-node mode |
| `AGENT_SECRET` | — | shared agent secret (≥ 32 chars) |
| `LOCAL_AGENT` | `0` | `1` = also probe from the master itself |
| `LOCAL_NODE_NAME` / `LOCAL_NODE_LOCATION` | `Master node` / `local` | public label of the local node |
| `TRUSTED_PROXY_HOPS` | `1` | reverse proxies in front (nginx = 1, CDN + nginx = 2, none = 0) |
| `TRUSTED_PROXY_CIDRS` | `127.0.0.1,::1` | only honour `X-Forwarded-For` when the TCP peer is in these CIDRs |
| `REPORTS_DIR` | `./data/reports` | permanent-link storage; `-` disables the feature |
| `REPORTS_CAP` | `2000` | max active permanent links (new ones rejected when full) |
| `MAX_CONCURRENT_CHECKS` | `30` | global cap on running checks + traceroutes |
| `ASN_CSV_PATH` | — | optional ASN dataset (CSV or CSV.GZ) |
| `DNS_TRANSPORT` | `auto` | `direct` (port 53 only), `doh` (resolver mode only), `auto` (direct, falling back to DoH when root servers don't answer; decided at startup) |

### Agent

| Variable | Default | Meaning |
|---|---|---|
| `AGENT_LISTEN` | `127.0.0.1:9090` | bind address — use the **private** interface |
| `AGENT_SECRET` / `AGENT_SECRET_FILE` | — | required, ≥ 32 chars |

## 5. Node registry

`/etc/domaindoctor/nodes.json`:
```json
{
  "nodes": [
    {"id": "fra1", "name": "Frankfurt — Hetzner", "location": "DE", "url": "http://10.0.0.2:9090"},
    {"id": "thr1", "name": "Tehran — ISP", "location": "IR", "url": "http://10.0.0.3:9090", "secret_env": "AGENT_SECRET_THR1"}
  ]
}
```
`id`: `[a-z0-9-]`, unique. `url` must be the private address. Only `id`, `name`, `location` are
ever shown to users. Restart the master after editing.

## 6. Firewall (ufw) on agents

The agent port must only accept the master's private address:
```bash
sudo ufw default deny incoming
sudo ufw allow OpenSSH
sudo ufw allow from 10.0.0.1 to any port 9090 proto tcp   # 10.0.0.1 = master private IP
sudo ufw enable
sudo ufw status numbered
```
On the master: allow 80/443 (nginx) and SSH only; 8082 stays on loopback.

## 7. nginx (SSE-friendly)

Use `deploy/nginx/domaindoctor.conf`. The important parts:
- `proxy_buffering off;` and long `proxy_read_timeout` for Server-Sent Events (the master also
  sends `X-Accel-Buffering: no`).
- `proxy_set_header X-Forwarded-For $remote_addr;` (overwrite, don't append) with
  `TRUSTED_PROXY_HOPS=1` and `TRUSTED_PROXY_CIDRS=127.0.0.1,::1`.
- If a CDN sits in front of nginx, use `$proxy_add_x_forwarded_for` and `TRUSTED_PROXY_HOPS=2`,
  and make sure only the CDN can reach nginx.

## 8. Optional ASN / operator data

Traceroute hops and the name-server network-diversity check can show ASN and operator names.
Download the free **IPinfo Lite** database in CSV format (requires a free ipinfo.io token):
```bash
curl -fsSL "https://ipinfo.io/data/ipinfo_lite.csv.gz?token=$IPINFO_TOKEN" -o /var/lib/domaindoctor/ipinfo_lite.csv.gz
```
Any CSV with a header containing `network` (CIDR) and `asn`, optionally `as_name` and
`as_domain`, works. Set `ASN_CSV_PATH` and restart. Without it everything works; hops simply have
no ASN, and NS diversity falls back to comparing /24 (IPv4) and /48 (IPv6) networks.

## 9. Verify

```bash
curl -s http://127.0.0.1:8082/healthz          # ok
curl -s http://127.0.0.1:8082/api/nodes        # live nodes (id/name/location only)
curl -s -XPOST http://127.0.0.1:8082/api/check -d '{"domain":"example.com"}'
journalctl -u domaindoctor-master -f            # "node X marked dead…" etc.
```
