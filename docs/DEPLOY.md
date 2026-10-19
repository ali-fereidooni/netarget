# Deploying netarget: master node, agents, adding a node

This guide deploys netarget with Docker:
- one **master** server that serves the panel, runs the DNS and registration checks, and probes from itself;
- any number of **agent** servers, which add measurement locations for the ping, TCP, HTTP and traceroute probes.

It matches the production setup of https://netarget.ir. For building binaries, the systemd units and every configuration variable, see [INSTALL.md](../INSTALL.md).

```
 visitor ──HTTPS──▶ ParsPack CDN ──▶ master server (nginx :80/:443 ─▶ master container 127.0.0.1:8082)
                                          │  local agent (probes from the master itself)
                                          │
                                          ├──HTTPS + X-Agent-Secret + pinned cert──▶ agent server A :9443
                                          └──HTTPS + X-Agent-Secret + pinned cert──▶ agent server B :9443
```

Each agent port accepts the master's IP only, and visitors never see agent addresses. The panel shows only each node's `id`, `name` and `location`.

---

## 1. Prepare a server (master or agent)

Tested on AlmaLinux 10 and Ubuntu 24.04, with 1 vCPU and 1 GB RAM or more. Run everything as root.

### AlmaLinux / RHEL 10

```bash
dnf -y install git firewalld dnf-plugins-core
dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
# The EL10 kernel has no xt_addrtype module: use Docker's nftables backend.
mkdir -p /etc/docker && printf '{\n  "firewall-backend": "nftables"\n}\n' > /etc/docker/daemon.json
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/90-docker.conf && sysctl -p /etc/sysctl.d/90-docker.conf
systemctl enable --now docker firewalld
```

### Ubuntu 24.04

```bash
apt-get update && apt-get install -y git ca-certificates curl ufw
curl -fsSL https://get.docker.com | sh
```

### Clone and check ICMP

Clone the repository on every server:

```bash
git clone https://github.com/ali-fereidooni/netarget.git /opt/netarget
cd /opt/netarget
```

Check that unprivileged ping is allowed. The containers run as an unprivileged user and use the host network:

```bash
sysctl net.ipv4.ping_group_range      # must print "0	2147483647"
```

If it prints `1 0`, fix it:

```bash
echo "net.ipv4.ping_group_range = 0 2147483647" > /etc/sysctl.d/90-ping.conf && sysctl -p /etc/sysctl.d/90-ping.conf
```

> Don't run agents behind a VPN or TUN client (v2ray, sing-box, nekoray in TUN mode). The tunnel answers ping and TCP locally, so every result would be fake.

---

## 2. Deploy the master node

### 2.1 Start the master

```bash
cd /opt/netarget
docker compose -f docker-compose.master.yml up -d --build
curl -s http://127.0.0.1:8082/healthz      # ok
curl -s http://127.0.0.1:8082/api/nodes    # [{"id":"local","name":"netarget","location":"IR"}]
```

[`docker-compose.master.yml`](../docker-compose.master.yml) runs the master on `127.0.0.1:8082` with:
- `LOCAL_AGENT=1`, so the master is also a measurement node;
- host networking;
- one trusted proxy hop (nginx on the same host).

Permanent links are kept in the `reports` Docker volume.

To change the local node's label, create `/opt/netarget/.env` (mode 0600) and recreate the container:

```bash
LOCAL_NODE_NAME=Tehran (Asiatech)
LOCAL_NODE_LOCATION=IR
```

### 2.2 nginx

**AlmaLinux:**

```bash
dnf -y install nginx policycoreutils-python-utils
semanage port -m -t http_port_t -p tcp 8082   # use -a instead of -m if 8082 has no SELinux type yet
setsebool -P httpd_can_network_relay 1        # let nginx proxy to 127.0.0.1:8082
```

**Ubuntu:**

```bash
apt-get install -y nginx
rm -f /etc/nginx/sites-enabled/default   # it also claims default_server on port 80
```

Self-signed origin certificate. Visitors see the CDN's certificate; this one only protects the CDN-to-origin hop.

```bash
install -d -m 0750 /etc/nginx/ssl
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
  -subj /CN=netarget.ir -addext "subjectAltName=DNS:netarget.ir,DNS:www.netarget.ir" \
  -keyout /etc/nginx/ssl/netarget.ir.key -out /etc/nginx/ssl/netarget.ir.crt
chmod 600 /etc/nginx/ssl/netarget.ir.key
```

ParsPack edge ranges. These are used to trust the visitor IP header and in the firewall:

```bash
curl -fsS https://parspack.com/cdnips.txt | grep -E '^[0-9a-fA-F.:]+/[0-9]+$' > /root/parspack-ips.txt
sed 's/^/set_real_ip_from /; s/$/;/' /root/parspack-ips.txt > /etc/nginx/parspack-realip.conf
sed 's/$/ 1;/'                      /root/parspack-ips.txt > /etc/nginx/parspack-geo.conf
```

Install the site and start nginx:

```bash
cp deploy/nginx/netarget-parspack.conf /etc/nginx/conf.d/netarget.conf
nginx -t && systemctl enable --now nginx && systemctl reload nginx
```

[`deploy/nginx/netarget-parspack.conf`](../deploy/nginx/netarget-parspack.conf) does the following:
- Unknown host names get no answer. Port 443 rejects the TLS handshake for any name it doesn't serve.
- `www.netarget.ir` redirects to `https://netarget.ir`.
- The visitor IP is read from `X-Real-IP`, but only when the request comes from a ParsPack edge. It is passed to the master as `X-Forwarded-For`.
- **Port 80 is CDN-aware.** ParsPack connects to the origin over plain HTTP for every visitor and sends no header saying whether the visitor used HTTP or HTTPS. A blanket HTTP→HTTPS redirect at the origin would loop forever. So:
  - requests from ParsPack edges are served;
  - direct requests are redirected to HTTPS;
  - every response carries HSTS.

  The full redirect for visitors is configured in ParsPack (step 2.4).
- Server-Sent Events (check progress, traceroute) are not buffered.

### 2.3 Firewall on the master

Open SSH and HTTP to everyone, and HTTPS to ParsPack only, so nobody can bypass the CDN.

**AlmaLinux (firewalld):**

```bash
firewall-cmd --permanent --add-service=ssh --add-service=http
firewall-cmd --permanent --new-ipset=parspack4 --type=hash:net
firewall-cmd --permanent --ipset=parspack4 --add-entries-from-file=/root/parspack-ips.txt
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source ipset=parspack4 service name=https accept'
firewall-cmd --reload
systemctl restart docker      # Docker re-registers its rules with firewalld
```

**Ubuntu (ufw):**

```bash
ufw allow OpenSSH && ufw allow 80/tcp
while read -r net; do ufw allow from "$net" to any port 443 proto tcp comment parspack; done < /root/parspack-ips.txt
ufw enable
```

ParsPack sometimes adds edge ranges. Re-run the `cdnips.txt` commands above when they do, and reload nginx and the firewall.

### 2.4 ParsPack panel (netarget.ir)

- **DNS:** `netarget.ir` and `www`, A records pointing to the master's IP, proxied (CDN on).
- **Origin:** the master's IP. The origin currently works over HTTP on port 80. For a clean setup, set the origin protocol to **HTTPS, port 443**, with certificate verification off (the origin certificate is self-signed).
- **Redirect:** turn on ParsPack's **HTTP → HTTPS redirect**. This is the only place a visitor's plain-HTTP request can be redirected without a loop.
- **Cache:** purge it after changing the origin.

### 2.5 Verify

From any machine:

```bash
curl -sI https://netarget.ir/ | head -1                                   # HTTP/2 200
curl -s https://netarget.ir/api/nodes
```

On the master:

```bash
tail -f /var/log/nginx/netarget.access.log      # peer= is the ParsPack edge, first field is the visitor
docker compose -f docker-compose.master.yml logs -f
```

---

## 3. Deploy an agent node

Do this on each new measurement server. In this section, `MASTER_IP` is the master's public IP (`193.242.125.249` for netarget.ir), and `AGENT_IP` is the new server's public IP.

### 3.1 Prepare the server and clone

Follow section 1.

### 3.2 Secret and TLS certificate

Every agent gets **its own** secret. Write it down; the master needs it in step 4.

```bash
cd /opt/netarget
install -d -m 0750 config
umask 077
echo "AGENT_SECRET=$(openssl rand -hex 32)" > .env
echo "AGENT_LISTEN=0.0.0.0:9443" >> .env
cat .env                                     # copy the AGENT_SECRET value
```

Build the image and create the certificate:

```bash
docker compose -f docker-compose.agent.yml build
docker run --rm --user 0 -v "$PWD/config:/out" netarget:latest /usr/local/bin/agent gen-cert -dir /out -hosts AGENT_IP
chown 10001 config/agent.key                 # the container user (uid 10001) must read the key
```

`gen-cert` prints the agent's **`cert_sha256`** fingerprint. Copy it too. Existing files are never overwritten.

### 3.3 Firewall: the agent port accepts the master only

**AlmaLinux (firewalld):**

```bash
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=MASTER_IP port port=9443 protocol=tcp accept'
firewall-cmd --reload && systemctl restart docker
```

**Ubuntu (ufw):**

```bash
ufw default deny incoming && ufw allow OpenSSH
ufw allow from MASTER_IP to any port 9443 proto tcp
ufw enable
```

### 3.4 Start the agent

```bash
docker compose -f docker-compose.agent.yml up -d
docker compose -f docker-compose.agent.yml logs --tail 5
```

The log shows `TLS enabled, cert_sha256 …` and `listening on 0.0.0.0:9443`.

Local test: the response is 200 with the secret and 401 without it.

```bash
S=$(sed -n 's/^AGENT_SECRET=//p' .env)
curl -sk -o /dev/null -w "%{http_code}\n" -H "X-Agent-Secret: $S" https://127.0.0.1:9443/health   # 200
curl -sk -o /dev/null -w "%{http_code}\n" https://127.0.0.1:9443/health                          # 401
```

From the master, the same request with the secret must return 200 when sent to `https://AGENT_IP:9443/health`. From any other machine, the port must not answer at all.

---

## 4. Add an agent node to the master

All steps are on the **master**, in `/opt/netarget`.

### 4.1 Register the node

Create `config/nodes.json`, or add an entry to it. It holds no secrets.

```json
{
  "nodes": [
    {
      "id": "fra1",
      "name": "Frankfurt (Hetzner)",
      "location": "DE",
      "url": "https://AGENT_IP:9443",
      "secret_env": "AGENT_SECRET_FRA1",
      "cert_sha256": "PASTE_THE_FINGERPRINT_FROM_GEN_CERT"
    }
  ]
}
```

| Field | Rule |
|---|---|
| `id` | `[a-z0-9-]`, 1 to 32 characters, unique. Shown publicly. |
| `name`, `location` | Public labels in the panel. |
| `url` | `https://` plus the agent's IP and port. Never shown to visitors. |
| `secret_env` | Name of the variable in `.env` that holds this agent's secret. If omitted, `AGENT_SECRET` is used. |
| `cert_sha256` | The fingerprint from `gen-cert`: 64 hex digits; the openssl colon form is accepted. The master refuses to connect if it doesn't match. |

### 4.2 Add the secret and point the master at the file

`/opt/netarget/.env` (mode 0600):

```bash
NODES_FILE=/etc/netarget/nodes.json
AGENT_SECRET_FRA1=<the AGENT_SECRET value from the agent's .env>
```

`./config` is mounted read-only at `/etc/netarget` inside the master container.

### 4.3 Restart and check

```bash
chmod 600 .env
docker compose -f docker-compose.master.yml up -d       # recreates the container with the new .env
curl -s http://127.0.0.1:8082/api/nodes                  # local + fra1
docker compose -f docker-compose.master.yml logs --tail 20
```

- New nodes start live, and the master health-checks every node every 12 seconds.
- A node that fails two checks in a row is marked dead (`node fra1 marked dead after 2 failed health checks`). Dead nodes disappear from the panel and from fan-outs until one check succeeds again.
- The master reads `nodes.json` only at start, so restart it after every edit:

  ```bash
  docker compose -f docker-compose.master.yml restart master
  ```

### 4.4 Change or remove a node

- **Remove:**
  1. Delete its entry from `nodes.json` and its `AGENT_SECRET_*` line from `.env`.
  2. Run `docker compose -f docker-compose.master.yml up -d`.
  3. On the agent server, run `docker compose -f docker-compose.agent.yml down`.
- **Rotate the secret:**
  1. Put a new `AGENT_SECRET` in the agent's `.env` and run `up -d` there.
  2. Update `AGENT_SECRET_<ID>` on the master and run `up -d`.
- **Rotate the certificate:**
  1. On the agent, delete `config/agent.crt` and `config/agent.key`, run `gen-cert` again, and restart the agent.
  2. Put the new `cert_sha256` into `nodes.json` and restart the master.
- **Agent on the same private network as the master:** use `http://PRIVATE_IP:9090` without `cert_sha256`. In that case set `AGENT_LISTEN` to the private IP and leave out the TLS lines.

---

## 5. Updating

On each server:

```bash
cd /opt/netarget && git pull --ff-only
docker compose -f docker-compose.master.yml up -d --build    # on the master
docker compose -f docker-compose.agent.yml up -d --build     # on agents
```

Static assets are versioned (`app.js?v=<hash>`), so a new UI reaches visitors through the CDN without purging.

## 6. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `docker.service` fails with `addrtype ... missing kernel module` | EL10 kernel. Use `"firewall-backend": "nftables"` (section 1). |
| Docker fails with `IPv4 forwarding is disabled` | Set `net.ipv4.ip_forward = 1` (section 1). |
| nginx 502, `connect() ... (13: Permission denied)` | SELinux. Run `setsebool -P httpd_can_network_relay 1` and the `semanage port` command (2.2). |
| Every page redirects to itself | The ParsPack origin is HTTP and the origin redirects port 80. Use the provided nginx config, and do the redirect in ParsPack (2.4). |
| netarget.ir shows the cPanel default page or a ParsPack "Upstream Error" | The ParsPack origin points at the wrong server. Fix it in the panel and purge the cache. |
| A node never appears in `/api/nodes` | Check, in order: the agent logs, the agent firewall (allow `MASTER_IP`), a `cert_sha256` that doesn't match the agent's `TLS enabled, cert_sha256 …` line, and `AGENT_SECRET_<ID>` versus the agent's `AGENT_SECRET`. |
| Ping shows `no reply` everywhere but TCP works | ICMP is blocked by the target, which is normal. If it happens for every target, check `net.ipv4.ping_group_range` on that node (section 1). |
| All pings report about 0 ms and every port is open | The node is behind a VPN or TUN client. Run the agent on a host with a plain network path. |
