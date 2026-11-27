# Deploying `countersignd`

This guide covers running `countersignd` in production (systemd or Docker) and
exposing it cleanly with Cloudflare Tunnel (+ optional Cloudflare Access),
Tailscale, a reverse proxy (Caddy / nginx), or a hybrid combination.

## 1. Prepare secrets and configuration

Create `/etc/countersign` and generate the required keys (never put secrets in
`config.toml`):

```sh
sudo install -d -o root -g countersign -m 0750 /etc/countersign
sudo countersign keygen /etc/countersign/session.key
sudo countersign signing-key /etc/countersign/signing.key
# Optional: if enabling browser Web Push notifications
sudo countersign vapid-key /etc/countersign/vapid.key
sudo chown root:countersign /etc/countersign/*.key
sudo chmod 0640 /etc/countersign/*.key
```

Start from [`crates/countersignd/config.example.toml`](../../crates/countersignd/config.example.toml),
save it as `/etc/countersign/config.toml`, and validate it:

```sh
countersignd --config /etc/countersign/config.toml check
```

## 2. Running `countersignd`

### systemd

Install [`deploy/systemd/countersignd.service`](../../deploy/systemd/countersignd.service)
and the server binaries (`countersignd`, `countersign`):

```sh
sudo install -m 0755 countersignd countersign /usr/local/bin/
sudo useradd --system --home /var/lib/countersign --shell /usr/sbin/nologin countersign
sudo install -m 0644 deploy/systemd/countersignd.service /etc/systemd/system/countersignd.service
sudo systemctl daemon-reload
sudo systemctl enable --now countersignd
```

#### Hot-reloading configuration and TLS certificates

Sending `SIGHUP` reloads `[[person]]`, `[[workload]]`, `[[group]]`, `[roles]`,
`[[client]]`, `[[policy]]`, `[[question_policy]]`, `store.retention`, and TLS
certificates without dropping active connections:

```sh
sudo systemctl reload countersignd
```

Changes to `[server]`, `[auth]`, `[store].path`, `[engine].poll_interval`,
`[backend.*]`, `[intake]`, or `[channel.*]` require `systemctl restart countersignd`.

### Docker

Build the server image (`countersignd` + `countersign` CLI) from the repository
root [`Dockerfile`](../../Dockerfile):

```sh
docker build -t countersign:local .
docker run -d --name countersignd \
  -v /etc/countersign:/etc/countersign:ro \
  -v countersign-state:/var/lib/countersign \
  -p 2780:2780 -p 2743:2743 \
  countersign:local
```

> [!WARNING]
> **Container networking:** Inside a container, `127.0.0.1` is unreachable
> from the host. Bind `[server].listen` to `0.0.0.0:2780` with `tls` (or a
> private container network IP behind a proxy). Because `[intake]` with
> `behind_proxy = true` refuses `0.0.0.0`, either terminate TLS inside the
> container (`tls = { cert_file, key_file }`) or bind `[intake].listen` to the
> container's private bridge IP.

## 3. Exposing Countersign: two independent listeners

`countersignd` exposes two distinct HTTP surfaces with different clients and
authentication models:

| Listener                      | Default paths                                                                                         | Who connects                                                    | Authentication                                                          | Browser Access gate (e.g. Cloudflare Access)         |
| ----------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------- |
| **Web UI** (`[server]`)       | `/`, `/login`, `/auth/callback`, `/api/*`, `/sw.js`, `/manifest.webmanifest`, `/icon.svg`, `/healthz` | Humans in browsers / installed PWAs                             | OIDC sign-in + session cookie (`fresh-auth` verified by `countersignd`) | Supported, **with static PWA/SW paths bypassed**     |
| **Intake & MCP** (`[intake]`) | `/intake/v1/*`, `/mcp`                                                                                | Machines: `countersign-sudo`, `countersign-ask`, AI MCP clients | `Authorization: Bearer` (static `cshk_` host key or CI OIDC JWT)        | **Must be bypassed** (or put on a separate hostname) |

Because the two listeners are completely independent, you can publish both
through the same stack (Recipes 4.1–4.3) or mix different stacks for each
listener (Recipe 4.4).

> [!NOTE]
> **TLS termination trust boundary:** Even when a proxy or tunnel terminates TLS
> in front of `[intake]`, every `sudo` approval is signed with `countersignd`'s
> Ed25519 key (`signing_key_file`) and verified against pinned `server_keys` on
> the target host. A proxy or tunnel can observe or block traffic, but cannot
> forge an approval.

## 4. Deployment recipes

### 4.1 Cloudflare Tunnel (+ optional Cloudflare Access)

Zero open inbound ports, automatic HTTPS, and reachable from external CI
(GitHub Actions) and mobile devices.

#### Basic setup (Tunnel only)

Keep both listeners on loopback and enable `behind_proxy` on `[intake]`:

```toml
# /etc/countersign/config.toml
[server]
public_url = "https://countersign.example.com"
listen = "127.0.0.1:2780"

[intake]
listen = "127.0.0.1:2781"
behind_proxy = true
client_ip_header = "cf-connecting-ip" # only needed if any [[client]] uses allowed_ips
signing_key_file = "/etc/countersign/signing.key"
```

Configure `cloudflared` ingress rules (evaluated top to bottom):

```yaml
ingress:
  - hostname: countersign.example.com
    path: ^/intake/.*
    service: http://127.0.0.1:2781
  - hostname: countersign.example.com
    path: ^/mcp$
    service: http://127.0.0.1:2781
  - hostname: countersign.example.com
    service: http://127.0.0.1:2780
  - service: http_status:404
```

- **Long polling:** Cloudflare enforces a 100 s origin read timeout (`524`).
  `countersignd` caps `?wait=` at 60 s (`countersign-sudo` and `countersign-ask`
  use 50 s; MCP uses 45 s), so long polling works without extra tuning.

#### Optional: adding Cloudflare Access in front of the Web UI

If you restrict the web UI with Cloudflare Access, **do not protect every path
on the same hostname without exceptions** — machine clients and PWA/Service
Worker fetches do not carry a Cloudflare Access cookie and will fail on `302`
redirects to the Access login page.

**Recommended layout — split hostnames:**

- `countersign.example.com` → `http://127.0.0.1:2780` (protected by Cloudflare Access, with PWA/SW paths bypassed below)
- `intake.countersign.example.com` → `http://127.0.0.1:2781` (no Cloudflare Access; authenticated by host keys / CI OIDC JWTs)

**Required Cloudflare Access Bypass applications:**

| Path                    | Why Bypass is required                                                                                                                                     |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/sw.js`                | Browsers update Service Workers in the background when `CF_Authorization` may be expired. A `302` or HTML login page breaks Web Push and PWA registration. |
| `/manifest.webmanifest` | Fetched without credentials by default on many browsers; a redirect breaks PWA installation.                                                               |
| `/icon.svg`             | Loaded by OS notifications and the manifest without Access cookies.                                                                                        |
| `/intake/*`             | _(Only if sharing one hostname)_ `countersign-sudo` and `countersign-ask` use Bearer tokens and intentionally refuse HTTP redirects.                       |
| `/mcp`                  | _(Only if sharing one hostname)_ MCP clients use Bearer tokens, not Access cookies.                                                                        |
| `/healthz`              | _(Optional)_ Needed only if an external uptime monitor probes `/healthz`.                                                                                  |

**Session & `fresh-auth` notes:**

- Cloudflare Access is a perimeter gate, **not** a replacement for `[auth.oidc]`.
  `countersignd` still runs its own OIDC flow so it can verify `auth_time` for
  `fresh-auth` policies.
- Set your Cloudflare Access session duration to at least `server.session_ttl`
  (for example, 24 h in Access vs. `12h` in `countersignd`) to avoid double
  sign-in prompts when opening a Web Push notification.

### 4.2 Tailscale (tailnet-only)

Keep `countersignd` completely off the public internet. Because Slack (Socket
Mode) and Discord (Gateway) connect **outbound** from `countersignd`, chat
notifications and button approvals still work with zero public exposure.

#### Option A: `tailscale serve` (recommended)

Enable MagicDNS and HTTPS certificates in the Tailscale admin console, then
publish the two listeners on **separate HTTPS ports**:

```sh
tailscale serve --bg --https=443  http://127.0.0.1:2780   # Web UI
tailscale serve --bg --https=8443 http://127.0.0.1:2781   # Intake API & MCP
```

> [!TIP]
> **Why separate ports (`443` and `8443`) instead of `--set-path /intake`?**
> `tailscale serve --set-path /intake http://127.0.0.1:2781` strips the `/intake`
> prefix before forwarding, which breaks `countersignd`'s `/intake/v1/...`
> routes. Tailscale Serve supports HTTPS on ports `443`, `8443`, and `10000`, so
> exposing intake on `8443` avoids path rewriting altogether.

```toml
# /etc/countersign/config.toml
[server]
public_url = "https://countersign.<tailnet>.ts.net"
listen = "127.0.0.1:2780"

[intake]
listen = "127.0.0.1:2781"
behind_proxy = true
client_ip_header = "x-forwarded-for" # only needed if using allowed_ips with 100.x.y.z
signing_key_file = "/etc/countersign/signing.key"
```

Target hosts enroll against `https://countersign.<tailnet>.ts.net:8443`.

#### Option B: `tailscale cert` with direct TLS

If you want `countersignd` to terminate TLS directly (and see the peer's
`100.x.y.z` IP without `behind_proxy` or `client_ip_header`):

1. Provision a certificate for the node:

   ```sh
   sudo tailscale cert \
     --cert-file /etc/countersign/tls/fullchain.pem \
     --key-file  /etc/countersign/tls/key.pem \
     countersign.<tailnet>.ts.net
   ```

2. Bind `[server].listen` and `[intake].listen` to the node's Tailscale IP with
   `tls = { cert_file = ..., key_file = ... }`.
3. Renew certificates periodically via a systemd timer and run
   `systemctl reload countersignd` (SIGHUP hot-reloads the certificate without
   restarting).

#### Operational notes for Tailscale

- **External OIDC providers work out of the box:** OIDC authorization code flow
  redirects through the approver's browser (which is on the tailnet), and
  `countersignd` makes outbound requests to the IdP. Register
  `https://countersign.<tailnet>.ts.net/auth/callback` as the redirect URI.
- **Mobile Web Push (PWA):** Push notifications still arrive via the browser's
  push service, but the phone must have Tailscale enabled to open the approval
  page when tapped.
- **GitHub Actions (`countersign-ask --github-oidc`):** GitHub-hosted runners
  are outside your tailnet. Either join the tailnet ephemerally during the job
  with `tailscale/github-action`, use a self-hosted runner on your tailnet, or
  use the **Hybrid** layout below.

### 4.3 Reverse proxy (Caddy / nginx)

On a VPS or server with a public IP, keep both listeners on `127.0.0.1`, set
`behind_proxy = true` under `[intake]`, and route **both** `/intake/*` and
`/mcp` to the intake listener:

```caddyfile
countersign.example.com {
    handle /intake/* {
        reverse_proxy 127.0.0.1:2781
    }
    handle /mcp {
        reverse_proxy 127.0.0.1:2781
    }
    handle {
        reverse_proxy 127.0.0.1:2780
    }
}
```

If any `[[client]]` sets `allowed_ips`, also set
`client_ip_header = "x-forwarded-for"` under `[intake]`.

### 4.4 Mixing listeners (Hybrid)

A strong pattern when you have external CI (GitHub Actions) or cloud hosts, yet
want the human Web UI completely private:

- **Web UI (`[server]`):** Keep on `127.0.0.1:2780` and expose **only** inside
  Tailscale (`tailscale serve --bg --https=443 http://127.0.0.1:2780`), or
  behind Cloudflare Access.
- **Intake & MCP (`[intake]`):** Expose on a dedicated hostname (for example
  `intake.countersign.example.com`) via Cloudflare Tunnel (no Access) or direct
  TLS on `:2743`.

```toml
[server]
public_url = "https://countersign.<tailnet>.ts.net"
listen = "127.0.0.1:2780"

[intake]
listen = "127.0.0.1:2781"
behind_proxy = true
client_ip_header = "cf-connecting-ip"
signing_key_file = "/etc/countersign/signing.key"
```

Operators approve from their tailnet (or Slack/Discord), while GitHub Actions
and remote hosts submit requests to `https://intake.countersign.example.com`
authenticated by OIDC JWTs or `cshk_` host keys.

## 5. Metrics, health checks, and backups

- **Prometheus metrics:** Set `metrics_listen = "127.0.0.1:2790"` under
  `[server]` to expose `GET /metrics` on a dedicated loopback listener.
- **Health check:** `GET /healthz` on the Web UI listener returns `200 OK`
  (`ok`).
- **Backups:** Back up SQLite online with:

  ```sh
  sqlite3 /var/lib/countersign/countersign.db ".backup /backups/countersign.db"
  ```

  Confidential question text and answers are overwritten in place
  (`secure_delete = ON`) and WAL-checkpointed once no longer needed, but older
  backups retain whatever was present when they were taken until those backups
  expire.
