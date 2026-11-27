# Deploying `countersignd`

This guide covers running `countersignd` in production with systemd, Docker, a
reverse proxy, TLS certificate hot-reload, and Prometheus metrics.

## 1. Prepare secrets and configuration

Create `/etc/countersign` and generate the required keys (never put secrets in
`config.toml`):

```sh
sudo install -d -o root -g countersign -m 0750 /etc/countersign
sudo countersign keygen /etc/countersign/session.key
sudo countersign signing-key /etc/countersign/signing.key
# Optional, if enabling Web Push:
sudo countersign vapid-key /etc/countersign/vapid.key
sudo chown root:countersign /etc/countersign/*.key
sudo chmod 0640 /etc/countersign/*.key
```

Start from [`crates/countersignd/config.example.toml`](../../crates/countersignd/config.example.toml),
save it as `/etc/countersign/config.toml`, and validate it:

```sh
countersignd --config /etc/countersign/config.toml check
```

## 2. Running with systemd

Install [`deploy/systemd/countersignd.service`](../../deploy/systemd/countersignd.service)
and the binaries (`countersignd`, `countersign`):

```sh
sudo install -m 0755 countersignd countersign /usr/local/bin/
sudo useradd --system --home /var/lib/countersign --shell /usr/sbin/nologin countersign
sudo install -m 0644 deploy/systemd/countersignd.service /etc/systemd/system/countersignd.service
sudo systemctl daemon-reload
sudo systemctl enable --now countersignd
```

### Hot-reloading configuration and TLS certificates

Sending `SIGHUP` reloads `[[person]]`, `[[workload]]`, `[[group]]`, `[roles]`,
`[[client]]`, `[[policy]]`, `[[question_policy]]`, `store.retention`, and TLS
certificates without dropping active connections:

```sh
sudo systemctl reload countersignd
```

Changes to `[server]`, `[auth]`, `[store].path`, `[engine].poll_interval`,
`[backend.*]`, `[intake]`, or `[channel.*]` require `systemctl restart countersignd`.

## 3. Reverse proxy (single hostname)

When terminating TLS in front of countersign (Caddy, nginx, etc.), keep both
listeners on `127.0.0.1` and set `behind_proxy = true` under `[intake]`. Route
**both** `/intake/` and `/mcp` to the intake listener, and everything else to
the web UI listener:

```caddyfile
countersign.example.com {
    handle /intake/* {
        reverse_proxy 127.0.0.1:8081
    }
    handle /mcp {
        reverse_proxy 127.0.0.1:8081
    }
    handle {
        reverse_proxy 127.0.0.1:8080
    }
}
```

If any `[[client]]` uses `allowed_ips`, also configure `client_ip_header` (for
example `client_ip_header = "x-forwarded-for"`) under `[intake]`.

## 4. Running with Docker

Build the server image (`countersignd` + `countersign` CLI) from the repository
root [`Dockerfile`](../../Dockerfile):

```sh
docker build -t countersign:local .
docker run -d --name countersignd \
  -v /etc/countersign:/etc/countersign:ro \
  -v countersign-state:/var/lib/countersign \
  -p 8080:8080 -p 8443:8443 \
  countersign:local
```

> **Container networking note:** In a container, `127.0.0.1` is unreachable from
> the host. Bind `[server].listen` to `0.0.0.0:8080` with `tls` (or a private
> container network IP behind a proxy). Because `[intake]` with
> `behind_proxy = true` refuses `0.0.0.0`, either terminate TLS inside the
> container (`tls = { cert_file, key_file }`) or bind `[intake].listen` to the
> container's private bridge IP.

## 5. Prometheus metrics and backups

- **Metrics**: Set `metrics_listen = "127.0.0.1:9090"` under `[server]` to
  expose Prometheus metrics at `GET /metrics` on a separate loopback listener.
- **Health check**: `GET /healthz` on the web UI listener returns `200 OK`.
- **Backups**: Back up the SQLite database online with
  `sqlite3 /var/lib/countersign/countersign.db ".backup /backups/countersign.db"`.
  Confidential question content is overwritten in place (`secure_delete = ON`)
  and WAL-checkpointed once no longer needed, but older backups retain whatever
  was present when they were taken until those backups expire.
