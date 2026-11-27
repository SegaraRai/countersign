# countersign

**Human-in-the-loop approval and structured questions for AI agents, CI/CD, and `sudo`.**

When an AI agent runs `sudo` on a server, a CI pipeline is about to deploy to
production, or an automated tool needs a human decision, countersign pauses it,
notifies the right people (Slack, Discord, browser Web Push, ntfy, or webhook),
enforces your approval policy, and returns a cryptographically signed decision.

> [!NOTE]
> **Early development:** Configuration and APIs may change before `1.0`.

## What you can do with it

- **Approve `sudo` on Linux hosts (`countersign-sudo`)** — Require human
  approval before an AI agent or service account can run `sudo`, with per-command
  or time-window grants. Approvals are Ed25519-signed so nothing on the network
  can forge root access.
- **Gate CI pipelines (`countersign-ask`)** — Ask operators a structured Yes/No,
  choice, or form question from GitHub Actions (using passwordless OIDC JWTs) or
  any script, and get validated JSON back on `stdout`.
- **Let AI agents ask humans over MCP (`POST /mcp`)** — Point any MCP client at
  countersign's built-in Streamable HTTP endpoint so agents can ask structured
  questions without extra glue code. Answers never grant access.
- **Plug in external access systems** — Approve pending Octelium sessions
  (`countersign-backend-octelium`) or integrate any custom system via a simple
  stdin/stdout JSON helper (`countersign-backend-exec`).

## How it works

```text
  Requester / Asker                 countersignd (self-hosted)                Approvers / Responders
  ─────────────────                 ──────────────────────────                ──────────────────────
  • Linux host (countersign-sudo)   • Evaluates policies & exclusions         • Web UI (OIDC + fresh-auth)
  • CI job (countersign-ask)   ───▶ • Signs approvals (Ed25519)          ───▶ • Slack / Discord buttons
  • AI agent (MCP / HTTP)           • Enforces quorum & assurance levels      • Browser Web Push (PWA)
  • Octelium / exec backend         • Stores audit log in SQLite              • ntfy / Standard Webhooks
```

### Core security guarantees

- **Fail-closed & re-verified:** If countersign is unreachable or nobody decides
  in time, access is denied. Backends re-verify facts before granting.
- **No self-approval:** Policies separate **persons** (who sign in and decide)
  from **workloads** (agents, CI, host users) and can exclude the requester, the
  workload's owners, and the person who initiated the run.
- **Assurance levels (`linked` < `web` < `fresh-auth`):** High-risk policies
  require `fresh-auth` (a recent OIDC re-authentication in the web UI). If a
  chat channel cannot meet the requirement, its Approve button automatically
  turns into a link to the web UI. Denials work from any eligible approver.
- **Confidentiality:** Sensitive approvals and confidential questions never leak
  their details into chat or logs; confidential question text and answers are
  overwritten in SQLite (`secure_delete = ON`) as soon as they are no longer needed.
- **Self-hosted & infrastructure-agnostic:** All you need is any OpenID Connect
  provider, one HTTPS address (direct TLS or behind a reverse proxy/tunnel), and
  a notification channel.

## Quick start

### 1. Generate server keys

Secrets never live in `config.toml`; generate them into `/etc/countersign` (root
/ `countersign` readable only):

```sh
countersign keygen /etc/countersign/session.key       # web session cookie encryption
countersign signing-key /etc/countersign/signing.key  # Ed25519 approval signing key (cssk_…)
# Optional: if using browser Web Push notifications
countersign vapid-key /etc/countersign/vapid.key      # VAPID P-256 key (csvk_…)
```

### 2. Create `/etc/countersign/config.toml`

Start from [`crates/countersignd/config.example.toml`](crates/countersignd/config.example.toml).
A minimal setup with OIDC sign-in, two approvers, `sudo` approval, and a log
channel looks like this:

```toml
[server]
public_url = "https://countersign.example.com"
listen = "127.0.0.1:2780"
session_key_file = "/etc/countersign/session.key"

[auth.oidc]
issuer = "https://id.example.com"
client_id = "your-oidc-client-id"
client_secret_file = "/etc/countersign/oidc-client-secret"

[store]
path = "/var/lib/countersign/countersign.db"

[intake]
listen = "0.0.0.0:2743"
tls = { cert_file = "/etc/countersign/tls/fullchain.pem", key_file = "/etc/countersign/tls/key.pem" }
signing_key_file = "/etc/countersign/signing.key"

[backend.sudo]
type = "host"

[channel.log]
type = "log"

[[person]]
id = "alice"
display_name = "Alice"
identities = ["oidc:https://id.example.com#<alice-sub>"]

[[person]]
id = "bob"
display_name = "Bob"
identities = ["oidc:https://id.example.com#<bob-sub>"]

[[workload]]
id = "deploy-agent"
owners = ["alice"]
identities = ["unix:web-1#agent"]

[[group]]
name = "approvers"
members = ["alice", "bob"]

[roles]
member = ["group:approvers"]
admin = ["person:alice"]

[[policy]]
name = "staging-sudo"
match = { backend = "sudo", source = "web-*" }
approvers = ["group:approvers"]
exclude = ["requester", "owners"]
grant = "once"
max_ttl = "1m"
pending_timeout = "5m"
min_assurance = "fresh-auth"
```

### 3. Validate and run

```sh
countersignd --config /etc/countersign/config.toml check
countersignd --config /etc/countersign/config.toml run
```

For production systemd, Docker, reverse proxy (`/intake/` + `/mcp`), and
Prometheus `/metrics` setup, see [`docs/guides/deployment.md`](docs/guides/deployment.md).

## Common workflows

### Approve `sudo` on a Linux host

Enroll the target host (pins countersign's signing key, generates a host key,
and prints the `[[client]]` block to paste into `config.toml`):

```sh
sudo countersign-sudo enroll \
  --server https://countersign.example.com:2743 \
  --server-key ed25519:<public-key-from-countersignd>
```

Then configure PAM and `sudoers` following
[`docs/guides/sudo-host-setup.md`](docs/guides/sudo-host-setup.md). Callers can
attach a reason or mark a command sensitive:

```sh
countersign-sudo run --reason "restart nginx after cert renewal" -- systemctl reload nginx
```

### Gate a CI pipeline with `countersign-ask`

In GitHub Actions (`id-token: write`), authenticate without static secrets:

```sh
countersign-ask \
  --server https://countersign.example.com:2743 \
  --github-oidc \
  --message "Deploy v1.4.0 to production?" \
  --yes-no
```

See [`docs/guides/ci-questions.md`](docs/guides/ci-questions.md) for exit codes
and `[[client]]` OIDC configuration.

### Connect an AI agent over MCP

Add countersign's `/mcp` endpoint to your MCP client with a `question`-scoped
client key:

```json
{
  "type": "http",
  "url": "https://countersign.example.com:2743/mcp",
  "headers": { "Authorization": "Bearer ${COUNTERSIGN_KEY}" }
}
```

The agent gets `ask_question`, `get_answer`, and `withdraw_question`.

## Day-2 operations (`countersign` CLI)

On the daemon host, `countersign` reads the same config and SQLite database.
Approving and answering are intentionally disallowed from the CLI so policy
assurance levels are always enforced.

```sh
# Inspect
countersign requests                                         # open approvals & questions (--all, --json)
countersign show <id>                                        # --verbose for audit details, --json for raw
countersign links                                            # linked chat accounts

# Intervene & emergency response
countersign deny <id> --as alice
countersign revoke <id> --as alice
countersign suspend bob --as alice --reason "lost laptop"    # admins only; ends sessions at once
countersign reinstate bob --as alice
countersign revoke-approved-by bob --as alice
countersign unlink discord 123456789012345678 --as alice

# Key generation (no config file needed)
countersign keygen /etc/countersign/session.key
countersign keygen /etc/countersign/webhook-secret --format whsec
countersign signing-key /etc/countersign/signing.key
countersign vapid-key /etc/countersign/vapid.key
countersign host-key /etc/countersign/host.key
```

- **Hot reload (`SIGHUP`):** Reloads `[[person]]`, `[[workload]]`, `[[group]]`,
  `[roles]`, `[[client]]`, `[[policy]]`, `[[question_policy]]`, `store.retention`,
  and TLS certificates without restarting (`systemctl reload countersignd`).
- **Backups:** Back up SQLite online with
  `sqlite3 /var/lib/countersign/countersign.db ".backup /backups/countersign.db"`.

## Building from source & local development

The web UI is a SvelteKit app in `web/` (styled with Stillwind), embedded into
`countersignd` at compile time via [fetchlet](https://fetchlet.roundtrip.dev/).
Building requires **Rust 1.100+**, **Node.js**, and **pnpm**.

```sh
pnpm install
vp run build            # builds web/build (embedded into countersignd)
cargo build --release
```

Without `web/build`, `countersignd` still compiles (with a warning): sign-in,
the JSON API, and the intake API work, while web pages return `503`.

- **UI development with hot reload:** `vp run dev` starts the demo daemon and
  serves the UI at <http://localhost:5173> with a mock IdP and sample data.
- **Frontend checks:** `vp run check` runs SvelteKit sync, type checks, and Stillwind checks.
- **Preview embedded UI:** `vp run build && cargo run -p countersignd --example web_demo` (<http://localhost:2770>).

## Crates

| Crate                          | Purpose                                                                                                            |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `countersign-core`             | Domain core: identity, approvals, questions, form schema, policies, presentation, and traits (`wasm32`-compatible) |
| `countersign-store-sqlite`     | SQLite store with transactional outbox and `secure_delete`                                                         |
| `countersign-auth-oidc`        | OpenID Connect sign-in (authorization code + PKCE)                                                                 |
| `countersign-backend-octelium` | Optional Octelium pending-session backend (`octeliumctl`)                                                          |
| `countersign-backend-exec`     | Generic stdin/stdout JSON helper backend                                                                           |
| `countersign-channel-slack`    | Slack Block Kit buttons & `/countersign-link` over Socket Mode                                                     |
| `countersign-channel-discord`  | Discord embeds, buttons & `/countersign-link` over the Gateway                                                     |
| `countersign-channel-webpush`  | Browser Web Push (RFC 8291 + VAPID) for eligible approvers / PWAs                                                  |
| `countersign-channel-ntfy`     | Push notifications via ntfy (notify-only, links to web UI)                                                         |
| `countersign-channel-webhook`  | Signed JSON events ([Standard Webhooks](https://www.standardwebhooks.com/))                                        |
| `countersignd`                 | Main daemon: engine, outbox dispatcher, web UI, JSON API, intake & MCP API, Prometheus metrics                     |
| `countersign`                  | Host-side admin & keygen CLI                                                                                       |
| `countersign-sudo`             | Linux PAM helper (`pam_exec`) and `run` / `enroll` CLI for `sudo` approval                                         |
| `countersign-ask`              | Standalone CLI for CI gates, scripts, and agents to ask structured questions                                       |

## Documentation

- **Operator guides & examples**
  - [`crates/countersignd/config.example.toml`](crates/countersignd/config.example.toml) — complete, annotated server configuration
  - [`docs/guides/deployment.md`](docs/guides/deployment.md) — systemd, Docker, reverse proxy (`/intake/` + `/mcp`), SIGHUP reload, metrics, backups
  - [`docs/guides/sudo-host-setup.md`](docs/guides/sudo-host-setup.md) — installing and verifying `countersign-sudo` on Linux hosts (with [`contrib/`](crates/countersign-sudo/contrib/))
  - [`docs/guides/ci-questions.md`](docs/guides/ci-questions.md) — `countersign-ask` and GitHub Actions OIDC setup
  - [`deploy/systemd/countersignd.service`](deploy/systemd/countersignd.service) & [`Dockerfile`](Dockerfile)
- **Design documents**
  - [`docs/design/deployment.md`](docs/design/deployment.md) — platform boundaries, TLS modes, and connectors
  - [`docs/design/identity-model.md`](docs/design/identity-model.md) — persons, workloads, identities, groups, roles, and exclusions
  - [`docs/design/questions.md`](docs/design/questions.md) — structured questions, MCP server, and confidentiality
  - [`docs/design/presentation.md`](docs/design/presentation.md) — unified presentation model across all surfaces
  - [`docs/design/sudo-approval.md`](docs/design/sudo-approval.md) — `sudo` PAM flow, signed approvals, and windows

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
