# countersign

Human approval for just-in-time access. countersign watches an access system
for requests that need a second pair of eyes (for example an AI agent asking for
an elevated session), tells the right people, and applies their decision — with
the assurance level you require. Programs can also ask the right people a
structured question and get their answer back; an answer never grants access.

> Status: early development. Nothing here is stable yet.

At its core, countersign does three things: approves `sudo` on your hosts
(`countersign-sudo`), lets programs ask for approval or ask people a question
through its intake API, and applies decisions to access systems you plug in
as backends (Octelium is one of them).

You run it yourself. It needs an OpenID Connect provider (any), one HTTPS
address that people and clients can reach (directly, or through a reverse
proxy or tunnel), and somewhere to send notifications. It assumes no
particular network, identity provider or access system; see
[`docs/design/deployment.md`](docs/design/deployment.md).

## Design

```
                 ┌──────────── countersign-core ─────────────┐
AccessBackend ◀─▶│ request state machine · policy · events   │◀── PolicySet
(host/sudo, exec,│ questions · outbox                         │
 Octelium)       │                                            │
                 └───────▲──────────────────────▲────────────┘
                         │                      │
             Channel (notify + decide)    Authenticator (web approvers)
        (ntfy, webhook, Discord, Slack)          (OIDC)
                         │
                       Store (SQLite, Postgres)
```

- **Backends** hold the actual access. countersign re-reads facts from the
  backend before acting and never trusts what the requester claims.
- **Actors**: persons sign in and decide; workloads (agents, CI, hosts' users)
  request and ask. Identities such as `oidc:<issuer>#<sub>`, `github:<id>` or
  `unix:<client>#<user>` tie accounts to them; countersign names the requester
  from the authenticated source, never from the request. Roles (`member`,
  `auditor`, `admin`) say what a person may do in countersign; policies say
  which requests they may decide. Suspending an actor takes effect at once.
- **Channels** announce requests and questions. Interactive channels can carry
  decisions and simple answers back; every inbound action is authenticated by
  the platform and tied to a person through an account link made with a
  one-time code from the web UI.
- **Confidentiality**: a sensitive approval or a confidential question shows up
  in chat only as "something from X under policy Y" with a link; confidential
  question text and answers are removed from the database once no longer
  needed.
- **Assurance**: each channel declares the strongest assurance it can vouch for
  (`linked` < `web` < `fresh-auth`). Policies set the minimum for approval. If a
  channel cannot meet it, its approve button becomes a link to the web UI, where
  the approver re-authenticates. Denials are accepted from any eligible approver.
- Policies are first-match, deny by default, with quorum of distinct persons,
  TTL ceilings, pending timeouts, and exclusions (the requester, the owners of
  a requesting workload, the person who started it).

```toml
[[workload]]
id = "deploy-agent"
owners = ["alice"]
identities = ["octelium:oct-main#deploy-agent"]

[[policy]]
name = "elevated-agents"
match = { backend = "oct-main", requester_group = "agents" }
approvers = ["group:approvers"]
exclude = ["requester", "owners"]
max_ttl = "30m"
min_assurance = "fresh-auth"   # the default

[[policy]]
name = "staging-sudo"
match = { backend = "sudo", source = "staging-*" }
approvers = ["person:alice", "person:bob"]
quorum = 2
max_ttl = "2h"
min_assurance = "linked"       # chat buttons may approve directly
```

## Crates

| crate | status |
|---|---|
| `countersign-core` | types, state machine, policy, traits |
| `countersign-store-sqlite` | SQLite store with transactional outbox |
| `countersign-auth-oidc` | OpenID Connect login (code flow + PKCE) for the web UI |
| `countersign-backend-octelium` | optional: approves/rejects pending Octelium sessions via `octeliumctl` |
| `countersign-backend-exec` | delegates to any program speaking a small JSON protocol over stdin/stdout |
| `countersign-channel-discord` | posts requests with Approve/Deny buttons and simple questions with answer buttons; receives presses over the Gateway (no inbound endpoint) |
| `countersign-channel-ntfy` | push notifications via an ntfy server, linking to the web UI (notify-only) |
| `countersign-channel-webhook` | signed JSON events ([Standard Webhooks](https://www.standardwebhooks.com/)) to any URL (notify-only) |
| `countersignd` | daemon: config, engine (discover, decide, grant, expire, questions), outbox delivery, web UI, JSON API, intake API for clients |
| `countersign` (CLI) | host-side administration: list/show requests and questions, deny/revoke, suspend/reinstate, manage account links, generate secrets (no approve, no answer) |
| `countersign-sudo` | PAM helper for target hosts: asks countersign before `sudo` runs |

## Running

```sh
countersignd --config /etc/countersign/config.toml check
countersignd --config /etc/countersign/config.toml run
```

On the same host, `countersign` reads the daemon's configuration and database:

```sh
countersign requests                  # open approvals and questions (--all, --json)
countersign show <id>
countersign deny <id> --as alice      # recorded as alice, via "cli"
countersign revoke <id> --as alice
countersign suspend bob --as alice --reason "lost laptop"   # admins only
countersign reinstate bob --as alice
countersign revoke-approved-by bob --as alice
countersign links                     # chat accounts linked to persons
countersign unlink discord 123456789012345678 --as alice
countersign keygen /etc/countersign/session.key            # 256-bit hex
countersign keygen /etc/countersign/webhook-secret --format whsec
countersign host-key /etc/countersign/host.key             # on a client; prints its [[client]] auth line
```

Approving and answering are intentionally not possible from the CLI; they go
through the web UI or a chat channel, where the policy's assurance level is
enforced. The CLI never prints confidential question text or answers.

The state database holds requests, questions, chat links, suspensions and the
admin log. Back it up like any other SQLite file (for example with
`sqlite3 countersign.db ".backup …"`); confidential content is overwritten in
place (`secure_delete`) once it is no longer needed, but copies in older
backups remain until those backups expire.

Both the web UI and the intake API serve HTTPS: either countersign terminates
TLS (`tls = { cert_file, key_file }`), or a reverse proxy or tunnel does and
the listener stays on a loopback or private address. Clients authenticate with
their key alone; `allowed_ips` is an optional extra. Approvals are signed by
countersign, and `countersign-sudo` checks the signature against a pinned
public key, so nothing in between can approve a `sudo`.

See [`crates/countersignd/config.example.toml`](crates/countersignd/config.example.toml)
and [`docs/design/deployment.md`](docs/design/deployment.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
