# countersign

Human approval for just-in-time access. countersign watches an access system
for requests that need a second pair of eyes (for example an AI agent asking for
an elevated session), tells the right people, and applies their decision — with
the assurance level you require.

> Status: early development. Nothing here is stable yet.

## Design

```
                 ┌──────────── countersign-core ─────────────┐
AccessBackend ◀─▶│ request state machine · policy · events   │◀── PolicySet
(Octelium, exec) │ outbox                                     │
                 └───────▲──────────────────────▲────────────┘
                         │                      │
             Channel (notify + decide)    Authenticator (web approvers)
        (ntfy, webhook, Discord, Slack)          (OIDC)
                         │
                       Store (SQLite, Postgres)
```

- **Backends** hold the actual access. countersign re-reads facts from the
  backend before acting and never trusts what the requester claims.
- **Channels** announce requests. Interactive channels can carry decisions back;
  every inbound action is authenticated by the platform and tied to an approver
  through an account link made with a one-time code from the web UI.
- **Assurance**: each channel declares the strongest assurance it can vouch for
  (`linked` < `web` < `fresh-auth`). Policies set the minimum for approval. If a
  channel cannot meet it, its approve button becomes a link to the web UI, where
  the approver re-authenticates. Denials are accepted from any eligible approver.
- Policies are first-match, deny by default, with quorum, TTL ceilings, pending
  timeouts, and self-approval prevention.

```toml
[[policy]]
name = "elevated-agents"
match = { backend = "oct-main", requester_group = "agents-elevated" }
approvers = ["group:approvers"]
max_ttl = "30m"
min_assurance = "fresh-auth"   # the default

[[policy]]
name = "staging-sudo"
match = { backend = "exec-sudo", target = "staging-*" }
approvers = ["approver:alice", "approver:bob"]
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
| `countersign-backend-octelium` | approves/rejects pending Octelium sessions via `octeliumctl` |
| `countersign-backend-exec` | delegates to any program speaking a small JSON protocol over stdin/stdout |
| `countersign-channel-discord` | posts requests with Approve/Deny buttons; receives presses over the Gateway (no inbound endpoint) |
| `countersign-channel-ntfy` | push notifications via an ntfy server, linking to the web UI (notify-only) |
| `countersign-channel-webhook` | signed JSON events ([Standard Webhooks](https://www.standardwebhooks.com/)) to any URL (notify-only) |
| `countersignd` | daemon: config, engine (discover, decide, grant, expire), outbox delivery, web UI and JSON API |
| `countersign` (CLI) | host-side administration: list/show requests, deny/revoke, manage account links, generate secrets (no approve) |

## Running

```sh
countersignd --config /etc/countersign/config.toml check
countersignd --config /etc/countersign/config.toml run
```

On the same host, `countersign` reads the daemon's configuration and database:

```sh
countersign requests                  # open requests (--all, --json)
countersign show <id>
countersign deny <id> --as alice      # recorded as alice, via "cli"
countersign revoke <id> --as alice
countersign links                     # chat accounts linked to approvers
countersign unlink discord 123456789012345678
countersign keygen /etc/countersign/session.key            # 256-bit hex
countersign keygen /etc/countersign/webhook-secret --format whsec
countersign host-key /etc/countersign/host.key             # on a target host; prints key_sha256
```

Approving is intentionally not possible from the CLI; it goes through the web
UI or a chat channel, where the policy's assurance level is enforced.

See [`crates/countersignd/config.example.toml`](crates/countersignd/config.example.toml).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
