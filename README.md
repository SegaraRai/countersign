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
  every inbound action is signature-verified and tied to a linked approver.
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
| `countersign-backend-exec` | planned |
| `countersign-channel-ntfy`, `-webhook`, `-discord` | planned |
| `countersignd` | daemon: config, engine (discover, decide, grant, expire), outbox delivery, web UI and JSON API |
| `countersign` (CLI) | planned |

## Running

```sh
countersignd --config /etc/countersign/config.toml check
countersignd --config /etc/countersign/config.toml run
```

See [`crates/countersignd/config.example.toml`](crates/countersignd/config.example.toml).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
