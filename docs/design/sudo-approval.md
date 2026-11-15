# Design: approving `sudo` on target hosts

Status: countersign side implemented (intake API, `host` backend, grant
modes); the host helper and PAM setup are not built yet.

## Goal

An automated account (the *agent user*) logs in to target hosts without
approval, as today. When it runs `sudo`, a human approves that command (or a
short window of similar commands) through countersign before it runs.

- Other accounts' `sudo` is unaffected, including when countersign is down.
- When countersign is unreachable, the agent's `sudo` fails (fail closed).
- Policy decides, per command pattern, whether an approval covers one
  invocation or a time window (e.g. package management for 15 minutes).
- The existing Octelium pending-session backend stays for cases where the
  connection itself needs approval.

Non-goals: restricting what an approved command does (an approved
`apt install` is root on that host), recording the session's output.

## Flow

```text
target host                                        countersign
───────────                                        ───────────
agent$ sudo apt upgrade
  sudo ─ PAM auth (sudo) ─ pam_exec ─▶ helper
                                        │ POST /intake/v1/requests  (host key)
                                        │──────────────────────────────▶ policy → open request
                                        │                               ──▶ Discord / ntfy / web
                                        │ GET  …/{id}?wait=50s (repeat)
                                        │◀────────────────────────────── approved | denied | expired
                                  exit 0 / 1
  sudo runs the command, or fails with "authentication failure"
```

## Target side

### Which sudo

Ubuntu 26.04 ships `sudo-rs` as `sudo` (`/usr/lib/cargo/bin/sudo`). It has
no plugin API, so sudo's approval plugins are not an option; PAM works with
both `sudo` and `sudo-rs`. Both read `/etc/pam.d/sudo` (and `sudo-i` for
`sudo -i`).

### sudoers

```sudoers
# The agent must authenticate for every sudo, so every sudo reaches PAM.
agent   ALL=(ALL) ALL
Defaults:agent timestamp_timeout=0
```

A `NOPASSWD` entry for the agent would skip PAM entirely and must not exist.
Windows are tracked by countersign, not by sudo's timestamp, because sudo's
timestamp cannot be scoped to a command pattern.

### PAM

Prepended to the `auth` section of `/etc/pam.d/sudo` and `/etc/pam.d/sudo-i`:

```pam
# The agent: countersign decides, and nothing else is tried.
auth [success=ignore default=1] pam_succeed_if.so quiet user = agent
auth [success=done default=die]  pam_exec.so quiet /usr/local/libexec/countersign-sudo
# Everyone else falls through to the normal stack.
@include common-auth
```

For any user other than the agent, `pam_succeed_if` fails, `default=1` skips
the `pam_exec` line, and authentication proceeds as before. The helper is
never run for them, so countersign's availability cannot affect them.

### Helper (`countersign-sudo`)

A small static Rust binary run by `pam_exec` as root. It:

1. Checks `PAM_TYPE=auth` and `PAM_SERVICE` is `sudo` or `sudo-i`.
2. Reads the invoking `sudo` process (`$PPID`): `/proc/$PPID/exe` must be a
   known sudo binary; `cmdline` gives the argv as typed; `cwd` the working
   directory. The process is setuid root, so the agent cannot alter it.
3. Reads an optional reason from `COUNTERSIGN_REASON` in
   `/proc/$PPID/environ`. Displayed, never trusted.
4. Sends the request with the host key from
   `/etc/countersign/host.key` (root-only 0600; the agent cannot read it).
5. Long-polls until a final answer or its deadline (default 5 minutes, below
   the policy's pending timeout). On deadline, SIGTERM or SIGINT (e.g. Ctrl-C)
   it withdraws the request.
6. Exits 0 only for "approved". Any error exits non-zero (fail closed).
   It writes one line to stderr for the user (e.g. the approval URL while
   waiting, the reason for a refusal).

Configuration: `/etc/countersign/sudo.toml` (server URL, key file, timeout).

The argv is shown as typed, e.g. `sudo -u postgres psql`. The helper parses
sudo's common options (`-u`, `-g`, `-i`, `-s`, `-E`, `--`) to report
`runas` and the command separately; anything it does not understand is sent
as raw argv and only matches policies that do not look at the command.

## countersign side

### Intake listener

A second listener for machines, bound to the tailnet address only (never
behind Cloudflare Access, never public):

```toml
[intake]
listen = "100.64.0.10:8443"
```

The tailnet already encrypts and authenticates traffic between nodes, so
plain HTTP is acceptable on this listener; TLS can be added later.

### Host authentication

Each target host is configured with a name and the SHA-256 of its key, so
countersign never stores the key itself:

```toml
[[host]]
name = "web-1"
key_sha256 = "…"              # printed by `countersign keygen --format host <file>`
allowed_ips = ["100.64.0.21"] # optional extra check on the peer address
```

The key is sent as `Authorization: Bearer <key>` and compared by hash in
constant time.

A single SHA-256 is only safe for high-entropy keys, and a hash says nothing
about the key behind it. countersign therefore accepts only keys in the
format its own generator produces:

```text
cshk_<43 chars: base64url of 32 random bytes><6 chars: base64url checksum>
```

- `countersign host-key` generates the key (from the OS CSPRNG) and prints
  the `key_sha256` line for the config; the key itself goes straight to a
  0600 file for the target host.
- The checksum is the first 4 bytes of SHA-256 over the prefix and random
  part. It catches typos and hand-made keys; it is not a secret.
- The server checks prefix, length, alphabet and checksum before hashing,
  and rejects anything else with the same response as a wrong key. Config
  loading rejects `key_sha256` values that are not 64 hex digits.
- Limit: someone who deliberately builds a low-entropy key in this format and
  hashes it themselves is not stopped. The format blocks accidents (short
  keys, reused passwords, keys from other systems), not deliberate misuse by
  whoever edits the config. The authenticated host name becomes a fact of the request (it
is not taken from the body).

Decided: per-host keys. Tailscale identity (LocalAPI `whois`) was considered
and rejected for now: it would give the daemon access to `tailscaled`'s
socket and tie countersign to Tailscale.

### API

```text
POST   /intake/v1/requests
       { "user": "agent", "runas": "root", "argv": ["apt","upgrade"],
         "cwd": "/home/agent", "reason": "…" }
  201  { "id": "…", "state": "pending", "url": "https://…/requests/…" }
  200  { "id": <window request>, "state": "approved", "until": "…", "url": … }  (open window)
  403  { "error": "no-policy" | "unknown-user", "message": "…" }
  429  { "error": "too-many-pending", … }

GET    /intake/v1/requests/{id}?wait=50          (seconds, at most 60)
  200  { "id", "url", "state": "pending" | "approved" | "denied" | "expired"
                                | "withdrawn" | "revoked" | "ended", "until"? }

DELETE /intake/v1/requests/{id}          withdraw: 204, or 409 if no longer pending
```

A host can only read or withdraw its own requests. Each host has a cap on
pending requests (e.g. 10) to bound spam from a misbehaving agent.

Long polls wait on an in-process notification fired when the engine changes
a request, so approvals reach the host immediately.

### Backend and engine

A new push-style backend, `host`, with `discover = false`. Its subjects are
created by the intake API, not discovered:

- `subject`: `{ backend: <backend name>, kind: "sudo", id: <uuid> }`
- `facts.requester.id`: the OS user; groups come from the backend's `users`
  map (`users = { agent = ["agents"] }`). Users not listed are refused.
- `facts.target`: the host name.
- `facts.attributes`: `host`, `user`, `runas`, `command` (argv joined with
  spaces), `cwd`.
- `grant` / `deny` / `revoke` have nothing external to do; the result is the
  request state itself, which the host reads through the API.

`Engine` gains `submit(PendingSubject)`: evaluate policies, then either answer
from an open window or open a request as `sync_backend` does today.

### Once vs. window

New policy field:

```toml
[[policy]]
name = "sudo-packages"
match = { backend = "host", attributes = { command = "apt *" } }
grant = "window"          # "once" (default) | "window"
max_ttl = "15m"
approvers = ["group:approvers"]
min_assurance = "linked"
pending_timeout = "5m"

[[policy]]
name = "sudo-other"
match = { backend = "host" }
grant = "once"
max_ttl = "1m"            # time for the helper to collect the answer
approvers = ["group:approvers"]
min_assurance = "linked"
pending_timeout = "5m"
```

- `once`: approval makes the request `active`; it ends when the helper reads
  the result (or after `max_ttl`). The approval applies only to the waiting
  invocation.
- `window`: while the request is `active`, a new submission from the same
  host, same user, matching the same policy, is approved immediately. Each
  such use is appended to the window request (time, argv, cwd) and shown in
  the web UI and CLI, so the audit trail lists every command run under it.
  Revoking the request ends the window early.

### Security notes

- Approving a command approves root on that host for as long as it runs;
  for many commands (`apt`, editors, shells) that is equivalent to full root.
  Command patterns are a convenience for approvers, not a sandbox.
- Command globs match the argv joined with spaces, so `apt *` also matches
  `apt -o APT::Update::Pre-Invoke::=sh …`. Approvers see the full argv.
- The request content is as trustworthy as root on the target host. A
  compromised host can request anything, but only for itself.
- Self-approval checks still apply: approver identities must not overlap the
  requester's.

## Rollout

1. countersign: intake listener, host auth, `host` backend, `Engine::submit`,
   `grant = once|window`, window uses in the store/UI/CLI.
2. Helper crate and packaging (static binary, config file, PAM snippet).
3. Test host: install helper, apply sudoers and PAM for a test user. Check
   `sudo`, `sudo -i`, `sudo -n` (non-interactive) and `sudo` over SSH
   without a TTY.
4. Target hosts: apply to the agent user. Keep a root shell open while
   changing PAM.

## Open questions

- Reason: is `COUNTERSIGN_REASON` in the caller's environment enough?
- Window scope: same policy + host + user (proposed), or narrower?
- Assurance: is a Discord tap (`linked`) enough for sudo, or should some
  commands require `fresh-auth` in the web UI?
- Octelium's role: keep it for connection-level access and audit, or simplify
  to Tailscale + SSH only.
