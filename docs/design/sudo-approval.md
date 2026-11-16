# Design: approving `sudo` on target hosts

Status: implemented — countersign side (intake API, `host` backend, grant
modes) and the host helper (`countersign-sudo`, with PAM, sudoers and config
examples in `crates/countersign-sudo/contrib/`). Not yet tried on a real host.

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
agent   ALL=(ALL) NOSETENV: ALL
Defaults:agent timestamp_timeout=0
# sudo -n (and sudo without a terminal) only reaches PAM with this.
Defaults:agent noninteractive_auth
```

A `NOPASSWD` entry for the agent would skip PAM entirely and must not exist.
`NOSETENV` matters: a rule for `ALL` commands implies `SETENV`, which lets the
caller set any variable on the command line (`sudo LD_PRELOAD=… id`) or keep
its environment (`-E`), bypassing sudo's environment checks. An approved
command could then run anything.
Windows are tracked by countersign, not by sudo's timestamp, because sudo's
timestamp cannot be scoped to a command pattern.

### PAM

Prepended to the `auth` section of `/etc/pam.d/sudo` and `/etc/pam.d/sudo-i`:

```pam
# The agent: countersign decides, and nothing else is tried.
auth [success=ignore default=1] pam_succeed_if.so quiet user = agent
auth [success=done default=die]  pam_exec.so quiet seteuid /usr/local/libexec/countersign-sudo
# Everyone else falls through to the normal stack.
@include common-auth
```

For any user other than the agent, `pam_succeed_if` fails, `default=1` skips
the `pam_exec` line, and authentication proceeds as before. The helper is
never run for them, so countersign's availability cannot affect them.

`seteuid` runs the helper with root as its real uid too, so the calling user
cannot signal or inspect it. `pam_exec`'s `stdout` option must not be used:
without a terminal the PAM conversation fails and `pam_exec` fails
authentication even after an approval (seen with `sudo-rs` and `sudo -n`).
`pam_exec` gives the helper unread pipes and no controlling terminal, so the
helper writes its messages to the calling `sudo`'s stderr (`/proc/$PPID/fd/2`),
reopened only when it is a pipe or a terminal — never a regular file, which
the caller could point at a file only root may write.

### Helper (`countersign-sudo`)

A small static Rust binary run by `pam_exec` as root. It:

1. Checks `PAM_TYPE=auth` and `PAM_SERVICE` is `sudo` or `sudo-i`.
2. Reads the invoking `sudo` process (`$PPID`): `/proc/$PPID/exe` must be a
   known sudo binary; its real uid must be `PAM_USER`'s; `cmdline` gives the
   argv as typed; `cwd` the working directory. The process is setuid root, so
   the agent cannot alter it.
3. Reads optional hints from `/proc/$PPID/environ`: `COUNTERSIGN_REASON`
   (shown to approvers) and `COUNTERSIGN_SENSITIVE=1` (see "Sensitive
   commands"). Both are set by the caller, so they are displayed or used to
   narrow where the request is shown, never trusted for anything else.
   sudo has no way to pass extra data to PAM, and the variables live in
   `sudo`'s own environment (`COUNTERSIGN_REASON=… sudo …`), so they work
   with `NOSETENV`.
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
sudo's options that do not change what runs (`-u`, `-n`, `-H`, `--`, ...) to
report `runas` and the command separately. Anything else is sent as the raw
arguments, which only match policies that do not look at the command: unknown
options, and on purpose `-E`/`--preserve-env` (the caller's environment can
make any command do anything), `-D`/`--chdir`, `-R`/`--chroot`, `-g` and
leading `VAR=value` assignments. With `-s` or `-i` the command runs through a
shell (for `-s`, the one the caller's `SHELL` names), so it is shown as
`(shell) <command>` or `(login shell) <command>`.

Command patterns in policies are globs over the command as shown. Write them
for exact commands or arguments the command cannot abuse: `apt *` also
matches `apt -o APT::Update::Pre-Invoke::=sh …`.

### Sensitive commands

Some command lines are better kept out of chat channels (internal host or
path names, customer identifiers). The caller can ask for that with
`COUNTERSIGN_SENSITIVE=1`, and policies can ask for it too.

What it changes — display only:

- Discord, ntfy and webhooks get "Sensitive approval request from
  &lt;host&gt; (&lt;policy&gt;)" and countersign's link, nothing from the
  command line. Approving happens in the web UI only, as for commands too long
  for chat.
- The web UI shows the full request to approvers as usual.

What it does not change:

- The audit record keeps the full command, user, runas and cwd. Unlike
  confidential questions (`docs/design/questions.md`), approvals have no
  "do not keep" option: the record of what ran as root is the reason
  approvals exist, and a flag set by the requester must not be able to remove
  it.
- Approvers always see everything they approve.

Policy field:

```toml
sensitive = "honor"   # "honor" (default): follow the caller's flag
                      # "ignore": always show in chat
                      # "always": never show this policy's commands in chat
```

The flag does not protect secrets. A command line is visible to every user
on the host while it runs (`ps`, `/proc/*/cmdline`), and sudo writes it to
its own log. Secrets must not be passed as arguments at all.

### Wrapper (optional)

A thin client mode of the helper for callers that prefer flags to
environment variables:

```sh
countersign-sudo run [--reason TEXT] [--sensitive] -- apt upgrade
```

It sets `COUNTERSIGN_REASON` / `COUNTERSIGN_SENSITIVE` and executes `sudo --`
with the command, nothing else.

- It is a convenience, not the enforcement point. A plain `sudo` still goes
  through PAM and the helper and needs the same approval; it just has no
  reason attached.
- It never talks to the intake API itself. Doing so would need the host key,
  which is readable by root only so that the agent cannot create requests
  outside sudo.
- It runs as the caller, unprivileged; the same binary acts as the PAM helper
  only when started by `pam_exec` (`PAM_TYPE` set, parent is sudo).

## countersign side

### Intake listener

A second listener for machines. It always serves HTTPS, because the host key
is the only thing that authenticates a host and the network is not trusted
(see `deployment.md`): countersign either terminates TLS itself or sits
behind a reverse proxy or tunnel on a loopback or private address.

```toml
[intake]
listen = "0.0.0.0:8443"
tls = { cert_file = "/etc/countersign/tls/fullchain.pem", key_file = "/etc/countersign/tls/key.pem" }
# or: listen = "127.0.0.1:8081" with behind_proxy = true
```

An access layer in front of it (single sign-on for browsers) would block the
hosts; put it only in front of the web UI. A mesh VPN or private network is
welcome as defence in depth, but nothing relies on it.

### Host authentication

Each target host is a `[[client]]` with the `approval` scope (the default),
configured with an id and the SHA-256 of its key, so countersign never stores
the key itself (see `identity-model.md` for clients and scopes):

```toml
[[client]]
id = "web-1"
auth = { host_key_sha256 = "…" } # printed by `countersign host-key <file>`
allowed_ips = ["192.0.2.21"]     # optional extra check on the client address
# backend = "sudo"               # only with more than one host backend
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
  the `auth` line for the `[[client]]`; the key itself goes straight to a
  0600 file for the target host.
- The checksum is the base64url of the first 4 bytes of SHA-256 over the
  text before it (`cshk_` and the random part). It catches typos and
  hand-made keys; it is not a secret.
- The server checks prefix, length, alphabet and checksum before hashing,
  and rejects anything else with the same response as a wrong key. Config
  loading rejects `host_key_sha256` values that are not 64 hex digits.
- Limit: someone who deliberately builds a low-entropy key in this format and
  hashes it themselves is not stopped. The format blocks accidents (short
  keys, reused passwords, keys from other systems), not deliberate misuse by
  whoever edits the config. The authenticated host name becomes a fact of the request (it
is not taken from the body).

Decided: per-host keys. Network-level identity (for example a mesh VPN's
peer lookup) was considered and rejected: it would tie countersign to one
network product, and the key works over any network.

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

A single-use approval ends when the host first reads it as `approved`; later
reads still say `approved`, so a lost answer can be asked for again. If its
time (`max_ttl`) runs out before the host reads it, it was never used and
reads as `expired`.

Commands longer than 3000 characters (as shown) are refused, so chat
channels can always show the whole command. Control characters and
invisible or text-reordering Unicode characters (zero-width characters,
bidirectional overrides) are written out as escapes before anything is
stored or shown.

Long polls wait on an in-process notification fired when the engine changes
a request, so approvals reach the host immediately.

### Backend and engine

A new push-style backend, `host`, with `discover = false`. Its subjects are
created by the intake API, not discovered:

- `subject`: `{ backend: <backend name>, kind: "sudo", id: <uuid> }`
- `facts.requester.id`: the OS user. countersign sets the requester identity
  to `unix:<client>#<user>` and resolves it to a `[[workload]]` or
  `[[person]]` listing that identity; its countersign groups are what
  `requester_group` matches. Users that resolve to no active actor are
  refused (`unknown-user`).
- `facts.source`: the client; `facts.target`: the client id (the host name).
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

- Reason: is `COUNTERSIGN_REASON` in the caller's environment enough? (The
  optional `countersign-sudo run` wrapper only makes it easier to set.)
- Sensitive commands: should countersign also mark a request sensitive by
  itself when the command looks like it carries a secret (`password=`,
  `token`)? Not planned yet; such commands are a mistake to fix at the
  caller.
- Window scope: same policy + host + user (proposed), or narrower?
- Assurance: is a Discord tap (`linked`) enough for sudo, or should some
  commands require `fresh-auth` in the web UI?
- Other access systems (such as Octelium) remain optional backends for
  connection-level access and audit; sudo approval does not depend on them.
