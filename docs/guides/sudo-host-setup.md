# Target host setup and verification (`countersign-sudo`)

This guide walks through installing and verifying `countersign-sudo` on a real
Linux host (tested design targets: Ubuntu 26.04 with `sudo-rs` and Debian /
Ubuntu with classic `sudo`).

> [!CAUTION]
> Open a separate root shell (`sudo -i` or console login) and keep it open until
> every check below succeeds. A mistake in `/etc/pam.d/sudo` can lock out `sudo`.

## 1. Install the binary

Copy the release binary `countersign-sudo` onto the target host:

```sh
sudo install -o root -g root -m 0755 countersign-sudo /usr/local/libexec/countersign-sudo
```

## 2. Enroll the host

Run `enroll` as root so it creates `/etc/countersign/host.key` (`0600`), pins
Countersign's Ed25519 approval signing key, and writes `/etc/countersign/sudo.toml`:

```sh
sudo /usr/local/libexec/countersign-sudo enroll \
  --server https://countersign.example.com:2743 \
  --server-key ed25519:<public-key-from-countersignd>
```

Add the printed `[[client]]` block to `/etc/countersign/config.toml` on the
Countersign server (plus a `[[workload]]` with identity `unix:<host>#<agent>`),
then reload the daemon:

```sh
sudo systemctl reload countersignd
```

## 3. Configure `sudoers`

Install `crates/countersign-sudo/contrib/sudoers` as
`/etc/sudoers.d/countersign-agent` (`0440 root:root`), replacing `agent` with
your automated user:

```sudoers
agent ALL=(ALL:ALL) NOSETENV: ALL
Defaults:agent timestamp_timeout=0
Defaults:agent noninteractive_auth
```

Verify syntax before continuing:

```sh
sudo visudo -cf /etc/sudoers.d/countersign-agent
```

Make sure no `NOPASSWD` rule applies to `agent` anywhere in `/etc/sudoers` or
`/etc/sudoers.d/`.

## 4. Configure PAM

Prepend these two lines to the top of the `auth` section in **both**
`/etc/pam.d/sudo` and `/etc/pam.d/sudo-i` (before `@include common-auth`):

```pam
auth [success=ignore default=1] pam_succeed_if.so quiet user = agent
auth [success=done default=die]  pam_exec.so quiet seteuid /usr/local/libexec/countersign-sudo
```

Do **not** add `stdout` to `pam_exec.so` (it breaks non-interactive `sudo -n`
and `sudo-rs` without a TTY).

## 5. Verification checklist

Run these checks while keeping your root shell open:

1. **Interactive `sudo` (approved):**
   - As `agent`: `sudo id`
   - Confirm the approval URL appears on stderr and in Slack / Discord / Web Push.
   - Approve it; confirm `uid=0(root)` is printed.
2. **Interactive `sudo` (denied):**
   - As `agent`: `sudo id`, then deny it.
   - Confirm `sudo` fails with authentication failure and does not run `id`.
3. **Reason wrapper (`--reason`):**
   - As `agent`: `/usr/local/libexec/countersign-sudo run --reason "verify host" -- id`
   - Confirm the reason shows up in the approval card as unverified text.
4. **Non-interactive / headless (`sudo -n` and SSH without TTY):**
   - `ssh -T agent@<host> 'sudo -n id'`
   - Confirm it waits for approval and succeeds without requiring a TTY.
5. **Window policy (if configured, e.g. `apt *`):**
   - Run `sudo apt update`, approve once, then run `sudo apt update` again within the window.
   - Confirm the second invocation runs immediately and both commands appear under "Used for" in the web UI.
6. **Cancellation (`Ctrl-C`):**
   - Run `sudo id` and press `Ctrl-C` while pending.
   - Confirm the request transitions to `withdrawn`.
7. **Fail-closed & human isolation:**
   - Temporarily stop `countersignd`.
   - Confirm `agent`'s `sudo id` fails closed.
   - Confirm a normal human user's `sudo id` still works normally via standard PAM auth.
