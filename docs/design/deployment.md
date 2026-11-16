# Deployment and platform boundaries

Status: the requirements, TLS modes and the platform-neutral core are
implemented. Outbound connectors for backends and the further channel kinds
below are design only.

countersign is software you run yourself, not a hosted service. It assumes no
particular network, identity provider or access system. This document says
what it needs, how it is exposed, and which boundaries keep it that way.

## What countersign needs

1. **An OpenID Connect provider** for people signing in to the web UI. Any
   provider with the authorization code flow and PKCE will do. Identities are
   written `oidc:<issuer>#<sub>`, so the provider is never assumed.
2. **One HTTPS address that people and clients can reach.** It can be served
   directly or through a reverse proxy or tunnel. Only one address is needed:
   the web UI and the intake API may share a proxy, or each listen on its own
   port.
3. **Somewhere to send notifications**: a chat channel, an ntfy topic or a
   webhook receiver.

Nothing else is required. Access systems (backends) are optional: without
one, countersign still handles sudo approval for hosts running
`countersign-sudo`, and questions from programs, both over the intake API.

### The core and the rest

These are the core:

- **sudo approval**: the `host` backend plus `countersign-sudo` on target
  hosts (`sudo-approval.md`);
- **the intake API**: how clients (hosts, agents, CI) reach countersign;
- **questions**: structured questions from programs, answered by people
  (`questions.md`).

Other access systems plug in as backends. Octelium (`countersign-backend-
octelium`) is one of them; `countersign-backend-exec` covers any system a
small program can drive. None of them is assumed by the core, the
configuration or the identity model.

## Exposing countersign

Each listener (`[server]` for the web UI, `[intake]` for clients) serves
HTTPS in one of two ways:

- **countersign terminates TLS**: `tls = { cert_file, key_file }` (PEM;
  PKCS#8, PKCS#1 or SEC1 keys). The listener may then use any address,
  including a public one. Certificates are read at startup; restart the
  daemon after renewing them.
- **Something in front terminates TLS**: a reverse proxy (Caddy, nginx), a
  tunnel, or a mesh VPN's HTTPS feature. The listener serves plain HTTP and
  must sit on a loopback or private address. For `[intake]` this is stated
  explicitly with `behind_proxy = true`, and config validation refuses plain
  HTTP on a public or unspecified address.

`server.public_url` must be `https://` (`http://` is accepted only for
`localhost` while trying things out). Session cookies are marked `Secure`
whenever it is HTTPS.

### Client authentication does not depend on the network

Clients authenticate with their key alone (`cshk_…`, sent as a bearer token
and compared by hash). The network is not trusted for anything:

- the key is only ever sent over TLS (`countersign-sudo` refuses an
  `http://` server other than this machine, and follows no redirects);
- `allowed_ips` on a `[[client]]` is an optional extra check, never a
  substitute for the key. Behind a proxy, countersign only knows the
  client's address if the proxy passes it: set `intake.client_ip_header`
  (e.g. `x-forwarded-for`; the last entry counts, because earlier ones come
  from the client). A client with `allowed_ips` behind a proxy without that
  header is a config error.

`countersign-sudo` trusts the system's usual roots plus, with `ca_file`, the
PEM certificates given there (a private CA or a self-signed certificate).

TLS is not what makes an approval trustworthy, though. countersign signs
every approval with its own key over the host, the exact command and a
fresh nonce, and the helper accepts only signatures from the keys it pinned
(`server_keys`). A proxy, tunnel or anyone else holding the TLS session can
read requests and block them, but cannot approve one. See "Signed
approvals" in `sudo-approval.md`.

### Example setups

These are examples, not requirements:

- **Public with its own certificate**: `[intake] listen = "0.0.0.0:8443"`
  with `tls`, the web UI behind a reverse proxy on 443.
- **Reverse proxy on the same host**: both listeners on `127.0.0.1`, the
  proxy terminates TLS for one hostname and routes `/intake/` to the intake
  listener (`behind_proxy = true`).
- **Mesh VPN** (Tailscale, WireGuard, …): the listeners on the VPN address
  with `tls` (e.g. a certificate the VPN issues), so hosts reach the intake
  API without any public port. The VPN is defence in depth; the key is still
  what authenticates the host.
- **Tunnel** (e.g. Cloudflare Tunnel): the web UI on loopback, published
  through the tunnel. An access layer in front of the web UI is fine; in
  front of the intake API it must let clients' bearer tokens through.

## Platform-neutral core

`countersign-core` holds the state machine, policies, the identity model,
questions and the traits every component implements, including `Store`. It
depends on no async runtime, database, filesystem or network library, so the
rules could run elsewhere, for example in a WebAssembly host such as
Cloudflare Workers with a store built on its database. The check:

```sh
cargo check -p countersign-core --target wasm32-unknown-unknown
```

On that target, uuid and jiff take randomness and the clock from JavaScript.

Two things a port would still have to deal with:

- The traits are `async_trait` with `Send` futures. Single-threaded hosts
  such as Workers produce futures that are not `Send`; a port would need the
  traits generated without that bound (`#[async_trait(?Send)]`, or native
  async traits) behind a feature.
- The daemon (`countersignd`: polling loops, listeners, outbox delivery) is
  tokio-based and stays so; another host would supply its own equivalents
  (cron triggers, request handlers, queues).

The SQLite store (`countersign-store-sqlite`) is one implementation of
`Store`; nothing outside it knows about SQLite.

## Backends and future connectors

The `AccessBackend` trait is the whole boundary between countersign and an
access system: discover pending subjects, re-read facts, grant, deny, revoke.
Today every backend runs inside the daemon and reaches its system directly
(`octeliumctl`, a local program, or hosts that call the intake API).

That boundary is kept narrow on purpose, so that later a backend can be a
**connector**: an agent running next to an inner system (an Octelium cluster,
a program that needs local credentials), connecting *out* to countersign and
carrying these same calls over that connection. countersign then needs no
route into the inner network. Requirements for that to stay possible:

- backends exchange only data (`PendingSubject`, `SubjectFacts`,
  `GrantHandle`), never handles to local resources;
- every call is idempotent or safe to retry, and the engine re-reads facts
  before acting, so a reconnecting connector cannot replay a decision;
- requester identities are namespaced by backend (`<scheme>:<backend>#<id>`),
  so a connector can only vouch for its own namespace.

The `host` backend already works this way in miniature: hosts connect out to
the intake API and countersign never connects to them.

## Channels

The `Channel` trait has `notify`, `update` and an optional long-running
`run` for receiving actions. Channels differ along two axes, and adapters
are expected for each combination:

| | how people act | how actions arrive |
|---|---|---|
| link-only (ntfy today, email) | open the web UI | — |
| buttons (Discord, Slack) | press a button in chat | persistent connection, or HTTP callbacks |
| webhook (Standard Webhooks) | a program decides what to do | — |

How actions arrive:

- **Persistent connection** (Discord Gateway, Slack Socket Mode): the channel
  connects out from `run`. No inbound endpoint is needed; this is what the
  Discord channel does today.
- **HTTP callbacks** (Discord HTTP Interactions, Slack's request URLs): the
  platform calls countersign. This needs an inbound route on the public
  address, with the platform's signature checked before anything is parsed.
  Planned shape: a channel can declare an inbound path and a handler that
  takes the raw request (method, headers, body) and returns a response,
  without depending on the web framework, so the daemon mounts it next to
  the web UI. Discord will offer this mode alongside the Gateway.

Whatever the transport, inbound actions go through the same `ActionSink`
(account links, assurance ceilings, policy checks), so a new channel cannot
widen what a chat press may do. Richer link-only channels (ntfy with action
buttons that open the web UI) need no inbound path at all.
