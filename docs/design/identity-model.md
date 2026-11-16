# Design: people, workloads, identities, groups, roles and relationships

Status: implemented, except CI OIDC client authentication
(`ClientAuth::Oidc`; clients authenticate with host keys only), notifying all
channels on suspension and bulk revoke (both are recorded in the admin log
and shown on the admin page), and break-glass policies. Exclusions are a
policy's `exclude` list (`requester`, `owners`, `initiator`; default
`["requester"]`), and `require_initiator` refuses requests whose source names
no initiator.

This replaced the earlier `[[approver]]` entries (id, groups, identity
strings) and requesters described only by the backend. countersign is
unreleased: `[[approver]]`, `approver:<id>` selectors and the old `Requester`
shape went away without compatibility shims, and state databases from before
need to be recreated.

## Goals

- One record per **person**, however many accounts they use.
- Requests say **who sent them** (an authenticated source), **who they are
  for** (the requester), and **who started them** (a person, if any), and
  countersign knows how far each of those is vouched for.
- "Do not approve your own agent's request" and "do not approve the deploy
  you pushed" can be enforced.
- Group membership can come from the **IdP**, without the IdP being able to
  create approvers by accident.
- **Roles** (what someone may do in countersign) are separate from
  **eligibility** (which requests they may decide).
- Removing or suspending someone takes effect immediately, including on
  requests in progress. Audit records stay readable after people leave.

Non-goals: managing people in the IdP, SCIM, delegation of approval rights.

## Who is involved

### When a request is made

```text
   Source (authenticated)          vouches for          Requester            started by
 ┌─────────────────────────┐                      ┌──────────────────┐   ┌──────────────┐
 │ Client: host key,       │ ───────────────────▶ │ Actor (resolved) │   │ Initiator    │
 │   CI OIDC token, ...    │                      │  or unresolved   │   │ (a person,   │
 │ Backend: discovered by  │                      │  backend account │   │  optional)   │
 │   countersign polling   │                      └──────────────────┘   └──────────────┘
 └─────────────────────────┘
```

| Role in the request | What it is | Example: sudo | Example: CI deploy | Example: Octelium |
|---|---|---|---|---|
| **Source** | the authenticated party that delivered the request; its credential is checked | host `web-1` (host key) | GitHub Actions (OIDC token) | the Octelium backend (countersign polls it) |
| **Requester** | whose action needs approval; vouched for by the source | OS user `agent` on web-1 | workload "repo X, workflow deploy, environment prod" | Octelium user `agent-ops` |
| **Initiator** | the person who caused it, if known | — (or the agent's owner, via relations) | GitHub user who pushed / ran the workflow | — |
| **Target and action** | what would happen | `apt upgrade` as root on web-1 | deploy commit abc to prod | connect to service ssh-web-1 |

So the answer to "is there only a Client?" is no: the **source** (a client or
a backend) authenticates the message, and the **requester** is who the
request is about. They are different things that happen to coincide when a
person uses the CLI as themselves.

#### Sources

```rust
enum Source {
    Client(ClientId),       // pushed to the intake API
    Backend(BackendName),   // discovered by countersign (Octelium pending sessions, exec)
}

struct Client {
    id: ClientId,           // "web-1", "github-actions"
    auth: ClientAuth,       // HostKey { key_sha256 } | Oidc { issuer, audience, claim rules }
    scopes: BTreeSet<Scope>,// approval, question
    vouches: VouchRule,     // which requester identities it may claim
}
```

A source can only vouch for requesters inside its namespace, set in config:

- A host key for `web-1` can only claim `unix:web-1#<user>`.
- A CI OIDC client derives the requester **from token claims** (repository,
  workflow, environment, ref); the request body cannot name it.
- A backend reports identities in its own namespace
  (`octelium:<cluster>#<user>`).

A source can never claim a person's `SignIn` or `Chat` identity, so it cannot
make a request look like it came from (or from someone other than) a person
with approval rights.

#### Requester

The requester is resolved to an actor when one of its identities matches;
otherwise it stays **unresolved** (just the backend account), which is allowed
but limits the relational checks.

- sudo: `unix:web-1#agent` → workload `agent-ops`.
- CI: `github:repo:<owner>/<repo>:environment:prod` → workload `deploy-prod`.
- A person using the CLI with their own credentials: that person.

#### Initiator

The person who caused the request, when the source can tell: the GitHub
`actor` claim of a workflow run, the owner of an agent session, the person
behind an Octelium session. It is matched against `Recognition` identities
(`github:<user id>`) to find the person.

- Reported by the source, so it is as trustworthy as the source.
- Used for display ("triggered by alice") and for exclusions ("the initiator
  may not approve").
- Optional. With no initiator, exclusions that need one do not apply, and
  policies can require one (`require_initiator = true`).

### When a request is decided

| Involved | What it is |
|---|---|
| **Decider** | an Active **person**; never a workload |
| **Identity used** | the account they act through: `SignIn` (web UI, OIDC session) or `Chat` (Discord) |
| **Assurance** | what that identity and session prove now: `linked` (chat), `session`, `fresh-auth` (recent passkey) |
| **Channel** | where the decision was made (web, Discord) |
| **Eligibility** | the policy's selectors frozen with the request, current group membership and status, exclusions |
| **Relations to the request** | same person as the requester? owner of the requester? the initiator? |

The decider's identity comes only from countersign's own sign-in or a chat
link the person made; nothing in the request can influence who the decider
is.

## Entities

```text
            ┌────────────┐ owns  ┌────────────┐
            │  Person    │──────▶│  Workload  │   agents, CI pipelines, scripts
            └─────┬──────┘       └─────┬──────┘
                  │ has many           │ has many
            ┌─────▼──────┐       ┌─────▼──────┐
            │ Identity   │       │ Identity   │   (provider, subject), one actor each
            └────────────┘       └────────────┘
   member of  ▲        ▲ member of
            ┌─┴────────┴─┐  granted  ┌────────┐
            │  Group     │──────────▶│  Role  │   (persons only)
            └────────────┘           └────────┘
            ┌────────────┐
            │  Client    │   authenticated caller of the intake API
            └────────────┘
```

### Actor: Person or Workload

| | Person | Workload |
|---|---|---|
| What | a human | anything automated: AI agent, CI pipeline, script |
| Signs in to the web UI | yes | never |
| Can decide (approve, answer) | yes, if eligible | never |
| Can be a requester | yes | yes |
| Can be an initiator | yes | no |
| Owners | — | one or more persons, required |

```rust
struct ActorId(String);   // never reused
enum ActorKind { Person, Workload { owners: BTreeSet<ActorId> } }

struct Actor {
    id: ActorId,
    kind: ActorKind,
    display_name: Option<String>,
    status: Status,       // Active | Suspended { since, by, reason } | Removed { at }
}
```

A removed actor stays as a tombstone so old audit records still resolve.

A workload is not a client. One client can deliver requests for many
workloads (one host, several OS users), and one workload can be delivered by
several clients (an agent using sudo on many hosts).

### Identity

```rust
struct Identity {
    provider: ProviderRef,
    subject: String,       // the provider's stable id, never an email or display name
    actor: ActorId,
    source: Source,        // Config | Linked { at, via }
    purpose: Purpose,      // SignIn | Chat | Recognition
}
```

Written as strings: `oidc:<issuer>#<sub>`, `discord:<user id>`,
`github:<user id>`, `github:repo:<owner>/<repo>:environment:<env>`,
`octelium:<cluster>#<user>`, `unix:<host>#<user>`.

- `(provider, subject)` is unique: one account belongs to one actor.
- Purpose limits what an identity proves:
  - `SignIn`: authenticates a person in the web UI; the only way to
    `fresh-auth`. Persons only.
  - `Chat`: acting from chat, at most `linked`. Persons only.
  - `Recognition`: recognising a requester or initiator in what sources
    report. Proves nothing about who is deciding.

### Group

```rust
struct Group {
    name: GroupName,
    members: BTreeSet<ActorId>,        // from config
    from_idp: Vec<IdpGroupMapping>,    // e.g. the IdP group "countersign-ops"
}
```

- IdP groups count only through an explicit mapping in config.
- IdP membership is a snapshot taken at sign-in (`groups` claim), refreshed
  at every sign-in and fresh-auth. Past `idp_groups_max_age` (default: the
  session lifetime) it does not count until the person signs in again.
- Persons must exist in config; an IdP sign-in never creates one.
- Groups may contain workloads, for policy matching (`requester_group`).

### Role

What a person may do in countersign, not which requests they may decide.

| Role | Capabilities |
|---|---|
| `member` | sign in; see requests they are eligible for; decide them; link chat accounts |
| `auditor` | read every request and audit record (confidential content excepted) |
| `admin` | suspend and reinstate actors; revoke grants in bulk; unlink chat accounts; invoke break-glass policies |

- Granted to persons or groups; additive; workloads have none.
- `admin` does not imply eligibility.
- Admin actions are recorded; suspension and bulk revoke notify all channels.

## Relationships

| Relation | Meaning |
|---|---|
| `same_person(p, r)` | p is the requester, or shares an identity with it |
| `owner(p, r)` | p owns the requesting workload |
| `initiator(p, r)` | p is the request's initiator |
| `member(a, g)` | a is in group g now |

## Eligibility

```toml
[[policy]]
name = "prod-deploy"
match = { source = "github-actions", requester = "deploy-prod" }
approvers = ["group:ops"]
exclude = ["requester", "owners", "initiator"]   # default: ["requester"]
require_initiator = true
quorum = 1
min_assurance = "fresh-auth"
```

A person P may decide request R when, at decision time:

1. P is `Active`.
2. P matches the selectors stored with R **and** still matches them now.
3. P is not excluded (same person, owner, initiator, as the policy says).
4. P presents the minimum assurance through a `SignIn` or `Chat` identity.
5. P has not already decided R (quorum counts persons).

Selectors are frozen with the request; status and membership are checked
live. A request can only get harder to approve after it is created. If no
Active person can meet 1–4 for the quorum, the request fails at once with "no
eligible approvers".

## Lifecycle

| Event | Effect |
|---|---|
| Person suspended / removed | web sessions ended; chat links stop working; their decisions on pending requests stop counting |
| Person removed from a group | the live check stops new decisions; nothing else changes |
| Grant approved by someone later suspended | stays active; admins get "revoke grants approved by X", offered on the suspension screen |
| Workload suspended | new requests refused; open requests withdrawn |
| Last Active owner of a workload gone | the workload is suspended |
| Client key revoked / removed | its requests are refused; open ones withdrawn |
| Identity unlinked | future actions through it fail; past records keep the identity string |

Suspensions live in the database and override `Active` in config, so admins
act without a deploy. Removal is a config change.

## Storage

| Data | Source of truth |
|---|---|
| Persons, workloads and owners, clients, groups and IdP mappings, roles, `SignIn`/`Recognition` identities | config |
| Chat links | database (link flow) |
| IdP group snapshots | database (sign-ins) |
| Suspensions | database (admin actions) |
| Requests and audit | database; actor ids plus a snapshot of display names, source, requester identity, initiator |

## Configuration sketch

```toml
[[person]]
id = "alice"
display_name = "Alice"
identities = ["oidc:https://id.example.com#<sub>", "github:<user id>"]

[[workload]]
id = "agent-ops"
owners = ["alice"]
identities = ["unix:web-1#agent", "octelium:main#agent-ops"]

[[workload]]
id = "deploy-prod"
owners = ["alice"]
identities = ["github:repo:example/app:environment:prod"]

[[client]]
id = "web-1"
auth = { host_key = "sha256:…" }
scopes = ["approval"]

[[client]]
id = "github-actions"
auth = { oidc = { issuer = "https://token.actions.githubusercontent.com", audience = "countersign" } }
scopes = ["approval"]

[[group]]
name = "ops"
members = ["alice"]
from_idp = [{ provider = "oidc:https://id.example.com", group = "countersign-ops" }]

[roles]
admin = ["person:alice"]
auditor = ["group:security"]
member = ["group:ops", "group:security"]
```

`[[host]]` becomes `[[client]]` with `host_key`; the sudo backend's
`users` map is replaced by workload identities and groups.

## What this changes in current code

- `Approver` → `Actor` (person); `Requester` → requester identity plus
  optional resolved `ActorId`; new `Source` and `Initiator` on requests.
- Self-approval checks become the relation checks above.
- Intake authentication becomes per-client with scopes and vouch rules; CI
  OIDC clients are a new auth method.
- The web sign-in stores a `groups` snapshot with the session.
- Decision-time checks 1–5 replace the current check, with tests for removal,
  group change and policy edit mid-request, quorum by persons, and owner and
  initiator exclusion.

## Open questions

- Workload registration only through config, or also self-service with admin
  approval?
- Time-limited group membership (on-call), or leave it to the IdP?
- Break-glass: a policy only `admin` can invoke, with loud notification. Needs
  its own design.
