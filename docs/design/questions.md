# Design: questions alongside approvals

Status: implemented. Step 6 became an MCP endpoint in the intake API
(`POST /mcp`, below) instead of a separate bridge; there is no
`countersign ask` CLI. One deviation from the model below: a question is its own
type (`Question`), not a `RequestKind` variant inside `Request`. Both are
stored in the `requests` table with a `kind` column, and the engine's grant,
revoke and window code takes a `Request`, which a question cannot be, so the
type system keeps questions out of those paths.

## Goal

countersign stops something at a hook, asks the right people, and hands their
answer back. Today the only thing it asks is "may this happen?" (an
*approval*). This document adds a second kind, a *question*: "what should
happen?", answered with structured data.

- Approvals keep their current model and guarantees unchanged.
- Questions get their own schema, policy and API. They share the request list,
  channels, identity, assurance and audit log with approvals.
- A question can never grant anything, whatever its answer says.

Non-goals: chat or multi-turn conversation, collecting secrets, polls that
need everyone's answer (see "Later").

## Why two kinds, not one

| | Approval | Question |
|---|---|---|
| Answer | approve / deny | data matching a schema, or decline |
| Several responders | quorum (n of the eligible approvers) | first answer wins |
| After the answer | a grant that lasts for a TTL or window, can be revoked | nothing; the answer is a fact |
| No answer in time | expired, and that means **no** (fail closed) | expired, recorded as **unanswered**; the asker decides what that means |
| Self-answer | forbidden by default | allowed if policy says so |
| Effect | the backend grants access | none inside countersign |

Folding these into one schema would make every approval field optional and
every question field meaningless for approvals. Most security bugs in a merged
design would come from a question taking a path meant for approvals, so the
split is enforced in types, storage, config and API.

## Prior art this follows

Only widely adopted specifications are used as references.

- **MCP elicitation** (Model Context Protocol, `elicitation/create`, revision
  2025-11-25) is the model for questions:
  - `message` plus `requestedSchema`, a restricted JSON Schema subset: flat
    object; string (`minLength`, `maxLength`, `pattern`, `format` of `email`,
    `uri`, `date`, `date-time`), number/integer (`minimum`, `maximum`),
    boolean, single-select enum (`enum`, or `oneOf` with `const`/`title`),
    multi-select enum (`array` of those); `title`, `description`, `default`
    on every field.
  - Three outcomes: `accept` (with `content`), `decline`, `cancel`.
  - Rules: no secrets in form mode; validate answers against the schema on
    both sides; show clearly who is asking; no clickable URLs inside form
    fields.

  countersign adopts the schema subset and the action names as they are, so an
  MCP server or agent framework can forward an elicitation to countersign
  without translation. It adds what a remote, multi-person, asynchronous
  setting needs: who may answer, a deadline, and the `expired` and
  `withdrawn` outcomes.
- **JSON Schema** (draft 2020-12) defines the keywords above; countersign
  validates against the subset only and rejects any other keyword.
- Approvals keep the existing countersign model (quorum, assurance,
  once/window grants), which follows the usual access-request shape of
  Teleport Access Requests and similar systems. It is not changed here.

## Model

```rust
enum RequestKind {
    Approval(Approval), // today's request: requirements, grant, decisions
    Question(Question),
}

struct Question {
    message: String,             // shown to responders; untrusted
    schema: FormSchema,          // the MCP subset, parsed and checked
    requirements: QuestionRequirements,
    confidentiality: Confidentiality, // see "Confidentiality"
    outcome: Option<QuestionOutcome>,
}

struct Confidentiality {
    question: bool,      // message, schema and context are confidential
    answer_may_be: bool, // the answer may be confidential (pre-fills the responder's choice)
}

struct QuestionRequirements {
    policy: PolicyName,
    responders: Vec<ApproverSelector>, // same selectors as approvers
    min_assurance: Assurance,
    answer_timeout: Duration,          // until the question expires
    allow_self_answer: bool,
}

enum QuestionOutcome {
    Accepted { by: Principal, at: Timestamp, assurance: Assurance, content: Map,
               confidential: bool }, // set by the responder
    Declined { by: Principal, at: Timestamp, assurance: Assurance, note: Option<String> },
    Expired  { at: Timestamp },   // no one answered
    Withdrawn { at: Timestamp },  // the asker gave up (MCP "cancel" on its side)
}
```

The shared parts (id, subject, facts, created time, channel message
references, audit events) stay in `Request`; only the kind-specific body
differs. Store: one table with a `kind` column and the body as JSON, so the
web UI lists both in one place. Existing rows are approvals.

States of a question: `pending → answered | declined | expired | withdrawn`.
There is no `approved`, `active`, `revoked` or `ended`: the engine's
grant/revoke code paths match only `RequestKind::Approval`, so a question
cannot reach them.

### Timeouts and "no answer"

- `answer_timeout` is the only clock. When it passes, the outcome is
  `Expired`, stored and returned as such. countersign never fills in a
  default answer.
- The response tells the asker plainly: `"state": "expired"`. An asker that
  wants a default applies it itself, and the record still shows that no
  human answered.
- `default` values in the schema only pre-fill the form; they are not used on
  expiry.
- When bridged to MCP, `expired` and `withdrawn` map to `cancel`, `declined`
  to `decline`, `answered` to `accept`.

### Several responders

First valid answer wins and closes the question for everyone; channels update
their messages to show who answered. There is no quorum: n identical answers
would need a rule for disagreement, which is a poll, not a question.

## Configuration

Separate tables so that fields of one kind cannot be set on the other and
config validation rejects mixing them:

```toml
[[question_policy]]
name = "agent-questions"
match = { asker = "agent-*" }        # which askers may use it
responders = ["group:operators"]
min_assurance = "linked"
answer_timeout = "30m"
max_pending = 5                      # per asker
confidential = "allow"               # "deny" (default) | "allow" | "require"
confidential_min_assurance = "fresh-auth"
answer_retention = "7d"              # how long a confidential answer stays readable by the asker
```

`[[policy]]` (approvals) is unchanged. A question matching no
`[[question_policy]]` is refused, as with approvals.

## API

A separate path, so a client cannot turn one kind into the other by changing a
field:

```text
POST   /intake/v1/questions
       { "message": "Which branch should I deploy?",
         "requestedSchema": { "type": "object",
           "properties": { "branch": { "type": "string", "enum": ["main", "release"] } },
           "required": ["branch"] },
         "context": { … },                       # optional, shown as facts
         "confidentiality": { "question": false, "answerMayBe": true } }  # optional, both default false
  201  { "id", "state": "pending", "url" }

GET    /intake/v1/questions/{id}?wait=50
  200  { "id", "url", "state": "pending" | "answered" | "declined" | "expired" | "withdrawn",
         "action"?: "accept" | "decline" | "cancel",          # MCP-compatible view
         "content"?: { … }, "answeredBy"?: "…", "answeredAt"?: "…",
         "confidential"?: true }                  # the answer was marked confidential

DELETE /intake/v1/questions/{id}               withdraw: 204, or 409 if no longer pending
```

`/intake/v1/requests` stays approval-only.

### MCP

The same calls are offered as an MCP server over Streamable HTTP at
`POST /mcp` on the intake listener, so an agent needs no extra program, only
its MCP client configured with the URL and the client's key:

```json
{ "type": "http", "url": "https://countersign.example.com:8443/mcp",
  "headers": { "Authorization": "Bearer ${COUNTERSIGN_KEY}" } }
```

- Tools: `ask_question` (message, requestedSchema, optional context,
  `confidential`, `answerMayBeConfidential`), `get_answer` (id) and
  `withdraw_question` (id). Results carry the question as above in
  `structuredContent`, plus a short text for the agent.
- The key needs the `question` scope; policies, limits and confidentiality
  are those of the REST calls. Refusals (no policy, invalid schema, unknown
  id) are tool results with `isError`, so the agent can read and correct
  them.
- People answer in minutes, MCP clients often give up on a tool call after
  60 s: `ask_question` and `get_answer` wait at most `wait_seconds`
  (default 45, at most 55) and then return state `pending`; the agent calls
  `get_answer` again.
- Stateless: one JSON-RPC message per POST, answered with
  `application/json`; no sessions and no server-initiated stream (GET and
  DELETE answer 405). Requests with an `Origin` header (browsers) are refused.
- Authentication is a static bearer key, not the OAuth flow the MCP
  specification describes for remote servers; MCP clients that let you set
  headers support it.

## Confidentiality

Some questions or answers should not end up in chat channels or in the
long-term audit log, which is kept for years and read by more people than
the original responders. Confidentiality decides **what is kept and where it
is shown**, not who may answer.

Confidential is not the same as secret: passwords, keys and tokens stay out
of scope for every question (see "What answers contain"). Confidential means
business or personal information that is fine to give to the asker but should
not be kept or spread.

### Who sets it

| When | Who | Flag | Meaning |
|---|---|---|---|
| Asking | asker | `question` | the message, schema (titles, options) and context are confidential |
| Asking | asker | `answerMayBe` | the answer may be confidential; pre-fills the responder's choice |
| Answering | responder | `confidential` | this answer is confidential |

- The responder's checkbox starts from `answerMayBe`. The responder can change
  it either way: they know what they typed.
- A confidential question's answer is always confidential, so the checkbox is
  checked and locked. The answer to "which of these confidential options?"
  reveals the option.
- Policy limits the flags: `confidential = "deny"` (default) refuses
  confidential questions, `"allow"` accepts them, `"require"` treats every
  question under that policy as confidential.

### What is kept

The audit record always says that something happened: who asked, under which
policy, when, who answered, with what assurance, and the outcome. Only the
content is withheld.

| Part | Normal | Confidential question | Confidential answer only |
|---|---|---|---|
| Asker, policy, times, responder, assurance, outcome | kept | kept | kept |
| Message, schema, context | kept | **not kept**; replaced by a placeholder | kept |
| Answer content | kept | **not kept** | **not kept** |
| Field names of the answer | kept | not kept | kept (they come from the schema, which is not confidential) |

Confidential content is held only as long as the exchange needs it:

- The question text is kept while the question is pending, so responders can
  read it.
- The answer is kept until the asker has read it, or until
  `answer_retention` runs out, whichever is first.
- After that, the text is overwritten in the store (not just hidden). The
  audit record stays, marked "content removed (confidential)".

No hash of the content is kept: most answers (a choice from a short list, a
yes/no) can be recovered from a hash by trying every value.

Backups contain whatever was in the database when they were taken. Retention
is therefore kept short, and the docs say so: confidential content may live
in backups until those expire.

### Where it is shown

- Chat channels (Discord, ntfy, webhook) never get confidential text:
  - A confidential question is announced as "Confidential question from
    &lt;asker&gt; (&lt;policy&gt;)" with only countersign's link, and it can
    only be answered in the web UI.
  - A confidential answer is never echoed back into the channel message; it
    shows only "Answered by &lt;responder&gt;".
- In the web UI, confidential content is shown only to the responders of that
  question, and only while it is kept. Confidential questions can require
  stronger sign-in (`confidential_min_assurance`, e.g. fresh-auth with a
  passkey).
- Logs (journal, tracing) never contain question or answer text, confidential
  or not; they carry ids only.

### Abuse

The asker sets the `question` flag, and the asker is untrusted. A flag that
removes content from the audit log could hide what an asker was doing. So:

- Confidential questions are refused unless the policy allows them.
- The audit record still names the asker, policy and responder, so "agent X
  asked 40 confidential questions" stays visible.
- Confidential questions count against the same pending cap.
- The flags only reduce what is kept and shown; they never widen who can see
  something, and never affect approvals.

## Security

Widening the intake from "ask for approval" to "ask anything" adds a new kind
of input that people read and act on. The rules below keep the approval path
exactly as strong as today.

### Answers never authorize

- Questions have no grant, TTL, window or revoke; the engine code that grants
  access cannot be reached with a question (enforced by the `RequestKind`
  match, with tests).
- No backend may treat an answer as permission. A host helper (e.g.
  `countersign-sudo`) only talks to the approvals API.
- Docs for askers say so: if an answer leads to a privileged action, that
  action needs its own approval.

### Who may ask

- Askers authenticate as today (per-client keys in the `cshk_` format, hashed
  in config). Each key gets **scopes**: `approval`, `question`, or both.
  Existing host keys default to `approval` only, so a compromised host cannot
  start asking operators questions unless allowed.
- The asker's identity comes from the key, never from the body.
- Per-asker caps on pending questions, separate from approval caps, so
  question spam cannot crowd out approvals (and the reverse).

### What responders see

The message and schema text come from the asker and are untrusted.

- Every string (message, titles, descriptions, enum labels) goes through the
  same escaping as commands today: control, bidi, zero-width and tag
  characters are shown as escapes.
- Length limits: message, each title/description, number of fields and enum
  options, schema size. Over the limit is refused (400), not truncated.
- No links: URLs in question text are not made clickable in any channel (MCP
  rule). The only link is countersign's own request URL.
- Questions look different from approvals everywhere:
  - a "Question" label and a different colour;
  - buttons say "Answer" / "Decline", never "Approve";
  - the asker's identity is shown in a field the asker cannot write.

  This stops a question from passing itself off as an approval ("Approve
  sudo on web-1?").
- Discord can answer in place only for schemas that fit its components
  (a single enum or boolean). Anything else links to the web form, the same
  way long commands do today.

### What answers contain

- Answers go back to the asker (often an AI agent) and into the audit log.
  The web form states this, and no field may have `format: "password"` or
  similar. Secrets are out of scope (MCP rule); a later URL-style flow could
  handle them, as MCP's URL mode does.
- The server validates the answer against the schema before storing it; the
  form validates first only for convenience.
- Only the asker that created a question can read its answer.

### Who may answer

- Responders are resolved and checked like approvers: linked identity, the
  policy's `min_assurance` (a question can require `fresh-auth` in the web
  UI), and no self-answer unless `allow_self_answer`.
- Answering is recorded with the responder, the assurance used and the time,
  the same as decisions.

## UI

- One list for both kinds, with a kind badge and a filter. Detail pages
  differ: approvals show requirements and grant state; questions show the
  form (pending) or the answer (finished).
- Colours: answered = the "done" green used for ended approvals; declined =
  the deny red; expired/withdrawn = muted grey, labelled "No answer" for
  expired.
- CLI: `countersign requests` lists both; `countersign answer <id>` is not
  added (like approvals, answers need a responder identity and assurance).

## Rollout

1. Core: `RequestKind`, `Question`, `FormSchema` (parse + validate the MCP
   subset), outcomes; store migration with `kind`.
2. Config: `[[question_policy]]`, key scopes (existing keys default to
   `approval`).
3. Intake: `/intake/v1/questions` with long polling and withdraw.
4. Web UI: form rendering from the schema, answer page with fresh-auth.
5. Channels: kind-aware rendering; Discord in-place answers for single enum or
   boolean.
6. Agents ask through MCP (`POST /mcp` on the intake listener) without
   writing HTTP calls.

## Later / open questions

- Polls that need every responder's answer, or n matching answers.
- URL-mode style questions for secrets (answer never passes through
  countersign's store).
- Whether a question may carry a follow-up approval in one step ("pick a
  branch, then approve the deploy"): kept as two requests for now.
- Retention of non-confidential answers: they follow the same cleanup as
  finished requests once that exists.
