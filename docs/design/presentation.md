# Design: how requests and questions are presented

Status: implemented (`countersign_core::present`). Before, every surface
(Discord, ntfy, web UI, CLI, webhook) built its own view from the raw
request, mostly by listing fields.

## Goal

An approver should understand, at a glance and on any surface, **what will
happen if they approve**: who wants to do what, where, as whom, for how long,
and why they say so. Everything else (identifiers, identity strings, policy
internals) stays available for audit but out of the way.

The data model has settled (`identity-model.md`, `questions.md`,
`sudo-approval.md`), so presentation can now be designed once, in one place,
instead of per channel.

## What was wrong

A `sudo id` by an agent on a target host, as it used to be shown:

```text
subject       sudo/sudo/b15007eb-d2b2-4b16-a0b0-4139e72ca5fd
requester     agent (agent@web-1)
identity      unix:web-1#agent (agent)
target        web-1
reason        deploy the hotfix
attr.command  id
attr.cwd      /home/agent
attr.host     web-1
attr.runas    root
attr.user     agent
policy        agent-sudo
needs         1 approval(s) at linked, once for 60s, excluding requester
```

1. **The command is Countersign's reading, not what was typed.** Approvers
   see `id`, not `sudo id`; with options they see either a rewritten form or,
   for options Countersign does not trust (`-E`, `-D`, ...), the raw
   arguments without `sudo`. The two forms look alike but mean different
   things.
2. **Backend attributes are dumped as-is.** `attr.*`, the subject id, host and
   target twice, user and requester twice. They exist for policy matching and
   audit, not for deciding.
3. **What approving does is buried.** "Runs this command once, as root, within
   60 s" or "allows `apt*` for 15 minutes" is the most important line and
   appears as `once for 60s` at the end, or as `Duration: 15m (window)`.
4. **Each surface decides on its own** what to show, in which order, how to
   escape untrusted text, how to label states. Discord says "Access request —
   ended", the web says "ended", the CLI says `ended`; Octelium sessions,
   sudo commands and exec subjects all get the same generic layout.

## Principles

1. **Show what will run, verbatim.** For sudo, the command line exactly as
   `sudo` received it. It is what `sudo` will interpret, so it is the most
   precise thing to show; Countersign's own reading of it is used for policy
   matching, not as the primary display.
2. **Lead with the consequence.** The first thing after the headline is what
   approving allows: scope, identity, duration.
3. **One model, many renderers.** Core builds a `Presentation` from a request
   or question; channels and the web UI only lay it out within their limits.
   Escaping, redaction and wording rules live in core and are tested once.
4. **Mark where facts come from.** Facts the source vouches for (host, user,
   identity) are shown plainly; text the requester wrote (reason, question
   context) is labelled as unverified.
5. **Audit details are folded, not dropped.** Identifiers, identity strings,
   subject references and the policy match stay one click (or `--verbose`)
   away.
6. **Never cut what is being approved.** If the command or question does not
   fit a surface, that surface says so and offers the web UI instead of an
   approve button (today's Discord rule, made general).

## The model

`countersign_core::present::Presentation` is derived from a stored `Request`
or `Question` (so old records render the same way later), for an audience:
`Chat` (channels, webhooks) or `Full` (web UI, CLI):

```text
Presentation
  kind       approval | question
  headline   one line: "agent wants root on web-1"
  grant      what approving allows, in words:
               "Runs this command once, as root, within 1 minute"
               "Allows agent to run commands matching `apt*`, as any user,
                on web-1, for 15 minutes"
               "Lets this session through for up to 30 minutes"
               (questions: "Answering grants nothing; the answer goes back
                to the asker")
  action     what the request is about, as shown (see "Actions"):
               Command { line }            shell-quoted, escaped
               Lines { title, lines }      sessions, exec backends
               Question { message, fields } fields summarised: "one of: a, b"
  facts      vouched for by the source: Host/Target, Run as, Directory,
             On behalf of (questions: Asked by)
  claims     requester-supplied text, labelled unverified: reason, context
  notes      remarks from countersign (why a command policy did not apply)
  status     state, label in words, detail, the time that matters
             ("Decide by", "Active until", "Ran at"), needs, tone (for
             colours), decisions, window uses
  audit      request id, subject ref, source, requester and identity,
             actor, initiator, policy and its rules, matched scope,
             attributes, binding (Full only)
  withheld   sensitive approval / confidential question for Chat: only the
             headline (safe title), From and Policy, and the status
```

A window covers later commands from the same requester and host that match
the same policy, whoever they run as, unless the policy itself matches on
`runas`; the grant sentence says so ("as any user"). The policy's attribute
globs are frozen with the request (`Requirements.scope`) so the sentence
does not change when the policy is edited later.

Redaction happens when the presentation is built: a withheld presentation
simply has no action, claims or audit content, so a renderer cannot leak
what it never receives. All untrusted text in a presentation already has its
hidden characters written out.

### Actions

The action comes from the backend, which knows what its subjects are.
`SubjectFacts` gains a typed `action` field, set by the backend (or by the
intake API for host requests) when the subject is reported, next to the
existing `attributes`, which remain the policy-matching surface:

- **Command** (host backend / sudo): `line` is the full `sudo` argv as the
  helper read it from the calling process, with `argv[0]` normalised to
  `sudo` or `sudoedit` (the helper has already checked it is a known sudo
  binary), plus `runas`, `cwd` and `notes`. The parsed command stays in
  `attributes.command` for matching and windows, and is shown only in the
  audit section.
- **Session** (Octelium): session type, device, user agent, credential name,
  whether it is a browser session (also kept as `attributes` for policies).
- **Generic** (exec backends): the program's optional `summary`, `{"title",
  "lines": [{"label", "value"}]}` (at most 10 lines). The program is
  configured by the operator but its output is still treated as untrusted
  text.
- **Question**: built from the question itself, not from facts.

### Showing a command line

- Arguments are joined with POSIX shell quoting, so the line can be copied
  and means exactly the same to a shell: `sudo -u postgres -- psql -c 'DROP
  TABLE x'`.
- Characters that could hide or reorder text (controls, zero-width,
  bidi overrides, tags; `countersign_core::text`) are written as
  `$'‮'`-style escapes inside the quoted argument, never dropped, so two
  different commands never display the same.
- Long lines wrap; they are never cut on a surface that offers approval.

### The signature covers what is shown

The approval signature (`approval_signing`) binds the invocation digest. With
the raw line displayed, the digest is computed over the raw `sudo` argv (plus
user and cwd), so what the approver saw is exactly what the signature allows
and the helper verifies. The helper already has the raw argv; the intake
request gains `sudo_argv` and drops the separate `runas`/`argv` pair, which
Countersign derives itself.

## Wording

States, in words, the same everywhere (the machine value stays in JSON):

| state             | label                | detail line                                     |
| ----------------- | -------------------- | ----------------------------------------------- |
| pending           | Waiting for approval | Decide by 14:30 (in 4 min)                      |
| approved / active | Approved             | Active until 14:45 (window) / Ready to run once |
| ended             | Approved, used       | Ran at 14:29 / Window closed at 14:45           |
| denied            | Denied               | by alice via Discord                            |
| expired           | No decision          | Nobody decided in time                          |
| withdrawn         | Withdrawn            | The requester gave up                           |
| revoked           | Revoked              | by alice at 14:40                               |
| failed            | Failed               | Countersign could not apply the decision: …     |

Questions: Waiting for an answer / Answered / Declined / No answer /
Withdrawn.

Labels: "Requested by" (actor, else the requester as the source names it),
"Host" for host requests and "Target" otherwise, "Run as", "Directory",
"Reason (from the requester, unverified)", "Policy", "Needs". The terms
_requester_, _target_ and _subject_ stay in JSON and the audit section.

Times: absolute and relative (`14:30 (in 4 min)`); the web UI in the
viewer's time zone, the CLI in UTC with `Z`, Discord with its own `<t:…>`
tags.

Language: English for now; the presentation model keeps strings in one
place so that a later translation (Japanese first) touches one module.

## Surfaces

Each surface lays out the same parts, in the same order, within its limits.

**Discord** (embed): title = state label + headline; description = the
command line or question in a code block, then the reason; fields = Host,
Run as, Directory, the grant sentence, Needs, deadline; footer = request id.
Approve only when the action and claims are shown in full and assurance
allows it; otherwise "Approve in web UI" plus Deny. Withheld: headline, From,
Policy, deadline, link.

**Slack** (Block Kit): same layout and safety rules as Discord (Approve/Deny
or single-field answer buttons when shown in full and assurance permits,
otherwise a link to the web UI; withheld requests show only headline, From,
Policy, and link).

**Web Push**: delivered only to eligible active approvers/responders. By
default (`details = false`), shows only a safe title on lock screens; clicking
opens the request page in the web UI / installed PWA.

**ntfy**: title = headline; message = grant sentence and, with `details`,
the first line of the command and the reason; click opens the web UI.

**Web UI, request page**: header (headline, state label), a highlighted
"If you approve" box with the grant sentence, the action (command block or
question), claims, then status and decisions, then a folded "Details" with
the audit section. The decision form stays at the bottom, next to the grant
sentence repeated on the button ("Approve: run once as root").

**Web UI, list**: one row per item: kind, headline, first line of the
action, state label, deadline.

**CLI `show`**: the same sections as plain text, audit included only with
`--verbose`; `--json` stays the raw record plus the presentation object.
`requests` lists headline and state like the web list.

**Webhook**: the payload keeps the raw request (already redacted with
`for_chat()`) and gains `presentation` (headline, grant, action) so
receivers need not rebuild the wording.

**Clients** (countersign-sudo, MCP): unchanged; they print the approval link
and the outcome. The helper may print the grant it received ("approved for
15 minutes for apt*").

## Examples

A single sudo command:

```text
Waiting for approval — agent wants root on web-1
  If you approve: runs this command once, as root, within 1 minute
  $ sudo id
  Directory   /home/agent
  Reason      deploy the hotfix   (from the requester, unverified)
  Needs       1 approval at linked · Decide by 14:30 (in 4 min)
```

A window:

```text
Waiting for approval — agent wants root on web-1
  If you approve: allows agent to run commands matching `apt*`, as any
  user, on web-1, for 15 minutes
  $ sudo apt update
```

Options Countersign does not interpret are still shown as typed, with a
note on why command-specific policies (such as an `apt*` window) did not
match:

```text
  If you approve: runs this command once, as root, within 1 minute
  $ sudo -E apt install foo
  Note        -E keeps the caller's environment, so policies for specific
              commands do not apply
```

An Octelium session:

```text
Waiting for approval — cs-test wants a session
  If you approve: lets this session through for up to 30 minutes
  Session on octelium
    Type      client
    Device    laptop-7
    Client    octelium-cli/0.21
```

A sensitive approval in chat:

```text
Waiting for approval — Sensitive approval request from web-1 (agent-sudo)
  Details only in the web UI.
```

## Implementation

- `countersign_core::present`: `Presentation`, wording, `duration_words`,
  `relative`; `countersign_core::text::shell_join` for command lines;
  `countersign_core::sudo` reads a `sudo` line for policies.
- Intake: `sudo_argv` replaces `runas`/`argv`; the invocation digest is over
  `[user, cwd, sudo_argv]`. (Unreleased: no compatibility with the old
  submission shape; hosts need the new helper.)
- Backends set `facts.action`; `Use.action` keeps the line of each command
  run under a window.
- Discord, Slack, Web Push, ntfy, webhook (`presentation` in the payload), the
  web UI request and list pages, the question page header and the CLI
  (`show --verbose`, `show --json` = `{approval|question, presentation}`) use
  it. Times: the web UI renders UTC in SSR and switches to the viewer's local
  time zone on hydration with a relative time, the CLI shows UTC, and Discord
  uses `<t:…>` tags.

## Open questions

- Should the web UI show Countersign's parsed reading next to the raw line
  when they differ (e.g. `sudo -u postgres psql` → runs `psql` as
  `postgres`), or is the headline's "as postgres" enough?
- Per-policy display hints (e.g. emphasise certain arguments, colour
  production hosts) — useful, but configuration should wait until the
  built-in layout has been used for a while.
- A Japanese translation of the human-facing strings, and whether the
  language is per deployment or per person.
