# CI approval gates and structured questions (`countersign-ask`)

`countersign-ask` lets CI pipelines, scripts, and agents ask humans a structured
question and receive the validated JSON answer on `stdout` (progress and the
review link go to `stderr`).

> [!IMPORTANT]
> An answer never grants access inside countersign. If a pipeline proceeds to
> perform a privileged action, gate that action with its own approval or
> least-privilege credential.

## 1. Configure a CI OIDC client on `countersignd`

Using OIDC JWTs avoids static secrets in CI. Add a `[[client]]` and
`[[question_policy]]` to `/etc/countersign/config.toml`:

```toml
[[workload]]
id = "ci-release"
owners = ["alice"]

[[client]]
id = "github-actions"
auth = { oidc = {
  issuer = "https://token.actions.githubusercontent.com",
  audience = "countersign",
  # Optional: restrict to a specific repository and branch/tag
  claims = { repository = "example/*", environment = "prod" },
  initiator_claim = "actor_id",
  initiator_scheme = "github"
} }
scopes = ["question"]
actor = "ci-release"

[[question_policy]]
name = "release-gates"
match = { asker = "github-actions" }
responders = ["group:approvers"]
min_assurance = "fresh-auth"
answer_timeout = "30m"
max_pending = 5
```

Reload the daemon (`sudo systemctl reload countersignd`).

## 2. Call `countersign-ask` from GitHub Actions

Grant `id-token: write` to the job and pass `--github-oidc`:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - name: Ask operator to confirm release
    run: |
      RESULT=$(countersign-ask \
        --server https://countersign.example.com:2743 \
        --github-oidc \
        --audience countersign \
        --message "Deploy ${{ github.sha }} to production?" \
        --yes-no \
        --context "repo=${{ github.repository }}" \
        --context "ref=${{ github.ref_name }}" \
        --timeout 15m)
      echo "$RESULT" | jq .
```

## 3. Question types and exit codes

- `--yes-no`: boolean field (default field name: `answer`, override with `--field`)
- `--choice A --choice B`: single-select enum
- `--text`: non-empty string
- `--schema '<json>'` or `--schema-file path.json`: full MCP elicitation JSON Schema subset
- `--confidential` / `--answer-may-be-confidential`: keep question/answer out of chat and logs

| Exit code | Meaning                                                                   |
| --------- | ------------------------------------------------------------------------- |
| `0`       | Answered (`state: "answered"`, `action: "accept"`)                        |
| `2`       | Declined by responder (`state: "declined"`, `action: "decline"`)          |
| `3`       | Expired without an answer (`state: "expired"`)                            |
| `4`       | Withdrawn on local timeout, `SIGINT`, or `SIGTERM` (`state: "withdrawn"`) |
| `1`       | Operational, auth, network, or policy error                               |
