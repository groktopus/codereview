# Review evidence receipts (GA-1) and decision-record links (GA-2)

Status: **GA-1 and GA-2 enforcement are active** (issues
[#269](https://github.com/groktopus/codereview/issues/269) and
[#270](https://github.com/groktopus/codereview/issues/270)). Both checks exist,
fail closed in CI, and are required status checks on `main`. Branch protection
keeps an explicit administrator bypass for the sole maintainer (`enforce_admins:
false`), so the owner can still merge their own PRs; the checks are mandatory for
every non-admin merge. Neither check is a GitHub review record. The remaining
verification is a recorded merge sample and a blocked non-admin merge attempt,
not a settings change.

Once the check is required, every merge into `main` must carry a review receipt
bound to the exact reviewed head. The first merge that adds this workflow is an
explicit bootstrap exception: `pull_request_target` executes the workflow from
the default branch, so the check cannot exist for that PR. Put a completed
receipt in the bootstrap PR body and merge after independent review; every later
PR is checked. The receipt lives in the pull request body inside one fenced
`review-receipt` block, is validated by
[`scripts/check_review_receipt.py`](../scripts/check_review_receipt.py) in the
[`Review receipt` workflow](../.github/workflows/review-receipt.yml), and is
recorded next to the merge for later audit.

## Required receipt fields

The block contains one JSON object with `schema: "review-receipt.v1"`. Unknown
fields are rejected, so a receipt cannot add its own approval shortcut.

| Field | Type | Contract |
|---|---|---|
| `schema` | string | Must be `review-receipt.v1`. |
| `reviewer.identity` | string | Durable reviewer identity: GitHub login for a human, recorded agent identity for an agent. Must not be a placeholder. |
| `reviewer.kind` | string | `human` or `agent`. |
| `reviewer.protocol` | string | Required when `kind` is `agent`: harness, model, and the review protocol followed. Optional and normally omitted for humans. |
| `reviewed_sha` | string | Full 40-character lowercase hex SHA of the reviewed pull request head. Abbreviations are rejected. |
| `independence` | string | Statement of whether the reviewer is independent of the author and what made the review independent. At least 20 characters. |
| `scope` | array of strings | Concrete files, diff ranges, or behavior examined. At least one item. |
| `verdict` | string | Exactly `CLEAR` or `NOT CLEAR`. Only `CLEAR` passes. |
| `evidence` | array of objects | Each entry is `{"kind": "link", "value": "https://..."}` or `{"kind": "command", "value": "..."}`. At least one entry. CI never runs commands from this field. |
| `reviewed_at` | string | ISO 8601 timestamp with a time zone, for example `2026-11-02T12:00:00Z`. |
| `self_review` | boolean | `true` only when `reviewer.identity` is the pull request author. |
| `post_merge_verification` | string | What will be verified after merge: the merge commit identity and the required checks on it. |
| `decision_records` | array of strings | Optional. **Required** by the `Decision record links` check when the pull request changes a path or glob listed in [`docs/adr/safety-invariants.json`](adr/safety-invariants.json), including the manifest file itself. Each item is a four-digit record ID (`0002`), a `docs/adr/NNNN-*.md` path, or an https link to that file. At most 10 items; an empty list is rejected so it cannot stand in for "not required". |

## Rules

1. **The reviewed SHA must equal the pull request head at merge.** The check
   compares `reviewed_sha` with `pull_request.head.sha` from the event. Any new
   commit changes the head, triggers the workflow again on
   `synchronize`, and invalidates the old receipt until it is updated. A merge
   of a head other than the reviewed SHA fails this rule.
2. **No self-review unless explicitly recorded.** When the reviewer identity
   equals the pull request author, `self_review` must be `true` and the
   `independence` statement must describe the limitation. When the reviewer is
   someone else, `self_review` must be `false`; claiming self-review for an
   independent reviewer is rejected as inconsistent.
3. **An agent may review only when its identity and protocol are recorded.**
   `reviewer.kind: "agent"` requires a non-placeholder `reviewer.protocol`
   naming the harness, model, and review protocol. The protocol text is a
   declaration by the reviewer; CI verifies that it exists, not that it is
   true.
4. **`NOT CLEAR` blocks.** A `NOT CLEAR` verdict, an unknown verdict, a missing
   verdict, or a placeholder verdict fails the check. There is no CI path that
   turns `NOT CLEAR` into `CLEAR`.
5. **Merge only after required checks are green at the exact head.** The
   receipt records review; it does not replace the test, lint, documentation,
   coverage, or compatibility jobs. The merger must confirm those required
   checks succeeded at `reviewed_sha` immediately before merging.
6. **Verify after merge.** After the merge, record the merge commit SHA and the
   required checks that ran on it, and confirm the reviewed head is the pull
   request head that was merged. `post_merge_verification` in the receipt
   states how this will be done; the observed result belongs in the merge
   record or a follow-up comment linked from the pull request.
7. **No auto-approval.** CI only validates text that a reviewer wrote. It never
   posts a review, approves, merges, edits the body, or infers a verdict.
   Unknown fields (including anything that looks like an approval instruction)
   fail closed.
8. **Safety-invariant changes cite accepted decision records.** When the pull
   request changes a path or glob in [`docs/adr/safety-invariants.json`](adr/safety-invariants.json)
   — or the manifest file itself, or a renamed or deleted protected path — the
   receipt must carry `decision_records`. Every cited record must already exist
   on the pull request **base** revision, be listed in the
   [decision-record index](adr/README.md), and have Status `Accepted`.
   Because the check reads the base revision, a record added by the same pull
   request does not count yet: land the accepted record in its own pull request
   first, or cite an existing accepted record that already authorizes the
   behavior. `docs/adr/README.md` owns that process.

## Writing a receipt

Open the pull request template, keep the single fenced block, and replace every
placeholder. The author may open the pull request, but the reviewer owns the
block's content.

```review-receipt
{
  "schema": "review-receipt.v1",
  "reviewer": {
    "identity": "octocat",
    "kind": "human"
  },
  "reviewed_sha": "0123456789abcdef0123456789abcdef01234567",
  "independence": "Independent reviewer; did not author, pair on, or advise this change.",
  "scope": [
    "diff 0123456..89abcde",
    "src/pr_review_harness/cli.py and tests/test_cli.py",
    "read-only and credential-boundary behavior in the changed paths"
  ],
  "verdict": "CLEAR",
  "evidence": [
    {"kind": "link", "value": "https://github.com/groktopus/codereview/actions/runs/00000000000"},
    {"kind": "command", "value": "python -m pytest -q tests/test_cli.py -> 52 passed"},
    {"kind": "link", "value": "https://github.com/groktopus/codereview/pull/000#issuecomment-000000000"}
  ],
  "reviewed_at": "2026-11-02T12:00:00Z",
  "self_review": false,
  "post_merge_verification": "Confirm the merge commit contains the reviewed head and that required checks pass on the merge commit."
}
```

For an agent review, add the protocol and keep the same evidence standard:

```json
"reviewer": {
  "identity": "review-agent/dsh-subagent",
  "kind": "agent",
  "protocol": "DeepSeek Harness subagent, model reported in the session; read-only diff and repository review protocol; no target execution."
}
```

When the change touches a safety-invariant path, add the records that authorize
it (omit the field otherwise):

```json
"decision_records": ["0002", "docs/adr/0004-publication-authorization.md"]
```

## The CI check

`Review receipt` runs on `pull_request_target` for `opened`, `edited`,
`synchronize`, and `reopened`. The workflow checks out the pull request **base**
revision only, with `persist-credentials: false`, read-only `contents`
permission, and no secrets. The receipt script reads only the event JSON; it
does not read the pull request checkout, execute pull request code, or use the
network.

Run the same check locally against a captured event payload:

```sh
python3 scripts/check_review_receipt.py --event pull_request.json
python3 scripts/check_review_receipt.py --event pull_request.json --json
```

Failure codes and exit codes are stable:

| Exit | Codes | Meaning |
|---|---|---|
| 0 | — | Receipt accepted for the exact head. |
| 1 | — | Unexpected internal error. |
| 2 | `EVENT_PATH_MISSING`, `EVENT_PATH_UNREADABLE`, `EVENT_TOO_LARGE`, `EVENT_INVALID_JSON`, `EVENT_INVALID_SHAPE`, `EVENT_HEAD_UNKNOWN`, `EVENT_AUTHOR_UNKNOWN` | The event is absent or malformed; the check fails closed. |
| 3 | `RECEIPT_MISSING`, `RECEIPT_DUPLICATE`, `RECEIPT_UNCLOSED`, `RECEIPT_TOO_LARGE`, `RECEIPT_NOT_JSON`, `RECEIPT_NOT_OBJECT`, `RECEIPT_DUPLICATE_KEY` | The fenced block is absent or unusable (duplicate JSON keys are rejected). |
| 4 | `FIELD_MISSING`, `FIELD_TYPE`, `FIELD_EMPTY`, `FIELD_INVALID`, `FIELD_UNKNOWN` | Schema or field validation failed. |
| 5 | `PLACEHOLDER` | Template or placeholder text remains in a required field. |
| 6 | `SHA_MISMATCH` | `reviewed_sha` is not the pull request head. |
| 7 | `VERDICT_NOT_CLEAR` | The verdict is not `CLEAR`. |
| 8 | `SELF_REVIEW_UNDECLARED`, `SELF_REVIEW_INCONSISTENT` | Self-review is undeclared or inconsistently declared. |
| 9 | `AGENT_PROTOCOL_MISSING` | An agent review lacks a recorded protocol. |

## The decision-record check (GA-2)

`Decision record links` runs on `pull_request_target` for `opened`, `edited`,
`synchronize`, and `reopened` on the base branch `main`. It is a separate
workflow so that each required check fails for its own reason. It checks out the
pull request **base** revision only, with `persist-credentials: false`,
`contents: read`, and `pull-requests: read`; the changed-file list comes from the
read-only GitHub API (`GET /repos/{owner}/{repo}/pulls/{number}/files`), and the
only token is the automatic `GITHUB_TOKEN`. No repository secret is used, the
token is never printed, redirects are refused, and no pull request code is
checked out or executed. The script is
[`scripts/check_decision_record_links.py`](../scripts/check_decision_record_links.py).

It fails closed when it cannot prove the requirement: no event, no changed-file
list, an API error or 1,000 or more changed files, a missing or malformed
manifest, a missing ADR index, a missing or unvalidated receipt, a missing
`decision_records` list, or any cited record that is malformed, unindexed,
absent from the base revision, or not `Accepted`.

Run it locally against a captured event payload and a changed-file fixture:

```sh
python3 scripts/check_decision_record_links.py \
  --event pull_request.json \
  --changed-files changed-files.json \
  --repo-root . \
  --json
```

The fixture is a JSON list of changed paths (strings, GitHub API item objects
with `filename`/`previous_filename`, or `{"files": [...]}`). It never contacts
the network. Without `--changed-files` the script reads the GitHub API and needs
`GITHUB_TOKEN`. `--base-ref` reads the manifest, index, and records from a Git
revision instead of the working tree; the workflow passes the base SHA.

Failure codes and exit codes are stable:

| Exit | Codes | Meaning |
|---|---|---|
| 0 | — | No safety-invariant path changed, or every cited record is accepted on the base revision. |
| 1 | — | Unexpected internal error. |
| 2 | `EVENT_PATH_MISSING`, `EVENT_PATH_UNREADABLE`, `EVENT_TOO_LARGE`, `EVENT_INVALID_JSON`, `EVENT_INVALID_SHAPE`, `EVENT_NUMBER_UNKNOWN`, `EVENT_REPOSITORY_UNKNOWN` | The event is absent or malformed. |
| 3 | `CHANGED_FILES_FIXTURE_MISSING`, `CHANGED_FILES_FIXTURE_INVALID`, `CHANGED_FILES_TOKEN_MISSING`, `CHANGED_FILES_API_UNAVAILABLE`, `CHANGED_FILES_API_ERROR`, `CHANGED_FILES_API_INVALID`, `CHANGED_FILES_API_TRUNCATED` | The changed-file list is unavailable, invalid, or truncated. |
| 4 | `BASE_UNAVAILABLE`, `MANIFEST_MISSING`, `MANIFEST_INVALID`, `INDEX_MISSING` | Base-revision content is missing or unusable. |
| 5 | `RECEIPT_NOT_VALID` | The review receipt is missing or did not validate; run `check_review_receipt.py` for details. |
| 6 | `DECISION_RECORDS_MISSING` | A safety-invariant path changed but the receipt has no `decision_records`. |
| 7 | `RECORD_REFERENCE_INVALID`, `RECORD_NOT_INDEXED`, `RECORD_NOT_ACCEPTED`, `RECORD_FILE_UNRESOLVED`, `RECORD_PATH_MISMATCH`, `RECORD_MISSING`, `RECORD_INVALID` | A cited decision record is malformed, unindexed, absent, or not accepted. |

Failures are emitted in a fixed code order, so identical input produces
identical output.

## Enforcement limits

Both mechanisms are required status checks on `main`. Branch protection uses
**Require status checks to pass before merging** for `Review receipt` and
`Decision record links`, with
`enforce_admins: false`, `strict: false`, and force pushes/deletions disabled.
The administrator bypass is a deliberate sole-maintainer exception: the owner can
merge their own PRs, while every non-admin merge requires both checks.

The outstanding verification is not a setting: record a sample of merges with
matching reviewed/merged SHAs and a blocked non-admin merge attempt.

Branch protection is enabled on `main` with `Review receipt` and
`Decision record links` as required contexts, `enforce_admins: false`,
`strict: false`, and force-push/deletion disabled. The administrator bypass is a
deliberate sole-maintainer exception, not an absence of enforcement.

## Bootstrap exception for GA-2 enforcement

The first pull request that adds the `decision_records` field and the
`Decision record links` workflow cannot be validated by them: `pull_request_target`
runs the base-branch workflow, whose receipt schema predates the field, and the
new check is not on the base branch. That bootstrap PR must still carry a valid
GA-1 receipt under the base schema, is independently reviewed, and is the only
merge exempt from citing `decision_records`. Every later pull request that
changes a safety-invariant path is checked. This exception does not authorize a
second unreceipted safety change.

## Bootstrap, retention, and caps

- The bootstrap merge is the only acknowledged exception; it still carried a
  completed receipt. `pull_request_target` runs the workflow from the default
  branch, so neither check could run on the pull request that first added it.
  Both checks have since run on `main` and are required.
- Both workflows retain the PASS/error summary in the job summary and log. They
  do **not** upload a signed or immutable receipt artifact; PR bodies remain
  editable and logs expire. Export the PR body and job logs together for audit.
- Caps: receipt ≤64 KB, event body ≤2 MB, scope/evidence ≤50 items each, most
  fields ≤4000 chars, reviewer identity ≤200, `post_merge_verification` ≥10
  chars, evidence values single-line, `decision_records` ≤10 items, changed-file
  list ≤999 entries (1,000 or more fails closed).

Even with both checks required, CI can and cannot do the following:

**CI can enforce**

- A single, well-formed `review-receipt` block is present in the pull request
  body on every `opened`, `edited`, `synchronize`, and `reopened` event.
- The reviewed SHA equals the head SHA observed in that event.
- The verdict is exactly `CLEAR`, all required fields are non-empty, no
  placeholder text remains, and no unknown approval-like fields are present.
- Self-review is declared consistently with the recorded reviewer identity,
  and agent reviews carry a protocol string.
- When a changed path matches `docs/adr/safety-invariants.json`, the receipt
  cites records that are indexed and accepted on the pull request base
  revision.
- Both checks fail closed when their input is missing, malformed, or
  unavailable.

**CI cannot enforce**

- That the reviewer identity is authentic: the receipt is text in the pull
  request body, editable by anyone who can edit the body. There is no
  cryptographic signature and no GitHub review record.
- That independence, scope, evidence, or the protocol text are true, or that
  the evidence links and commands exist or passed. CI does not fetch links and
  never runs receipt commands.
- That the required checks were green at the exact reviewed head, or that the
  merger did not merge a different head between the check run and the merge.
  That is what a required status check plus branch protection adds, and even
  then an administrator can bypass protection.
- That a receipt edited after a passing run is re-evaluated before an immediate
  merge. The `edited` event starts a new run, but a merge can race that run;
  the post-merge verification rule catches the mismatch afterward rather than
  preventing it.
- That a cited accepted decision record actually authorizes the change, or that
  the decision was wise or sufficient. The link check is structural: it proves
  the record exists, is indexed, and is accepted on the base revision.
- That the GitHub changed-file list reflects every intended change beyond the
  API response and its 999-entry cap. The check fails closed on an API error
  or an oversized list instead of guessing.
- Direct pushes, force pushes, or merges performed by automation that bypass
  the pull request body.

Post-merge verification is therefore the compensating control: the merger
records the merge commit and its required checks, and confirms the merged
commit's parent is the reviewed head. It is a recorded procedure, not a CI
gate. The owner could promote it to an automated post-merge check or a merge
queue later.

## Related documents

- [Contributing](../CONTRIBUTING.md) — development checks and merge
  expectations.
- [Operations guide](OPERATIONS.md) — CI operation, evidence handling, and
  recovery.
- [Status](STATUS.md) — what the harness does and does not do.
- [Decision-record index](adr/README.md) — record format, status vocabulary,
  safety-invariant surfaces, and the process for adding a record.
- [Issue record: governance and accountability](issues/09-governance-and-accountability.md)
  — GA-1 and GA-2 scope, status, and exit criteria.
