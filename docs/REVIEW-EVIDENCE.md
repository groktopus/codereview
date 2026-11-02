# Review evidence receipts (GA-1)

Status: **partial implementation of GA-1
([issue #269](https://github.com/groktopus/codereview/issues/269))**. The receipt
protocol and CI validator exist; enforcement is pending the owner marking the
`Review receipt` check required. It is not a GitHub review record or branch
protection, and this change does not by itself make an unreceipted merge
impossible.

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

## Enforcement limits

This mechanism is enforceable only after the repository owner completes one
setting change. Without it, the workflow produces a failing check but GitHub
does not prevent a merge:

> **Owner action:** in repository **Settings → Branches**, protect `main`,
> enable **Require status checks to pass before merging**, and select
> **Review receipt** (and the other required harness jobs). Enable **Require
> branches to be up to date before merging** so the check runs against the
> latest base. Optionally restrict force pushes and deletions.

The owner deliberately did not enable branch protection in this change, so the
current state is: the receipt protocol is documented, checked, and visible, but
a merge is only procedurally blocked until that setting exists.

## Bootstrap, retention, and caps

- The bootstrap merge is the only acknowledged exception; it must still carry a
  completed receipt in its body even though the check is absent. The owner
  cannot select `Review receipt` as required until it has run at least once on
  `main`; bootstrap in two steps (merge this protocol with a receipt, then mark
  the check required).
- The workflow retains the PASS/error summary in the job summary and log. It
  does **not** upload a signed or immutable receipt artifact; PR bodies remain
  editable and logs expire. Export the PR body and job log together for audit.
- Caps: receipt ≤64 KB, event body ≤2 MB, scope/evidence ≤50 items each, most
  fields ≤4000 chars, reviewer identity ≤200, `post_merge_verification` ≥10
  chars, evidence values single-line.

Even with the check required, CI can and cannot do the following:

**CI can enforce**

- A single, well-formed `review-receipt` block is present in the pull request
  body on every `opened`, `edited`, `synchronize`, and `reopened` event.
- The reviewed SHA equals the head SHA observed in that event.
- The verdict is exactly `CLEAR`, all required fields are non-empty, no
  placeholder text remains, and no unknown approval-like fields are present.
- Self-review is declared consistently with the recorded reviewer identity,
  and agent reviews carry a protocol string.
- The check fails closed when the event payload is missing or malformed.

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
- Direct pushes, force pushes, or merges performed by automation that bypass
  the pull request body.

Post-merge verification is therefore the compensating control: the merger
records the merge commit and its required checks, and confirms the merged
commit's parent is the reviewed head. It is a recorded procedure, not a CI
gate. A future change can promote it to an automated post-merge check if the
owner enables branch protection or a merge queue.

## Related documents

- [Contributing](../CONTRIBUTING.md) — development checks and merge
  expectations.
- [Operations guide](OPERATIONS.md) — CI operation, evidence handling, and
  recovery.
- [Status](STATUS.md) — what the harness does and does not do.
- [Issue record: governance and accountability](issues/09-governance-and-accountability.md)
  — GA-1 scope and exit criteria.
