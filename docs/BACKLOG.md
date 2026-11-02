# Backlog triage: states, labels, owners, and closure evidence (GA-3)

Status: **operating triage for GA-3**. This file defines the states, labels,
owners, closure evidence, and the current open-issue map. The root applied the
`state:*` labels and `@magnus919` assignee to every open issue on 2026-11-02;
this table remains the checked-in board state and is refreshed when the open set
changes.

Source snapshot: [`backlog-open-issues.json`](backlog-open-issues.json), captured
with `gh issue list --repo groktopus/codereview --state open` at branch base
`5becb81`. The filed-issue map is [issues/FILED.md](issues/FILED.md); the theme
and exit criteria are in [issues/README.md](issues/README.md).

## Why this exists

The repository has one contributor and a 33-issue backlog filed from a dated
assessment. Filing was the first step; it is not triage. Without a state, an
owner, and a closure rule, "open" means only "not yet remembered." This document
makes the current state inspectable and gives the owner one table to apply.

It does not invent a team. Every owner is `@magnus919`, the only
recorded accountable human. See [OWNERSHIP.md](OWNERSHIP.md) for the bus-factor
statement and the limits of agent authority.

## States

Exactly one state applies to an open issue. A closed issue is `done` and drops
its state label; the closure record is the evidence.

| State | Meaning | Label | Exit from the state |
|---|---|---|---|
| `triage` | Intake exists but no owner decision on scope, dependencies, or next action. | `state:triage` | Owner assigns an accountable owner and either a state or a rejection reason. |
| `ready` | Dependencies are met; the issue is independently actionable now. | `state:ready` | Work starts (`in-progress`), a hard dependency appears (`blocked`), or the issue closes. |
| `in-progress` | An implementation or decision is actively being prepared on a named branch or pull request. | `state:in-progress` | Review/merge moves it to `awaiting-evidence` or `done`; abandonment returns it to `ready` or `blocked`. |
| `blocked` | Cannot proceed until a named open issue, owner action, or external prerequisite is resolved. | `state:blocked` | The blocker is closed or recorded as resolved, then `ready`. |
| `awaiting-evidence` | Implementation merged, but one or more exit criteria still lack observable evidence. | `state:awaiting-evidence` | The evidence is linked and checked (`done`), or the remaining work returns to `ready`. |
| `done` | Closed because the exit criteria are met and linked. | none (closed) | Reopen with new evidence if the claim regresses. |

`triage` is not a resting state for this snapshot: all 15 issues have a
state below. Use it for new intake until the owner has read the issue.

## Labels

The filed issues already carry `theme:*`, `priority:*`, and `dimension:*`
labels. Keep them: they describe the work, not its current position.

| Label family | Values | Owner applies it? |
|---|---|---|
| `state:` | `state:triage`, `state:ready`, `state:in-progress`, `state:blocked`, `state:awaiting-evidence` | Yes; one per open issue. |
| `kind:` | `kind:bug`, `kind:feature`, `kind:security`, `kind:task` | Yes, when the issue form does not set it. |
| `theme:` | Existing theme labels | No change proposed. |
| `priority:` | Existing P0/P1/P2 labels | No change proposed; reprioritise only with a recorded reason. |
| `dimension:` | Existing scorecard-dimension labels | No change proposed. |

Do not encode an owner in a label. The GitHub assignee is the owner. An agent
may be a worker, but the assignee remains the accountable human.

## Owners

- Accountable owner for all 15 open issues: `@magnus919`.
- An implementing agent, when one is used, is a worker on a branch under the
  owner's direction. It is not the assignee and cannot close the issue.
- If the owner is unavailable, do not reassign to an agent or to a placeholder.
  Leave the issue open and unassigned-or-owner-assigned, record the proposed
  action, and follow [OWNERSHIP.md](OWNERSHIP.md#if-the-maintainer-is-unavailable).

## Closure evidence rules

An issue closes only when its **exit criteria** have observable evidence. A
merged pull request is not closure evidence by itself.

Every closure must link:

1. **The issue and the change.** The pull request or commit that addresses it,
   with the exact merged SHA.
2. **The exit-criterion evidence.** The command, test, artifact, receipt, tag,
   protection setting, or external record named by the issue's `Verification`
   field, together with the observed result.
3. **The review record.** The GA-1 review receipt on the exact reviewed head, or
   the recorded owner decision where a receipt is not the applicable control.
4. **The follow-up boundary.** Any residual gap, non-goal, or deferred part is
   named, with a new issue if it needs tracking.

Specific gates:

- **Tests and checks:** paste the exact command and result, not "tests pass."
  A focused test that does not exercise the changed behavior is not evidence.
- **Coverage, mutation, property, or fault-matrix claims:** link the generated
  report and its denominators, seeds, or case IDs.
- **Documentation and ownership:** run `python3 scripts/check_ownership.py` and
  the docs index/link/truth checks; link the zero-error output.
- **Release or supply chain:** link the tag, release assets, checksums, SBOM,
  provenance, and the verification command output. A merged workflow is not a
  release.
- **Security or credentials:** do not paste secrets, token prefixes, private
  repository content, or exploit details. Link the private advisory or the
  owner's recorded decision and state only the control outcome.
- **Quality, completeness, or replacement claims:** link human-adjudicated
  labels, the frozen corpus version, and denominators. Model agreement or a
  green transport test is not quality evidence.
- **Blocked closure:** if the exit criterion cannot be met, close as
  "not planned" only with the owner's reason and the affected A− gate named.
  Do not mark an unmet criterion as met.

The checker validates that the table below stays consistent with the open-issue
snapshot and the filed-issue map. It cannot validate the truth of a closure
record; a reviewer must do that.

## Mapping for the 15 open issues

Existing labels stay. "Labels to add" is the applied state label; `kind:*` is
added only if the issue form or the owner later assigns one. "Next action" is
the concrete move, not a schedule.

<!-- backlog-table:start -->
| Issue | ID | Title | Owner | State | Labels to add | Next action / blocker |
|---|---|---|---|---|---|---|
| #239 | RC-1 | [RC-1] Separate the retrieval envelope from the model-output budget | `@magnus919` | `ready` | `state:ready` | No hard dependency. Start with the dedicated retrieval limit and the 40 KB symbol-at-end fixture. |
| #240 | RC-2 | [RC-2] Replace prefix retrieval with a retrieval compiler | `@magnus919` | `blocked` | `state:blocked` | Blocked by #239; the frozen corpus is now available for measurement. |
| #241 | RC-3 | [RC-3] Make completeness measurable and regression-gated | `@magnus919` | `ready` | `state:ready` | Frozen corpus available; publish the baseline and gate. |
| #243 | QM-2 | [QM-2] Establish the human labeling and adjudication protocol | `@magnus919` | `ready` | `state:ready` | Protocol, rubric, and empty pilot exist; owner accepted synthetic model-teacher adjudication (ADR 0010) and human packets are optional. Needs a real synthetic teacher run with retained provenance and a non-empty validated packet set. |
| #244 | QM-3 | [QM-3] Run evaluation continuously and publish scorecards | `@magnus919` | `blocked` | `state:blocked` | Blocked by #241 and #243; two-arm scorecard/gate infrastructure exists, but real predictions, real synthetic labels, and an accepted baseline remain. |
| #245 | QM-4 | [QM-4] Measure the incumbent on identical snapshots | `@magnus919` | `blocked` | `state:blocked` | Blocked by #243. |
| #246 | QM-5 | [QM-5] Integrate adversarial and injection evaluation | `@magnus919` | `blocked` | `state:blocked` | Blocked by #243. |
| #252 | VD-2 | [VD-2] Add property, mutation, and fault-injection testing | `@magnus919` | `ready` | `state:ready` | Dependencies #247 and #251 are closed. Start with property tests and the fault matrix; mutation score needs an owner-set threshold. |
| #253 | VD-3 | [VD-3] Isolate historical pins in a compatibility suite | `@magnus919` | `ready` | `state:ready` | Dependency #248 is closed. The compatibility marker exists; the refresh tool and manifest work remain. |
| #254 | VD-4 | [VD-4] Enforce static analysis, typing, and formatting | `@magnus919` | `ready` | `state:ready` | Dependency #250 is closed. Expand lint/format/types with a ratchet; a whole-repo reformat is separate from the gate. |
| #258 | SE-4 | [SE-4] Prove effect-boundary behavior with a fault matrix and canary | `@magnus919` | `ready` | `state:ready` | Dependencies #255, #256, #247 are closed. Build the parameterized matrix; live publication stays disabled. |
| #261 | RS-3 | [RS-3] Produce SBOM, provenance, and reproducible artifacts | `@magnus919` | `awaiting-evidence` | `state:awaiting-evidence` | PR #296 merged SBOM/provenance/reproducibility tooling, but provenance is unsigned and no release carries it. Needs #260's real release plus signed attestation or an explicitly accepted unsigned limit. |
| #262 | RS-4 | [RS-4] Lock dependencies and publish the package contract | `@magnus919` | `ready` | `state:ready` | Dependency #259 is closed. The package has no runtime dependencies; lock and publish the contract deliberately. |
| #269 | GA-1 | [GA-1] Require recorded review evidence for every merge | `@magnus919` | `blocked` | `state:blocked` | Protocol and receipt check merged in PR #293, but branch protection does not require the check. Owner action: protect `main` and require `Review receipt` plus the other required jobs. |
| #270 | GA-2 | [GA-2] Record decisions with named owners and evidence | `@magnus919` | `awaiting-evidence` | `state:awaiting-evidence` | PR #295 merged the ADR index and structural check. PR-diff enforcement is now active as the `Decision record links` check: read-only GitHub API changed-file list, and for a safety-invariant path a non-empty `decision_records` receipt list whose records are indexed and Accepted on the base revision. Exit criteria still need branch protection: owner action to mark `Review receipt` and `Decision record links` required on `main`, plus a sampled change traced to its record. |
<!-- backlog-table:end -->

Summary: **8 `ready`, 5 `blocked`, 2 `awaiting-evidence`, 0 `in-progress`**;
15 open issues, all with one owner and one state.

## Board and issue-template configuration

GitHub Projects is not configured for this repository, and no file-based board
format is in use. Do not imply that a board exists. The checked-in table above
is the reviewable board state; when a GitHub Project is created later, its
columns should map one-to-one to the five open states. The project, labels, and
assignees are applied by the owner or root, not by a worker.

Issue forms are file-based under `.github/ISSUE_TEMPLATE/`:

- `bug_report.yml` — reproducible defect with evidence and affected revision.
- `feature_request.yml` — problem, scope, exit criterion, owner impact.
- `triage.yml` — generic structured intake that requires the evidence and exit
  criteria this backlog expects.
- `config.yml` — disables blank issues and points security reports to the
  private-reporting guidance in [SECURITY.md](../SECURITY.md). There is no public
  security issue form; do not ask for exploit details in a public issue.

A new issue is not "triaged" because a template was used. It is triaged when it
has an owner, one state, and observable exit criteria.

## Applied state (owner/root action)

The root applied the `state:*` labels and `@magnus919` assignee to every open
issue on 2026-11-02. The commands below are retained for new intake and for
re-applying a state after a refresh.

```sh
# Create the state labels once.
for state in triage ready in-progress blocked awaiting-evidence; do
  gh label create "state:${state}" --repo groktopus/codereview \
    --description "Backlog triage state: ${state}" --color ededed
done

# Example: apply one row. Repeat only for the rows the owner accepts.
gh issue edit 239 --repo groktopus/codereview \
  --add-assignee magnus919 --add-label state:ready
```

Root must also decide whether to add `kind:*` labels or rely on the issue forms.
No issue is closed by applying a state label.

## Consistency and maintenance

- Update [`backlog-open-issues.json`](backlog-open-issues.json) with the same
  read-only `gh issue list` query whenever the open set changes.
- Update the table and the summary in the same change.
- A state change needs a one-line reason in the issue or the linked pull
  request; a silent relabel is not triage.
- `python3 scripts/check_ownership.py` verifies that the table has exactly the
  snapshot's open numbers, one owner and one valid state per row, IDs that match
  [issues/FILED.md](issues/FILED.md), and no duplicate or missing issue.
