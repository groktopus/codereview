# Ownership, review authority, and access record (GA-3)

Status: **current governance record for issue
[#271](https://github.com/groktopus/codereview/issues/271) (GA-3)**. It records
who is accountable, what another reviewer may and may not do, who owns
publication incidents and credentials, and what happens when the single
maintainer is unavailable. It does not create a second human owner, a second
administrator, or an on-call rotation.

The repository state and issue snapshot behind this record are dated
2026-11-02 on branch base `5becb81`. Counts and states can change; the checked
backlog snapshot is [`backlog-open-issues.json`](backlog-open-issues.json), and
the applied issue mapping is in [`BACKLOG.md`](BACKLOG.md).

## Bus factor and authority

**Bus factor is 1.** The repository has one recorded accountable human,
`@magnus919`, and no second human with repository administration, merge,
release, or credential access. That is the honest current state, not a temporary
label:

- Every path in [`.github/CODEOWNERS`](../.github/CODEOWNERS) resolves to
  `@magnus919`; several paths are grouped so that a sensitive change cannot
  disappear behind the default `*` rule.
- No branch-protection, release, credential-rotation, or incident authority is
  delegated to a named second person in this repository.
- An agent reviewer can provide independent review evidence under the GA-1
  protocol, but an agent is not an owner, cannot stand in for a human for
  effects or access, and cannot merge.
- Losing access to the `@magnus919` account means merges, releases, credential
  rotation, and incident rollback stop until that account or the GitHub
  organization is recovered. The project remains readable and testable; it is
  not operable for effects.

This record reduces ambiguity. It does **not** reduce the bus factor from 1.
No document in this repository should describe an agent, a shared mailbox, or a
team alias as a human backup unless a real named person accepts that role and
the acceptance is linked here.

## Ownership map

| Surface | Paths (CODEOWNERS group) | Accountable owner | Second human |
|---|---|---|---|
| Core review path | `src/pr_review_harness/` core modules (`core-review`) | `@magnus919` | None recorded |
| Publication and external effects | publisher, runtime, receipts, actions bridges, templates (`publication-effects`) | `@magnus919` | None recorded |
| Security and credentials | provider transport, credential providers, private capture, security policy (`security-credentials`) | `@magnus919` | None recorded |
| Workflows and automation | `.github/workflows/`, CodeQL, CODEOWNERS (`workflows`) | `@magnus919` | None recorded |
| Documentation and contributor policy | `docs/`, README, CONTRIBUTING, templates (`docs`) | `@magnus919` | None recorded |
| Release and supply chain | version, license, changelog, packaging, release workflow and evidence (`release`) | `@magnus919` | None recorded |

The groups are review-routing labels, not separate teams. One person owns all
six. The value is that a pull request changing a credential provider, a release
workflow, or a publication template is visibly sensitive instead of relying on
the default rule.

## Module map

This table is the human-readable owner map for the 40 production modules in
[`public-surface.json`](public-surface.json). The module names are the
`production_modules` entries; the group must match the effective CODEOWNERS
group for `src/pr_review_harness/<module>`. `scripts/check_ownership.py`
enforces the complete, duplicate-free partition and the effective group.

| Group | Modules | Accountable owner |
|---|---|---|
| `core-review` | `__init__.py`, `__main__.py`, `budget.py`, `checks.py`, `claim_assessment.py`, `claim_reconciliation.py`, `claim_transport.py`, `cli.py`, `completeness.py`, `context_targets.py`, `contract_registry.py`, `contracts.py`, `cost.py`, `current_source_capture.py`, `dependency_context.py`, `engine.py`, `errors.py`, `evidence.py`, `github.py`, `metrics.py`, `planner.py`, `reconcile.py`, `recovery_inputs.py`, `report.py`, `review_stages.py`, `review_state.py`, `snapshot.py`, `source_audit.py`, `waiver.py` | `@magnus919` |
| `publication-effects` | `actions_publication.py`, `actions_runtime.py`, `artifact_intake.py`, `external_effect_observer.py`, `protected_publication_runtime.py`, `publication_receipts.py`, `publisher.py` | `@magnus919` |
| `security-credentials` | `github_actions_credentials.py`, `github_app_canary.py`, `github_app_credentials.py`, `private_capture.py`, `providers.py` | `@magnus919` |

Module classification follows [ARCHITECTURE.md](ARCHITECTURE.md). New production
modules must be added to `public-surface.json`, this table, and CODEOWNERS in
the same change; a module that appears only under `*` is unowned for review
routing and fails the check.

## Second-reviewer path

### Human reviewer, when available

If a human other than the author is available, that human is the preferred
second reviewer. They review the exact head, write the GA-1 receipt with
`reviewer.kind: "human"`, and record self-review honestly. No such human is
currently recorded. Do not claim one exists, and do not label an agent receipt
as human review.

### Documented agent protocol

When no second human is available, an independent read-only agent may perform
the second review. This is the path that has actually been used.

**Protocol**

1. The reviewer is a separate agent identity from the author, for example
   `independent-review-agent/<change-slug>`. It must not be the authoring
   agent under a different label.
2. It works read-only: no edits, no commits, no credential use, no target-code
   execution, and no live effect. It reviews the full diff at the exact
   40-character head SHA, runs the focused checks, and probes failure cases
   where feasible.
3. It writes a `review-receipt.v1` block in the pull request body with
   `reviewer.kind: "agent"`, a non-empty `reviewer.protocol` naming the harness,
   model, and review protocol, an independence statement, the scope actually
   examined, a `CLEAR` or `NOT CLEAR` verdict, and evidence links or exact
   commands. The complete field contract and limits are in
   [REVIEW-EVIDENCE.md](REVIEW-EVIDENCE.md).
4. The receipt is bound to the reviewed head. A new commit invalidates it until
   the reviewer re-reviews and updates `reviewed_sha`.
5. The accountable owner remains the merger and remains accountable for the
   change. The owner verifies the required checks at the exact reviewed head
   and performs the post-merge verification described in the receipt.

**What agent review may cover**

- Code, tests, docs, and structural checks in the reviewed diff.
- Read-only reproduction of focused test results.
- A `NOT CLEAR` verdict that blocks the merge.
- Advisory review of workflow, release, publication, credential, or ownership
  changes, with the owner explicitly deciding whether to accept it.

**Limits of agent authority**

- An agent cannot approve or perform a live publication, release, tag,
  credential rotation, repository-setting change, branch-protection change, or
  incident rollback. Those require the accountable human.
- An agent cannot merge, cannot waive a required check, and cannot convert
  `NOT CLEAR` into `CLEAR`.
- An agent review does not satisfy a policy that requires a human. It satisfies
  the GA-1 review-evidence protocol only when the protocol and identity are
  recorded.
- The receipt is editable text in the pull request body. CI validates its
  shape, not the reviewer's identity, independence, evidence, or truth. See
  [REVIEW-EVIDENCE.md](REVIEW-EVIDENCE.md) for enforcement limits.
- For changes to CODEOWNERS, this document, credential/security paths, release
  workflows, or publication effects, agent review is **advisory only**; a
  recorded owner decision is also required before merge. The owner action is
  listed in the pull request, not implied by a green check.

**Use evidence**

The agent path has been used, with independent read-only reviewers distinct
from the author:

- [PR #295](https://github.com/groktopus/codereview/pull/295) (GA-2, issue
  #270): `independent-review-agent/ga2`, verdict `CLEAR`, receipt in the pull
  request body.
- [PR #296](https://github.com/groktopus/codereview/pull/296) (RS-3, issue
  #261): `independent-review-agent/rs3`, verdict `CLEAR`, receipt in the pull
  request body.
- [PR #293](https://github.com/groktopus/codereview/pull/293) (GA-1, issue
  #269) used the same agent-review path for the receipt protocol itself.

These are agent reviews, not human reviews. The sampled PR for GA-3 exit
verification is #295 because its receipt and independence statement are in the
merged record and its scope is directly adjacent governance work.

## Publication incident and rollback ownership

Publication remains **disabled by default** under
[ADR 0004](adr/0004-publication-authorization.md) and
[PUBLICATION-READINESS.md](PUBLICATION-READINESS.md). This section assigns
responsibility if a route is ever enabled or if an effect is observed; it does
not authorize enabling publication.

| Responsibility | Owner | Agent may |
|---|---|---|
| Incident commander for a publication or external-effect incident | `@magnus919` | Detect, collect read-only evidence, prepare a timeline, propose a rollback plan |
| Rollback decision and execution | `@magnus919` | Prepare commands and a dry-run; never execute the live effect |
| Reconciliation of an ambiguous submit (unknown whether the effect landed) | `@magnus919` | Read the published history and receipts; never re-submit |
| Disclosure to the affected repository or user | `@magnus919` | Draft the disclosure; never send it |
| Post-incident evidence and follow-up issues | `@magnus919` (may delegate analysis to an agent) | File a draft issue body for the owner to review; do not mutate external trackers |

Incident sequence:

1. **Stop the route.** Disable the publication workflow or revoke the token that
   can perform the effect. Do not retry while the outcome is unknown.
2. **Preserve evidence.** Keep the run IDs, publication receipts, artifact
   hashes, and request/response summaries. Do not edit or delete receipts.
3. **Reconcile before retrying.** Determine from provider history whether the
   review, comment, or message landed. An ambiguous submit is `UNKNOWN`, not a
   failure and not a success.
4. **Roll back deliberately.** Remove or supersede an unintended review or
   comment only with the owner's recorded decision. Never run an unreviewed
   bulk delete.
5. **Record.** Link the incident, the stopped route, the reconciled outcome, the
   rollback (if any), and the follow-up issue in the merge or incident record.
   Disclosure follows [SECURITY.md](../SECURITY.md) and the owner's decision.

If the owner is unavailable, the route stays disabled and the incident stays
open. An agent must not improvise a rollback or a retry to "restore service."

## Credential and access ownership

`@magnus919` is the sole recorded holder and administrator of:

- the GitHub repository and organization settings, including branch
  protection, required checks, actions permissions, and environment secrets;
- the GitHub App registration and private key used by the credential provider,
  and the installation-scoped Actions token path;
- provider credentials used through `LLM_BASE_URL`/`JEV_BASE_URL` and the trusted
  environment variables, which are configuration inputs and are never written
  to prompts, logs, reports, fixtures, or this document;
- release signing/tagging authority and the release workflow's `contents: write`
  permission.

No shared vault, sealed escrow, second administrator, or break-glass account is
recorded. The credential boundary and transport rules are in
[ADR 0003](adr/0003-transport-security-policy.md),
[DEPLOYMENT-CONFIGURATION.md](DEPLOYMENT-CONFIGURATION.md), and
[GITHUB-APP-CREDENTIAL-PROVIDER.md](GITHUB-APP-CREDENTIAL-PROVIDER.md).

### Rotation

Rotate a credential when it is suspected exposed, when its scope or workflow
changes, or when the provider requires it. The owner performs the rotation; an
agent may prepare the checklist but must not handle the secret value.

1. Create the replacement credential with the least scope the workflow needs.
2. Store it in the trusted secret store; never put it in the repository, a pull
   request, a test fixture, or a log.
3. Run the read-only canary or the smallest safe check that exercises the new
   credential.
4. Revoke the old credential at the provider, not only in GitHub.
5. Record the date, credential class, rotation reason, and verification result
   in the operational log. Do not record the secret, a token prefix, or a value
   that can identify it.

### Recovery

- **Repository access lost:** recover the `@magnus919` account or the GitHub
  organization through GitHub's account-recovery process. Until then, no merges,
  releases, or setting changes are possible. Do not create a parallel repository
  or a new organization as an emergency workaround.
- **Provider key lost or revoked:** the provider account owner must issue a new
  key. Existing CI fails closed. Do not enable a fallback provider; ADR 0005
  limits providers to the configured ones.
- **GitHub App key lost:** create a new private key on the App registration,
  replace the secret, verify the installation, then revoke the old key. An agent
  cannot perform this action.
- **Suspected compromise:** stop publication and release workflows, preserve
  logs and receipts, rotate the affected credential, and follow
  [SECURITY.md](../SECURITY.md). Do not publish exploit details in a public
  issue.

## If the maintainer is unavailable

The project does not have a designated successor. The honest consequence is a
freeze on authority-bearing actions, not an improvised transfer:

| Action | If `@magnus919` is unavailable |
|---|---|
| Read code, docs, issues, and evidence | Allowed. |
| Run tests and read-only checks | Allowed within the existing bounded test authority. |
| Open issues or pull requests with evidence | Allowed; they remain unmerged proposals. |
| Triage, label, or close issues | Not allowed without recorded delegated authority. Prepare the proposed mapping instead. |
| Merge to `main` | Blocked. Do not merge on the owner's behalf without a prior, recorded delegation. |
| Tag, release, sign, or publish artifacts | Blocked. |
| Enable, retry, or roll back a live publication effect | Blocked; keep the route disabled and the incident open. |
| Rotate, create, or revoke credentials; change repository settings | Blocked. |
| Accept a decision record as accepted | Blocked; a proposed record is not approval. |

Continuity work that is safe and useful: preserve run evidence, reproduce
failures, write failing tests, draft patches, and update the backlog with
evidence. When the owner returns, re-check every reviewed head, because a
receipt bound to an old head is stale.

## Backlog triage

Issue intake, states, labels, owners, closure-evidence rules, and the applied
mapping for the current 7 open issues are in [BACKLOG.md](BACKLOG.md). The
short version: every open issue must have an accountable owner and exactly one
current state; an issue closes only with observable evidence for its exit
criteria, not because a pull request merged.

## Verification

```sh
python3 scripts/check_ownership.py
python3 scripts/check_docs_index.py
python3 scripts/check_relative_links.py
python3 scripts/check_docs_truth.py
python3 -m pytest -q tests/test_ownership.py
```

The ownership check verifies CODEOWNERS coverage against the public module map,
the required sections of this document, and the backlog table's open issue
numbers against the checked snapshot and the filed-issue map. It is a
structural check: it cannot prove that a reviewer was independent, that a
credential is stored safely, or that the owner is available.
