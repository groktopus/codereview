# Decision records (ADR index)

This is the index for decisions taken in this repository. It records the
decision, its owner and authority, the evidence that supports it, and when it
must be revisited. It is authoritative for `docs/adr/`; the older proposals in
[`docs/design/adrs/`](../design/adrs/README.md) are reconciled by reference and
are not rewritten or renumbered.

An **accepted** record means a decision authority and evidence are recorded. It
does not mean every consequence is implemented or that quality, release, or
replacement claims are established. A **proposed** record is a recommendation,
not permission. Do not invent an owner or promote a proposal to accepted without
recorded decision authority.

## Status vocabulary

The Status column is the record's lifecycle: `Proposed` → `Accepted`, with
`Deprecated` or `Superseded` for later states and `Rejected` as a terminal
alternative. Accepted records remain accepted until a linked successor changes
them; the original rationale is retained.

| Status | Meaning |
|---|---|
| Proposed | Recorded recommendation with no recorded acceptance. It does not authorize a change. |
| Accepted | Decision authority is recorded. Implementation evidence may still be partial or absent; the record's evidence section says which. |
| Rejected | Considered and deliberately not adopted. The reason is retained. |
| Deprecated | Previously accepted but no longer recommended; no direct successor. |
| Superseded | Replaced by a linked later record. History is retained. |

## Decisions

| ID | Record | Status | Owner | Date | Evidence |
|---|---|---|---|---|---|
| 0001 | [Post-CA-2 feature budget](0001-post-ca2-feature-budget.md) | Accepted | Repository owner (`@magnus919`) | 2026-11-01 | PR [#291](https://github.com/groktopus/codereview/pull/291); [public-surface.json](../public-surface.json); [surface test](../../tests/test_surface_consolidation.py) |
| 0002 | [Production architecture: one modular core with typed deterministic stages](0002-production-architecture.md) | Accepted | Repository maintainers (`@magnus919`) | 2026-11-01 | PRs [#277](https://github.com/groktopus/codereview/pull/277), [#284](https://github.com/groktopus/codereview/pull/284); [ARCHITECTURE.md](../ARCHITECTURE.md) |
| 0003 | [Transport and credential policy: HTTPS or exact loopback](0003-transport-security-policy.md) | Accepted | Repository maintainers (`@magnus919`) | 2026-11-01 | PR [#275](https://github.com/groktopus/codereview/pull/275); [providers.py](../../src/pr_review_harness/providers.py); [transport tests](../../tests/test_providers.py) |
| 0004 | [Publication authorization: READ_ONLY by default, live effects disabled](0004-publication-authorization.md) | Accepted | Repository owner (`@magnus919`) | 2026-09-29 | [AGENTS.md](../../AGENTS.md); [PUBLICATION-READINESS.md](../PUBLICATION-READINESS.md); [STATUS.md](../STATUS.md) |
| 0005 | [Model and provider boundary: configured providers only, no new providers](0005-provider-boundary.md) | Accepted | Repository owner (`@magnus919`) | 2026-09-26 | [AGENTS.md](../../AGENTS.md); [TEST-MODEL-POLICY.md](../TEST-MODEL-POLICY.md); [providers.py](../../src/pr_review_harness/providers.py) |
| 0006 | [Evaluation gates: no quality or replacement claim without independent evidence](0006-evaluation-gates.md) | Accepted | Repository owner (`@magnus919`) | 2026-11-01 | [STATUS.md](../STATUS.md); [EVALUATION-TOOLKIT.md](../EVALUATION-TOOLKIT.md); [test_evaluation.py](../../tests/test_evaluation.py) |
| 0007 | [License: MIT for original code and documentation](0007-license.md) | Accepted | Repository owner (`@magnus919`) | 2026-11-01 | PR [#292](https://github.com/groktopus/codereview/pull/292); [LICENSE](../../LICENSE); [pyproject.toml](../../pyproject.toml) |
| 0008 | [Release and version policy: SemVer plus independent contract versions](0008-release-version-policy.md) | Accepted | Repository maintainers (`@magnus919`) | 2026-11-02 | PR [#294](https://github.com/groktopus/codereview/pull/294); [VERSIONING.md](../VERSIONING.md); [RELEASING.md](../RELEASING.md) |
| 0009 | [Ownership and second-review path](0009-ownership-and-second-review.md) | Accepted | Repository owner (`@magnus919`) | 2026-11-02 | [issue #271](https://github.com/groktopus/codereview/issues/271), PR #297, CODEOWNERS, OWNERSHIP/BACKLOG |


The post-CA-2 budget (0001) is accepted as a one-time migration exception:
current source growth must still update the measured surface and cannot use
unused budget as a general growth allowance.

## Decisions that remain open

These are intentionally not "accepted by implication" from a merged feature:

- **Production model selection.** ADR 0005 records the provider boundary but not
  a production model. `docs/TEST-MODEL-POLICY.md` says the model is not yet
  selected; `docs/RELEASE-PLAN.md` states `openai/gpt-6-luna` **is the selected
  production inference model**, while `docs/TEST-MODEL-POLICY.md` says the
  production model is unselected. No dated owner decision resolves the conflict;
  it is treated as unresolved rather than downgraded to a candidate. The
  conflict is documented in ADR 0005 and needs an owner decision plus
  model-specific quality evidence.
- **Publication activation.** ADR 0004 keeps the CLI and central route
  disabled. Enabling a route needs a separate owner decision, the readiness
  gates, and an `UNKNOWN` reconciliation owner.
- **Evaluation thresholds and corpus.** ADR 0006 records the no-claim rule and
  the unmet gate. The numeric targets and corpus in the quality-measurement
  backlog (issues #242–#246) remain proposals.
- **Service decomposition.** ADR 0002 keeps one modular deployment. No evidence
  currently justifies a queue/worker or hosted-service boundary.

## Safety-invariant and external-effect changes

**Enforcement is active.** A pull request that changes a safety invariant or an
external effect requires a decision record, and CI now checks the pull request
diff for it. The machine-readable surface list is
[safety-invariants.json](safety-invariants.json). It covers the deterministic
control plane, no target-code execution, credential transport, provider
selection, budget/surface limits, publication authorization, and the
quality-claim gate. Each entry is an exact path, a directory path ending in `/`,
or a glob (`*`, `?`, `**`, `[...]`). The manifest file itself is always a
protected path, and a renamed or deleted protected path counts as a change.

Two checks apply:

1. `python scripts/check_decision_records.py` is the structural gate. It
   verifies that the index covers every record, required fields and statuses are
   valid, every safety-invariant surface maps to an accepted record, and the
   process is documented in `CONTRIBUTING.md` and the pull request template.
2. The `Decision record links` workflow
   ([`scripts/check_decision_record_links.py`](../../scripts/check_decision_record_links.py))
   is the diff gate. For a pull request it reads the changed-file list from the
   read-only GitHub API, compares it with `safety-invariants.json` on the pull
   request base revision, and — when a protected path changed — requires a
   non-empty `decision_records` list in the review receipt. Each cited record
   (ID, `docs/adr/NNNN-*.md` path, or link to that file) must already exist on
   the base revision, be listed in the table above, and have Status `Accepted`.
   It fails closed when the event, changed-file list, base content, or receipt is
   missing or unusable.

Because the check reads the base revision, a record added by the same pull
request does not satisfy it. Land the accepted record first (or amend an
existing record) in its own pull request, then cite it from the change that
depends on it. The field contract, failure codes, and enforcement limits are in
[review evidence](../REVIEW-EVIDENCE.md).

Neither check judges whether the evidence is sufficient or the decision was
wise. Both fail closed, but **branch protection is not enabled**: the checks run
and report, and they are not yet required status checks, so a failing result is
visible and recorded but GitHub does not by itself block the merge. The owner
action is recorded in [review evidence](../REVIEW-EVIDENCE.md#enforcement-limits);
issue [#270](https://github.com/groktopus/codereview/issues/270) stays open until
the owner marks the checks required.

## Legacy design ADRs (proposed, not rewritten)

`docs/design/adrs/` contains the earlier design proposals. They are retained at
their original identifiers and locations. None records an acceptance decision;
the accepted production decisions are the records above.

| Legacy ID | Record | Reported status | Reconciliation |
|---|---|---|---|
| ADR-001 | [Keep a reusable modular core behind CLI and Actions adapters](../design/adrs/001-modular-core-and-adapters.md) | Proposed; acceptance not recorded | The modular-core intent is realized and recorded as accepted in [ADR 0002](0002-production-architecture.md) for the production surface. The broader design proposal remains unaccepted. |
| ADR-002 | [Keep review workflow and disposition deterministic](../design/adrs/002-deterministic-review-controller.md) | Proposed; acceptance not recorded | The deterministic controller and typed stages are recorded in [ADR 0002](0002-production-architecture.md). The design-scope proposal remains unaccepted. |
| ADR-003 | [Persist run evidence and make recovery and effects idempotent](../design/adrs/003-durable-ledger-and-idempotent-effects.md) | Proposed; storage shape superseded by the current stateless direction | Retained for recovery and idempotency rationale. The current stateless direction and publication boundary are recorded in [ADR 0002](0002-production-architecture.md) and [ADR 0004](0004-publication-authorization.md); the durable-ledger storage proposal is not adopted. |
| ADR-004 | [Separate credentialed analysis from untrusted head-code execution](../design/adrs/004-isolate-untrusted-pr-execution.md) | Proposed; acceptance not recorded | The implemented trust boundary is recorded in [ADR 0002](0002-production-architecture.md), [ADR 0003](0003-transport-security-policy.md), and [ADR 0004](0004-publication-authorization.md). The design proposal remains unaccepted as a whole. |

## Adding or changing a record

1. Use the next four-digit identifier. Do not renumber or delete an existing
   record; supersede it and link both directions.
2. Fill every required field: status, date, owner, decision authority, scope,
   evidence, and reversal/expiry.
3. State alternatives and consequences. Distinguish proposed from accepted, and
   observed evidence from planned checks.
4. Add the record to the table above, merge it, and then cite its ID from the
   PR that changes the behavior (`decision_records` in the review receipt).
5. For a safety-invariant or external-effect change, update
   `safety-invariants.json` if the surface list changes. A manifest change is
   itself protected, so it also needs an accepted record cited in the receipt.
6. Keep a record's Status and the table row consistent; the structural check
   rejects a mismatch, and the diff check reads both.
