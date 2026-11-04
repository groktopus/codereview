<!-- Generated status evidence. Edit scripts/status-evidence.inputs.v1.json and regenerate. Do not edit by hand. -->
# Status evidence — generated from repository artifacts

> **Derived evidence, not an owner review.** This page is generated from checked-in
> artifacts at the observation revision. It does **not** refresh
> [STATUS.md](STATUS.md) or promote a `REPORTED` record into an observed fact.
> Evidence dates below are the dates the cited evidence was produced or recorded,
> not the date this page was generated or edited.

## Derived evidence

| Field | Value | Evidence | Evidence date |
|---|---|---|---|
| Current evidence revision | b9281b1 (full SHA in the evidence manifest) | [evidence manifest](../scripts/documentation-status-evidence.v1.json) | 2026-11-04 |
| Last verified run | NOT RECORDED — no retained review-run-summary.v1 artifact is checked in; CI test execution is not a review run | [run summary schema](../schemas/review-run-summary.v1.schema.json) | not applicable |
| Contract set | contract-registry.v1: 18 supported, 3 experimental, 17 deprecated, 6 archived | [contract registry](../src/pr_review_harness/contract_registry.json) | 2026-11-01 |
| Publication decision | harness CLI (`pr-review publish`): UNAVAILABLE — preview only; central `groktopus/codereview` Actions route: HARD-DISABLED; target-local `magnus919/SlopSearX` route: REPORTED ENABLED (DISPOSITION) | [publication decisions](#publication-decisions) | 2026-09-29 / 2026-10-11 |
| Status owner review | NO FINDINGS — still not an owner review | [STATUS.md](STATUS.md), [handoff manifest](../scripts/documentation-truth-evidence.v1.json) | 2026-11-04 |
| Evidence date | 2026-11-04 (observation revision commit date; not this page's edit date) | [evidence manifest](../scripts/documentation-status-evidence.v1.json) | 2026-11-04 |

## Publication decisions

Retained decision records. `REPORTED` means recorded by a dated document and not
re-observed for this block; `UNKNOWN` means no retained evidence establishes the
state. This block does not authorize publication.

| Route | State | Decision | Evidence class | Decision date | Evidence |
|---|---|---|---|---|---|
| harness CLI (`pr-review publish`) | UNAVAILABLE — preview only | NO-GO | REPORTED | 2026-09-29 | [PUBLICATION-READINESS.md](PUBLICATION-READINESS.md), [STATUS.md](STATUS.md), [cli.py](../src/pr_review_harness/cli.py) |
| central `groktopus/codereview` Actions route | HARD-DISABLED | NO-GO | REPORTED | 2026-09-29 | [PUBLICATION-READINESS.md](PUBLICATION-READINESS.md), [pr-publish.yml](../.github/workflows/pr-publish.yml) |
| target-local `magnus919/SlopSearX` route | REPORTED ENABLED (DISPOSITION) | 2026-10-11 cutover record | REPORTED | 2026-10-11 | [CURRENT-STATUS.md](CURRENT-STATUS.md), [STATUS.md](STATUS.md) |

The target-local route is recorded from target-repository documents. No target-side
artifact is retained in this repository, and its current state is not re-observed here.

## Contract set

The registry is [contract-registry.v1](../src/pr_review_harness/contract_registry.json) with 18 supported, 3 experimental, 17 deprecated, 6 archived.
The supported combination below is the registry's declared default surface; it is not
a quality or acceptance claim.

| Role | Contract | Status | Evidence |
|---|---|---|---|
| limits | ordinary-review-limits-v3 | supported | [registry](../src/pr_review_harness/contract_registry.json) |
| profile | codereview-native-v1-candidate | supported | [registry](../src/pr_review_harness/contract_registry.json) |
| review_contract | codereview-native-v1 | supported | [registry](../src/pr_review_harness/contract_registry.json) |

### Deprecated contracts (not current)

The registry marks these contracts deprecated. They are not current guidance; each
names its replacement where one exists. Archived contracts remain in the registry.

| Contract | Status | Replaced by | Evidence |
|---|---|---|---|
| legacy-v14 | deprecated | bounded-production-v16 | [registry](../src/pr_review_harness/contract_registry.json) |
| bounded-production-v16 | deprecated | bounded-production-v17 | [registry](../src/pr_review_harness/contract_registry.json) |
| bounded-production-v17 | deprecated | none | [registry](../src/pr_review_harness/contract_registry.json) |
| slopsearx-v14-jev-reconciliation-candidate | deprecated | slopsearx-v16-bounded-production-candidate | [registry](../src/pr_review_harness/contract_registry.json) |
| slopsearx-v16-bounded-production-candidate | deprecated | slopsearx-v17-context-target-manifest-candidate | [registry](../src/pr_review_harness/contract_registry.json) |
| slopsearx-v17-context-target-manifest-candidate | deprecated | none | [registry](../src/pr_review_harness/contract_registry.json) |
| slopsearx-v8-static-review-boundaries | deprecated | slopsearx-v14-jev-reconciliation-candidate | [registry](../src/pr_review_harness/contract_registry.json) |
| ordinary-review-limits-v2 | deprecated | ordinary-review-limits-v3 | [registry](../src/pr_review_harness/contract_registry.json) |
| claim-assessment.1 | deprecated | claim-assessment.2 | [registry](../src/pr_review_harness/contract_registry.json) |
| actions-receipt-v1 | deprecated | actions-receipt-v2 | [registry](../src/pr_review_harness/contract_registry.json) |
| specialist-findings.v3 | deprecated | specialist-findings.v4 | [registry](../src/pr_review_harness/contract_registry.json) |
| specialist-findings.v2 | deprecated | specialist-findings.v4 | [registry](../src/pr_review_harness/contract_registry.json) |
| specialist-findings.v1 | deprecated | specialist-findings.v4 | [registry](../src/pr_review_harness/contract_registry.json) |
| semantic-adjudication.v2 | deprecated | semantic-adjudication.v3 | [registry](../src/pr_review_harness/contract_registry.json) |
| semantic-adjudication.v1 | deprecated | semantic-adjudication.v3 | [registry](../src/pr_review_harness/contract_registry.json) |
| context-selection.v2 | deprecated | context-selection.v3 | [registry](../src/pr_review_harness/contract_registry.json) |
| context-selection.v1 | deprecated | context-selection.v3 | [registry](../src/pr_review_harness/contract_registry.json) |

## Status owner-review observation

The owner-reviewed status page remains a human record. This generated block records
its freshness verdict verbatim and does not rewrite it.

| Document | Reviewed revision | Evidence date | Checker verdict | Evidence |
|---|---|---|---|---|
| [docs/STATUS.md](STATUS.md) | b9281b1 | 2026-11-04 | NO FINDINGS | [handoff manifest](../scripts/documentation-truth-evidence.v1.json) |

No freshness findings at the checked-out head. This is still derived evidence, not an owner review.

## Historical snapshots (immutable; not current)

These records are retained unchanged and are not current state. The generator writes
only the status-evidence page and its manifest; it never rewrites historical evidence.

| Record | Label | Evidence |
|---|---|---|
| [docs/VERIFICATION.md](VERIFICATION.md) | 2026-09-26 specification-gap snapshot | [record](VERIFICATION.md) |
| [docs/history/checkpoints/DELIVERY-RESET-2026-09-29.md](history/checkpoints/DELIVERY-RESET-2026-09-29.md) | 2026-09-29 delivery reset checkpoint | [record](history/checkpoints/DELIVERY-RESET-2026-09-29.md) |
| [docs/history/checkpoints/pr464-shadow-run-2026-09-29.md](history/checkpoints/pr464-shadow-run-2026-09-29.md) | 2026-09-29 PR-464 shadow-run checkpoint | [record](history/checkpoints/pr464-shadow-run-2026-09-29.md) |
| [docs/history/evidence/CONTEXT-CANDIDATE-FAILURE.md](history/evidence/CONTEXT-CANDIDATE-FAILURE.md) | Context-selection candidate failure evidence | [record](history/evidence/CONTEXT-CANDIDATE-FAILURE.md) |

## Evidence links

- [Generator](../scripts/generate_status_evidence.py)
- [Inputs](../scripts/status-evidence.inputs.v1.json)
- [Evidence manifest](../scripts/documentation-status-evidence.v1.json)
- [tests/test_status_evidence.py](../tests/test_status_evidence.py)
- [scripts/check_docs_truth.py](../scripts/check_docs_truth.py)
- [scripts/documentation-truth-evidence.v1.json](../scripts/documentation-truth-evidence.v1.json)
- [.github/workflows/test.yml](../.github/workflows/test.yml)
- [src/pr_review_harness/contract_registry.json](../src/pr_review_harness/contract_registry.json)
- [docs/STATUS.md](STATUS.md)

---

Generated by [generate_status_evidence.py](../scripts/generate_status_evidence.py) from [status-evidence.inputs.v1.json](../scripts/status-evidence.inputs.v1.json). This page is not an owner review;
owner refresh of [STATUS.md](STATUS.md) remains a separate decision.
