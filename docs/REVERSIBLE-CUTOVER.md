# Reversible Droid cutover qualification

**Status: planning package only.** The current decision is **DEFER**: this harness is not accepted as a Droid replacement, publication remains disabled, and no cutover is authorized. This document and [`../templates/cutover-qualification.json`](../templates/cutover-qualification.json) define a reviewable evidence packet; completing the form does not itself authorize a change.

The package preserves the original 39 acceptance criteria, 12 nonfunctional requirements, and six delivery milestones. It is aligned with [NFR-011](design/SPEC.md), [EVALUATION.md](design/EVALUATION.md), [model-only-shadow-audit-v1.md](model-only-shadow-audit-v1.md), and [PRODUCTION-DELIVERY.md](PRODUCTION-DELIVERY.md). The existing evidence still records incomplete operational milestones and missing replacement evidence. One successful run, green CI, model agreement, or exact-head Droid comments cannot satisfy this packet.

## Decision boundaries

1. **Read-only advisory shadow:** may be considered only after a named owner authorizes a bounded run while Droid remains authoritative. Every selected case and role must have a reconciled terminal state; required source and deterministic checks must be explicit; stale, partial, failed, or unknown required evidence must never appear current or complete. There must be no unauthorized effects, deterministic safety/control violations, or owner-selected operating-limit breaches. This establishes operational completeness only.
2. **Advisory publication canary:** is a separate decision and requires its own authorization, exact-head recheck, least-privilege writer, and exercised duplicate, replay, and ambiguous-submit recovery. It must remain non-blocking and cannot affect merge eligibility. A shadow qualification does not authorize publication.
3. **Reversible cutover:** requires repeated normal-workflow shadows on a frozen, owner-selected natural sample, a second project/profile, complete role and deterministic-check accounting, recorded cost/latency/abstention/disagreement distributions, no unresolved deterministic-control violations, and an observed rollback rehearsal. The named owner must explicitly accept that semantic accuracy and error rates remain unknown. Keep the incumbent available throughout the owner-selected rollback window.

Human labels are unavailable. No field in this packet turns `model_teacher` observations, model agreement, a Jev score, issue links, or an unadjudicated candidate into ground truth. Do not claim accuracy, calibration, precision, recall, or quality-based adoption. If independent labels become available later, they belong in a separately versioned evaluation record with provenance, adjudication, denominators, error/abstention analysis, and owner-selected quality bounds.

## Required qualification packet

Fill one [`cutover-qualification.json`](../templates/cutover-qualification.json) for the proposed candidate and attach immutable evidence references. Use `UNKNOWN`, `NOT_RUN`, `NOT_APPLICABLE`, or `MISSING` where appropriate; do not turn missing evidence into a pass. The operator and accountable owner must review the packet before any stage change.

Record and preserve:

- The exact harness source, installed artifact, profile, model/provider configuration identity, prompt/rubric, limits, repository, case-set and split identities. Identify every run and every artifact by immutable ID/hash and location; retain failed, partial, abstained, unavailable, and zero-candidate outcomes.
- A preselected natural-sample frame and observation window, plus a separately identified second project/profile. The owner selects the sample size, window, concurrency, spend, latency, and incomplete/abstention bounds before dispatch. Leave them unset until selected; this package supplies no numeric thresholds.
- For every case and role, one terminal status and reconciliation to its output. For every required deterministic control, record `PASS`, `FAIL`, `UNKNOWN`, `NOT_RUN`, or justified `NOT_APPLICABLE`, with source and evidence. Any failed or unknown hard control blocks qualification.
- Per-stage elapsed time, calls/retries, resource use, known spend, and explicitly `UNKNOWN` spend when billing is unavailable. Report distributions and denominators; a single observation is not a distribution.
- Model-role disagreements and abstentions as advisory observations. Record `reviewer_kind: model_teacher` for model-produced screens; missing reviewer provenance is unknown, never human.
- A stop decision, named on-call/escalation owner, incumbent continuity plan, rollback trigger, recovery objective selected by the owner, and a witnessed rollback rehearsal with timestamps and evidence.
- The precise harness and Droid control changes proposed, who can perform and verify each action, and the exact rollback instructions from the systems’ current operator documentation. Do not invent Droid commands or assume that disabling the harness disables Droid.

## Stop, rollback, and authority

Stop the shadow or cutover immediately if any deterministic safety/control invariant fails, any required outcome/check is unaccounted for, stale/partial/unknown evidence is presented as complete, an unauthorized side effect occurs, or an owner-selected operating bound is exceeded. Also stop if a required identity, artifact, or observation is missing or ambiguous. Preserve the evidence and hand control back to the incumbent workflow; do not retry an ambiguous write automatically.

Before any cutover, the operator must provide Droid’s actual enable/disable and restoration controls, their authorized owner, the prior configuration snapshot, and the recovery procedure. The repository evidence does **not** identify a verified Droid cutover switch or rollback command. These remain required operator inputs.

Known harness-side controls, which do not control Droid, are:

- Analysis workflow: `REVIEW_ANALYSIS_ENABLED` is the documented disable control in [OPERATIONS.md](OPERATIONS.md). Verify its current workflow semantics and effective value in the target repository before relying on it.
- Review publication: [`.github/workflows/pr-publish.yml`](../.github/workflows/pr-publish.yml) currently has a job guarded by the literal `false && vars.PR_REVIEW_PUBLICATION_ENABLED == 'true'`; setting the repository variable cannot enable that job. The protected runtime also returns `DISABLED` when the protected policy’s `enabled` field is false. Do not treat either control as a Droid switch or as authorization to alter the workflow/policy.
- Deployment boundary: the central codereview-to-SlopSearX pilot is read-only. Publication requires a separately installed, same-repository target-local caller and publisher configuration. The target can use the protected workflow's repository-scoped `GITHUB_TOKEN` route or an explicitly configured GitHub App route; neither route is installed or qualified in SlopSearX today. Current names-only repository-secret metadata identifies LLM/Jev bindings, not writer credentials. Do not treat the central pilot’s admission or receipt as writer qualification, copy credentials across repositories, or inspect secret values to fill this packet.
- Incumbent: keep Droid enabled and authoritative during shadow and through the full rollback window. A proposed reversible cutover needs an owner-defined mechanism to route work back to Droid and evidence that the incumbent remained usable.

Do not perform production changes as part of qualification. Any later action must follow the repository’s state-modifying skill gate: confirm target, scope, and rollback path before the first mutation. This document grants no such authorization.

## Review and exit

The accountable owner records exactly one outcome: `DEFER`, `NO_GO`, `GO_WITH_CONDITIONS`, or `GO`. For this candidate, the current outcome remains `DEFER`. A `GO` for reversible cutover is an operational risk-acceptance decision only when semantic quality remains unknown; it must explicitly say so and must not be represented as quality-based adoption. Any exception must name the specific gap, accountable human approver, scope, and expiration; automated checks cannot grant an exception.

The packet is ready for owner review only when required evidence is linked and every missing/unknown item has an explicit disposition. A decision to defer is complete and valid when blockers, owners, and next evidence are recorded. Reopen the qualification if the source, profile, prompt/rubric, model, limits, case set, workflow, or authority surface changes.

## Six-milestone trace

Map packet evidence to the existing milestone names; do not mark a milestone complete merely because this form is filled.

| Existing milestone | Evidence this packet should link | Current boundary |
|---|---|---|
| Reliable operation | Exact-runtime bounded operation, failures, recovery, observed rollback | Prior finite recovery rehearsals are bounded evidence; current hosted interruption and live-provider recovery remain unverified in the cited status. |
| Relevant context | Exact source/profile/check identity and explicit retrieval/check outcomes | The latest ordinary v8 runs for PRs 475/476 record five required rows as `COMPLETE`; the browser check is `NOT_APPLICABLE` for that sampled dependency-change frame under configured applicability. This supersedes the v7 retrieval gap as the current context observation, but does not establish broad context completeness or applicability for other changes. Resolve every applicable check for the selected qualification sample. |
| Review judgment | Case/role outputs, anchors, disagreements, abstentions, denominators | Semantic quality remains unknown without independent adjudication. |
| Production reliability | Limits, packaging/runtime identity, support/escalation, cost and latency records | Cost may remain unknown; owner bounds must be chosen before the run. |
| GitHub delivery | Artifact integrity, freshness, effect/replay evidence, authority boundary | Publisher is hard-disabled; shadow qualification is not write-path evidence. |
| Replacement evidence | Same-snapshot baseline where available, second project/profile, owner decision | No quality-based replacement claim without the NFR-011 evidence; reversible operational cutover still requires explicit unknown-accuracy acceptance and rollback proof. |
