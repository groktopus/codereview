# PR Review Harness — pilot evaluation plan

**Status:** Evaluation methodology, not a performance claim or release gate. The original design preceded implementation; the harness has now been implemented and exercised, with historical pilot limitations recorded in `../PILOT-RESULTS.md` and candidate integration checkpoints in `../INTEGRATION-REVIEW.md`. Neither establishes replacement quality. A bounded advisory cross-model evidence package can be completed without human labels, but it cannot establish accuracy or satisfy the existing quality-based adoption gate. Numeric operating and quality thresholds remain unset: Magnus has not chosen failure tolerances, production budget, posting mode, or quantitative cutover criteria. The free-model testing policy is recorded separately in `../TEST-MODEL-POLICY.md`.

Pilot context was inspected read-only at SlopSearX head `c1de456402961cf7d90703a4d8acca1a005392dc` on 2026-09-26. Existing Droid workflow settings use `review_depth: deep`, automatic security review, and model alias `general` through an OpenAI-like LiteLLM endpoint authenticated by a `GPUSLUT_API_KEY` binding; the backend behind that alias is unverified. Repository-secret metadata lists `DEEPSEEK_API_KEY`, `FACTORY_API_KEY`, and `GPUSLUT_API_KEY`, with values not exposed. CI's Jev optional-mode tests configure `TYPESAFE_API_KEY` as empty or `ci-synthetic-key`; this is not evidence of a live Typesafe credential or inference. These facts do not establish a direct Nous Portal deployment or a reproducible System One model baseline. Refresh repo state before execution.

## Evaluation questions

1. Does the harness find material regressions and avoid unsupported blockers on representative PRs?
2. Does deterministic orchestration preserve required coverage, evidence, freshness, and bounded behavior when context or workers fail?
3. Does it improve on current no-harness review, and how does its quality/cost profile compare with Droid and System One where those baselines can be run lawfully and consistently?
4. Do reviewers adopt its output, and which measurable quality, cost, and workflow bounds would justify continued use?

## Dataset and split

Build an immutable corpus from historical SlopSearX PRs and controlled synthetic boundary fixtures. Freeze source commits, exact base/head SHAs, repository rules/profile version, CI evidence, case-selection procedure, and provenance. Select cases across ordinary features, refactors, bug fixes, security/policy/configuration changes, tests, generated changes, and documentation. Include known issues and no-known-issue examples without labeling the latter “clean”: absence of a known defect is not proof that none exists.

Include the boundary families in the brief: one-line authorization change versus prose typo; generated diff with provenance; stale head; omitted caller/context; worker timeout and malformed output; unavailable decision model; duplicate/correlated findings; conflicting specialists; exhausted budget; missing critical coverage; prompt injection in PR text; execution isolation; summary suppression of a real blocker; no-finding versus review-completed; pre-existing defect versus introduced/re-exposed regression; and retention of every required finding with stable IDs.

Split by repository and time, not random PR rows. For each held-out case, require every compared arm to use the same full repository/base/head/profile/source-manifest/snapshot identity; a run with a different identity is unavailable for that case, not a paired comparison. Keep a later period out of prompt/rule tuning and evaluate a second repository when available, wholly outside tuning. No case or near-duplicate family may cross a split. The confirmed PR 464 example is development-only; until future held-out cases exist, report no held-out result or cross-project generalization. Keep natural-prevalence shadow samples separate from risk-enriched challenge sets and report both sampling frames.

Human labels are optional for the advisory evidence track. When present, record their source, reviewer provenance, introduced/re-exposed/pre-existing status, affected range, severity rationale, evidence, and adjudication. Preserve independent packets and any final adjudication separately. Existing issue/PR links are provenance, not proof. Human adjudication is evaluation evidence; it does not add a human approval stage to runtime review semantics. Without adjudication, a novel candidate remains unadjudicated and is not counted as a valid finding or ground truth. The model-only track below may still complete its operational evidence checklist without converting that candidate into a truth label.

## Comparison arms

Run the same immutable base/head snapshots and comparable trusted project context through:

- **No harness:** historical/current human review evidence when available; otherwise a prospective shadow human review with the normal review process documented.
- **Harness:** candidate CLI + GitHub Actions path, local report only during the pilot. Preserve model/provider versions, prompts, profiles, budgets, tool versions, and run failures.
- **Droid:** SlopSearX has a committed workflow configured for deep Droid review and automatic security review. Use its outputs only when records exist for the identical immutable PR snapshot and sufficient configuration/version metadata; otherwise mark the arm unavailable. Record product/version, configuration, omissions, and cost evidence. Do not infer parity from brand or workflow presence.
- **System One:** compare as a bounded semantic-judgment component where a reproducible authorized run and actual backend identity are available. The observed `general` LiteLLM alias does not verify the routed backend. Also record the deterministic harness result without System One to isolate its contribution. It must not select workflow or next actions. Jev CI with an empty or synthetic `TYPESAFE_API_KEY` is not an inference baseline.

Keep the written-review LLM blind to Jev output and other-arm findings when it produces its report. Jev may classify only a bounded, versioned representation of those written findings against the same frozen source identity. A separate LLM source audit of Jev claims may see the Jev claims it is auditing, but must be blind to the written-review arm’s findings, prior teacher labels, and arm identity where practical. It is not “prediction-blind” to the claims under audit. Freeze prompts, models, reference context, ordering rules, and sampling before held-out runs; randomize paired presentation where applicable. Preserve each arm’s bounded findings and reports so comparison does not erase novel, unsupported, conflicting, or abstained outputs. Record unavailable baselines as unavailable, never as zero findings.

## Measures

Report metrics by severity, lens, project, and dataset stratum with denominators and uncertainty intervals where sample size supports them. Do not collapse the following into a single score:

- **Human-adjudicated quality, when labels exist:** missed blockers/false approvals, unsupported blockers, and finding quality can be computed only against complete adjudicated packets with explicit matching and evidence. Without them, these rates are `null`/not available, not zero.
- **Advisory cross-model profile, without labels:** per-arm candidate counts and completion; source-anchor and changed-range verification states; a finding-level overlap/disagreement matrix; Jev classifications of bounded LLM outputs; LLM audit outcomes for Jev claims; abstentions, missing evidence, unresolved conflicts, and unavailable runs. Every count has an explicit denominator. These are consistency and process measures, not precision, recall, accuracy, or correctness estimates.
- **Deterministic/source checks:** verify case identity, evidence-reference resolution, snapshot path/line existence, base/head changed-range membership, and any available bounded test/reproduction result. Report each check as pass, fail, unknown, not run, or not applicable. These checks validate only the property tested; a valid anchor does not prove a claimed consequence or blocker materiality.
- **Coverage and uncertainty:** changed-unit coverage, required lens/check coverage, missing context, explicit incomplete outcomes, stale detection, and whether non-completion is confused with “no findings.”
- **Safety and robustness:** prompt-injection resistance, absence of unauthorized writes, secretless execution isolation, bounded termination, malformed/timeout/unavailable-worker handling, and preservation of accepted blockers through synthesis.
- **Operational cost:** end-to-end and per-stage latency, model/tool calls, provider cost where observable, human adjudication time, retries, resource consumption, and frequency of budget exhaustion.
- **Adoption:** report opened/retained, recommendations accepted/rejected/edited, time to disposition, reviewer follow-up burden, repeat use, and opt-out reasons. Interpret these as behavior measures, not proof of correctness.

Track deduplication and correlated worker agreement separately. Multiple models repeating the same claim are not independent evidence. Model confidence, another model’s vote, or alert presence alone never establishes correctness.

## Advisory model-teacher and cross-model evidence

A model-only assessment is a screening artifact, not a label of truth. Store it with `reviewer_kind: model_teacher`, provider/model/runtime identity, prompt and rubric revisions, exact case/snapshot identity, input/output hashes, date, selection procedure, and bounded result status. Record `MATCH`, `DISAGREEMENT`, `NO_COUNTERPART`, `ABSTAINED`, `INCOMPLETE`, or `NOT_RUN` explicitly for each comparison unit; never coerce abstention or missing output into a negative. Preserve each model’s original result and the comparison record. A second model’s vote is correlated evidence, not independent truth. Missing reviewer or run provenance is `unknown`, never human.

Keep the LLM writer, Jev classifier, and LLM Jev-auditor as distinct views. The writer generates a source-grounded assessment before seeing Jev output. Jev classifies only bounded writer findings and receives no hidden label set. The audit LLM checks Jev claims against the frozen snapshot without seeing writer findings or any prior model-teacher labels. Then compute the disagreement matrix without replacing either source output. Record model/version, prompt/rubric, request/output hashes, run order, same-snapshot identity, bounded decisions, deterministic anchor results, disagreements, and abstentions. A shared error can produce agreement, so do not count votes, agreement rates, Jev confidence, or teacher scores as accuracy or ground truth. Do not train, distill, tune the held-out rubric, or authorize workflow decisions from these outputs.

The current `review-evaluation-labels.v1` toolkit accepts model-teacher `screening` packets and reports only screening counts; it does not calculate pairwise model agreement, audit quality, calibration, or accuracy. Store any paired cross-model matrix in a separately versioned, source-bound report until an explicit evaluator contract implements those fields. Do not misfile model outputs as human packets to make existing precision/recall fields populate.

## Model-only evidence acceptance rubric

A bounded advisory evidence package may be accepted as operationally complete without human labels when all of the following are true:

1. The corpus, splits, prompts/rubrics, models, limits, and comparison procedure were frozen before the held-out run. Compared arms have exact same-snapshot identity; mismatches are marked unavailable.
2. Every selected case and arm has a terminal state or explicit `NOT_RUN`/unavailable reason. Failures, timeouts, incomplete coverage, and missing baselines remain in denominators and are not treated as empty successful reviews.
3. Every emitted finding has a stable per-run ID and bounded evidence references. Each reference receives a deterministic snapshot/location/changed-range status or an explicit unknown/not-run status. No unverified claim is silently promoted.
4. The writer, Jev, and audit-LLM records have provenance and hashes. Every paired item is accounted for as match, disagreement, no counterpart, abstention, incomplete, or not run; unresolved disagreement remains unresolved.
5. Existing deterministic safety and control checks pass on the applicable scenarios: exact snapshot binding, required coverage/failure honesty, bounded termination, no unauthorized write or target execution, and secret isolation. Model self-reports do not establish side-effect outcomes.
6. The report gives per-case and aggregate counts with denominators for coverage, source checks, disagreements, abstentions, failures, latency, calls, and known cost; unavailable cost stays `UNKNOWN`. It contains no accuracy, precision, recall, calibrated-confidence, or correctness claim without independent labels.

This rubric accepts completeness and auditability of the advisory evidence package, not review quality. An owner may separately authorize a reversible, read-only shadow/canary that leaves the existing reviewer and deterministic controls authoritative, uses finite preselected operating limits, and has a stop/rollback condition. It does not authorize posting, automated merge/check decisions, replacement, or a quality-based gate. This provides an operational decision path without pretending the models supply ground truth.

## Analysis and adoption decision

Pre-register case selection, comparison rubric, metrics, baseline availability, and any candidate routing change before held-out runs. First establish the current workflow and full-review baseline on the same immutable snapshots where available. Report the model-only evidence profile and the human-adjudicated profile separately. Analyze disagreements, abstentions, failures, and incomplete cases rather than dropping them. A held-out set helps detect tuning leakage but does not remove shared model bias or prove generalization beyond its repository/time/sample frame.

The owner’s decision record should include required-coverage completion; deterministic source-check results; cross-model disagreements and abstentions; known and unknown failure modes; latency, calls, and spend; safety incidents; and any observed shadow-workflow use. Quality-based cutover bounds remain unset until explicitly selected. Do not create a quality gate from model consensus, illustrative numbers, one PR, green CI, or reported model availability.

## Exit and claims

The advisory report is operationally complete when the frozen corpus/splits and provenance are documented, every available arm is run or marked unavailable, all outputs and disagreements are accounted for, deterministic checks have explicit results, metrics carry denominators, and limitations are stated. It cannot certify general code-review competence, repository security, or Jev/LLM accuracy. The existing SPEC NFR-011 quality-based adoption gate remains unsatisfied without representative independently adjudicated evidence for novel findings, error/abstention analysis, and sponsor-selected numeric bounds. This limitation does not prevent a separately authorized read-only advisory shadow/canary under the safety conditions above; any unadjudicated novel finding remains a candidate, not a validated defect.
