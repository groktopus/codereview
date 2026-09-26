# PR Review Harness — pilot evaluation plan

**Status:** Evaluation methodology, not a performance claim or release gate. The original design preceded implementation; the harness has now been implemented and exercised, with historical pilot limitations recorded in `../PILOT-RESULTS.md` and candidate integration checkpoints in `../INTEGRATION-REVIEW.md`. Neither establishes replacement quality. Numeric acceptance thresholds remain unset: Magnus has not chosen failure tolerances, production budget, posting mode, or quantitative cutover criteria. The free-model testing policy is recorded separately in `../TEST-MODEL-POLICY.md`.

Pilot context was inspected read-only at SlopSearX head `c1de456402961cf7d90703a4d8acca1a005392dc` on 2026-09-26. Existing Droid workflow settings use `review_depth: deep`, automatic security review, and model alias `general` through an OpenAI-like LiteLLM endpoint authenticated by a `GPUSLUT_API_KEY` binding; the backend behind that alias is unverified. Repository-secret metadata lists `DEEPSEEK_API_KEY`, `FACTORY_API_KEY`, and `GPUSLUT_API_KEY`, with values not exposed. CI's Jev optional-mode tests configure `TYPESAFE_API_KEY` as empty or `ci-synthetic-key`; this is not evidence of a live Typesafe credential or inference. These facts do not establish a direct Nous Portal deployment or a reproducible System One model baseline. Refresh repo state before execution.

## Evaluation questions

1. Does the harness find material regressions and avoid unsupported blockers on representative PRs?
2. Does deterministic orchestration preserve required coverage, evidence, freshness, and bounded behavior when context or workers fail?
3. Does it improve on current no-harness review, and how does its quality/cost profile compare with Droid and System One where those baselines can be run lawfully and consistently?
4. Do reviewers adopt its output, and which measurable quality, cost, and workflow bounds would justify continued use?

## Dataset and split

Build a labeled corpus from historical SlopSearX PRs plus controlled synthetic boundary fixtures. Freeze source commits, base/head SHAs, repository rules/profile version, CI evidence, and label provenance. Select historical cases across ordinary features, refactors, bug fixes, security/policy/configuration changes, tests, generated changes, and documentation. Use both defect-introducing and clean cases. “Clean” means no known substantive defect after review, not proof that no latent defect exists.

Include at minimum the boundary families in the brief: one-line authorization change versus prose typo; generated diff with provenance; stale head; omitted caller/context; worker timeout and malformed output; unavailable decision model; duplicate/correlated findings; conflicting specialists; exhausted budget; missing critical coverage; prompt injection in PR text; execution isolation; summary suppression of a real blocker; no-finding versus review-completed; pre-existing defect versus introduced/re-exposed regression; and retention of every required finding with stable IDs.

Split by repository and time, not random PR rows. Keep a held-out later period from SlopSearX and, when available, a second repository entirely outside prompt/rule tuning. No case or near-duplicate from a held-out family should leak into tuning. With only the confirmed pilot, call results pilot-internal and do not claim cross-project generalization. Preserve natural-prevalence shadow samples separately from intentionally balanced challenge sets; report the sampling frame and prevalence.

For each evaluation label, record source (tests, maintainer report, incident, independent reviewer), introduced/re-exposed/pre-existing status, affected range, severity rationale, evidence, and adjudication. Existing issue/PR links are provenance, not proof by themselves. Where feasible, two human reviewers independently label evaluation cases; resolve disagreements with a named adjudicator and preserve both original labels. A human adjudication here establishes evaluation evidence only. It does not add a human approval stage to runtime review semantics; those remain defined by the separate product contract. Novel candidate findings are reviewed by a human before counting as valid even when absent from known issue ground truth.

## Comparison arms

Run the same immutable base/head snapshots and comparable trusted project context through:

- **No harness:** historical/current human review evidence when available; otherwise a prospective shadow human review with the normal review process documented.
- **Harness:** candidate CLI + GitHub Actions path, local report only during the pilot. Preserve model/provider versions, prompts, profiles, budgets, tool versions, and run failures.
- **Droid:** SlopSearX has a committed workflow configured for deep Droid review and automatic security review. Use its outputs only when records exist for the identical immutable PR snapshot and sufficient configuration/version metadata; otherwise mark the arm unavailable. Record product/version, configuration, omissions, and cost evidence. Do not infer parity from brand or workflow presence.
- **System One:** compare as a bounded semantic-judgment component where a reproducible authorized run and actual backend identity are available. The observed `general` LiteLLM alias does not verify the routed backend. Also record the deterministic harness result without System One to isolate its contribution. It must not select workflow or next actions. Jev CI with an empty or synthetic `TYPESAFE_API_KEY` is not an inference baseline.

Blind human adjudicators to arm/model identity when practical. Randomize presentation order for paired output review. Keep all arms’ raw candidate findings and final reports so matching does not erase novel findings or unsupported claims. Distinguish unavailable baseline data from zero findings.

## Measures

Report metrics by severity, lens, project, and dataset stratum with denominators and uncertainty intervals where sample size supports them. Do not collapse the following into a single score:

- **Missed blockers / false approvals:** known and human-adjudicated novel blockers not surfaced; cases whose APPROVE disposition conflicts with labeled required review obligations.
- **Unsupported blocker rate:** blocker findings rejected by adjudication, including whether the problem is evidence, severity, or introduced-code attribution.
- **Finding quality:** relevance, correctness of problem identification, location accuracy, evidence sufficiency, explanation, actionability, specificity, context, and completeness.
- **Coverage and uncertainty:** changed-unit coverage, required lens/check coverage, missing context, explicit incomplete outcomes, stale detection, and whether non-completion is confused with “no findings.”
- **Safety and robustness:** prompt-injection resistance, absence of unauthorized writes, secretless execution isolation, bounded termination, malformed/timeout/unavailable-worker handling, and preservation of accepted blockers through synthesis.
- **Operational cost:** end-to-end and per-stage latency, model/tool calls, provider cost where observable, human adjudication time, retries, resource consumption, and frequency of budget exhaustion.
- **Adoption:** report opened/retained, recommendations accepted/rejected/edited, time to disposition, reviewer follow-up burden, repeat use, and opt-out reasons. Interpret these as behavior measures, not proof of correctness.

Track deduplication and correlated worker agreement separately. Multiple models repeating the same claim are not independent evidence. Model confidence, another model’s vote, or alert presence alone never establishes correctness.

## Advisory model-teacher labels

If human labels are temporarily unavailable, an independent inference model may screen a prediction-blind sample as advisory pseudo-labeling only. Store `reviewer_kind: model_teacher`, model/provider/version, prompt revision, source and output hashes, date, case-selection procedure, disagreements, and abstentions. Do not train on harness/Jev predictions, count teacher agreement as independent truth, call its score accuracy, or use it to authorize a gate. Missing reviewer provenance is `unknown`, not human.

## Analysis and adoption decision

Pre-register case selection, label rubric, metrics, baseline availability, and any candidate routing change before running the held-out set. First establish the current workflow and full-review baseline. Compare quality and cost jointly; cheaper routing is acceptable only if held-out adjudication shows no unacceptable increase in missed blockers or false approvals under bounds Magnus explicitly selects. Analyze abstentions/incomplete cases rather than dropping them. If evidence is sparse, conflicting, or dependent on teacher labels, report the result as inconclusive and collect more human-labeled cases.

The adoption decision should be a recorded choice by Magnus using measured values for: missed-blocker and false-approval rates; unsupported-blocker burden; required-coverage completion and abstention; novel-finding quality; human review minutes saved or added; latency and spend distribution; failure/incomplete rate; safety incidents; and repeat-use/acceptance. Leave the acceptable bounds and weighting blank until he selects them. Do not create a pass/fail gate from illustrative numbers, a single PR, a green CI result, or reported model availability.

## Exit and claims

A pilot report is complete when the fixed corpus/splits and provenance are documented, every available arm is run or marked unavailable, novel findings and disagreements are adjudicated or explicitly unresolved, metrics include denominators and uncertainty, and tradeoffs are shown. It may support a constrained adoption decision; it cannot certify general code-review competence or repository security. Production gates require representative independently adjudicated data, held-out testing, error and abstention analysis, and a separately versioned explicit gate contract.
