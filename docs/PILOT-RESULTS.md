# SlopSearX historical pilot — 2026-09-26

The harness builds, installs, and produces auditable reports through the real CLI. The live experiment does **not** demonstrate a usable Droid replacement yet: all six final historical reviews were `INCOMPLETE`, with distinct coverage, model-output, and provider failures preserved. No PR review was posted, no target code executed, and no changes were made to SlopSearX or the Agent Skills catalog.

## Fixed sample and provenance

Target: public `magnus919/SlopSearX`, freshly cloned as a bare object repository; public status and origin checked with GitHub before inference. Comparison basis is each selected commit against its first parent, including merges. This is a purposive sample of recent changes, not random, representative ground truth or a held-out benchmark.

Final manifest: `../artifacts/pilot/manifest-1790412393110125000.json`. It records exact full base/head pairs and hashes of runtime source, profiles, and provider configuration. Corresponding `pilot-*-1790412393110125000-*.json` / `.md` files contain structured results, coverage, task output, evidence indexes, safe errors, hashes and provenance. These local experiment artifacts are intentionally ignored by Git but delivered with the checkout.

| Head | Change | Elapsed | Calls | Required coverage (complete / partial / not started) | Disposition |
|---|---|---:|---:|---:|---|
| `c1de456` | EXP-025 corpus documentation and large audit inventory | 6.584s | 4 | 0 / 12 / 38 | INCOMPLETE |
| `c355830` | Narrow filelock 4.x Dependabot ignore | 6.353s | 4 | 1 / 3 / 0 | INCOMPLETE |
| `3c8bc04` | FastMCP dependency range | 3.612s | 3 | 0 / 3 / 1 | INCOMPLETE |
| `9dc787e` | Stateless JSON HTTP transport | 6.363s | 4 | 0 / 6 / 25 | INCOMPLETE |
| `63e3ecd` | OAuth/FastMCP compatibility | 8.122s | 5 | 0 / 10 / 115 | INCOMPLETE |
| `606d695` | Compose engine credential forwarding | 4.720s | 4 | 0 / 6 / 11 | INCOMPLETE |

All six CLI operations exited 0 because each wrote a valid terminal report. This does not mean six successful reviews. Across final tasks: 10 valid specialist envelopes, 14 failed envelopes, 82 skipped tasks. These are task counts, not accuracy or finding metrics. There were zero retained candidate findings in this final pass. Zero candidates with incomplete coverage does not establish clean changes.

## What the experiment taught us

- The initial scheduler counted evidence bytes while the transport limited the entire serialized request. Full request measurement now includes instructions, schema, task metadata, escaping, and a grouping margin; its regression verifies measured size against actual HTTP bytes and rejects before transport at one byte under the limit.
- Repeated base context exhausted the original 120000-byte specialist dispatch ceiling on a small four-lens change. The final provisional ceilings are 300000 total specialist request bytes, 64000 per request, 12 calls, 3 concurrent scopes, 0 retries, 300s controller deadline, 16000 response bytes and 1800 output tokens. Large evidence still yields explicit skipped/partial coverage. Neither these values nor latency measurements are adoption targets.
- Thirteen final provider reports failed `invalid_context_gap_target`. Strict validation rejected them rather than repairing model output or inventing a target. This prevents false completeness but limits usefulness. The next model-input revision needs prediction-blind challenge examples for the one-target contract, preservation of quarantined invalid items and available usage metadata, and a fresh live comparison. The current adapter rejects an invalid item’s whole report and loses available metering for that rejected response.
- Valid reports often declared static scope `PARTIAL` or `NOT_COVERED` for config-only or test-only evidence. We retained those states. Scope instructions/applicability need refinement so reviewing a static change is not confused with executing its tests, without treating missing consequential evidence as covered.
- Applicable portal-impact checks have no execution/evidence adapter and remain not started. Larger changes also hit evidence and dispatch budgets; the profile needs more selective context rather than simply raising every ceiling.
- The last commit had one `http_status_402` from Nous. No claim is made about the account’s balance or the exact cause. We stopped additional Nous calls and did not silently substitute providers.

Earlier manifests `1790412040364462000` and `1790412249581961000`, the original single-commit canary in `artifacts/live/`, and provider-free runs remain available. The initial canary emitted one comment-rationale candidate with no verified changed-line/semantic support. It remained `NEEDS_EVIDENCE`, never a blocker. It was not independently human-adjudicated and is not a known true or false finding. No rubric was tuned to turn it into a pass.

## System One observations

`artifacts/native-capability-probe.json` records successful native Laya and Typesafe/Jev request/response probes. Typesafe reported `jev-1.13.0`; the example configuration pins that version. Laya reported `system-one-laya`, which is an endpoint label rather than proof of a physical checkpoint. Their probe probabilities are uncalibrated capability observations.

`artifacts/native-controller/native-controller-1790412504571208000.json` exercises Laya through the installed CLI, with no generative provider configured. One budgeted native call returned HTTP 200, choice `security_sensitive` (0.643), and advisory `UNRESOLVED`. The controller kept coverage `NOT_STARTED` and disposition `INCOMPLETE`. The advisory result could not clear missing review scopes or decide disposition. This is a controller integration test, not evidence of classification accuracy, a matched generative-review comparison, or cross-model equivalence. GLiNER was not run.

## Cost, checks and limits

Configured-price estimates for the 10 valid final responses sum to **$0.120904**. This is only the recorded known portion, not the six-run total, all experiments’ total, or billed spend: rejected responses can incur cost with metering discarded; native cost and cache/billing reconciliation are unknown. Result budget cost remains `UNKNOWN` accordingly. Prices were drawn from the Nous model catalog for the configured `openai/gpt-5.4-mini` alias; physical checkpoint identity is not independently established.

Final local verification is recorded in `VERIFICATION.md`: package installation and installed `pr-review --help`, pytest, Ruff lint/format, official Actions commit-pin verification, and an exact-value scan of known live credential values across delivered source/artifacts with zero matches. The workflow is an integration artifact, not a deployed or remotely tested job. Provider/socket timeouts and the pilot runner's 360s process timeout are exercised; an adversarial slow-stream absolute HTTP deadline and hard worker isolation are not established by these tests.

## Next development gate

Before another live model comparison: repair the gap/coverage input contract and retain invalid-item/cost provenance, prioritize bounded relevant context, implement trusted external-check evidence ingestion, add file-level/deleted-line findings and duplicate/contradiction consolidation, and complete all-stage budget reservations. Then compare against independently adjudicated recent PRs, including actual regressions and clean cases. Quality thresholds, human labels, a Droid baseline, and cross-project validation are absent; retiring Droid or enabling publication is not justified by this pilot.
