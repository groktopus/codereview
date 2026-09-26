# Verification and implementation status

This is an initial read-only pilot implementation. The original draft specification in `design/SPEC.md` remains the target, not a statement of completion. Controlled fixtures prove specific controller properties; real inference runs prove transport and normal-path operation. Neither establishes model accuracy or parity with Droid.

## Acceptance accounting

| Spec criteria | Evidence / status |
|---|---|
| AC-001–004, AC-039 | Shared core behind CLI and Actions event adapter; help/dry-run/JSON, rejection, immutable event identity, local HTTP adapter tests. Manual Actions workflow supplied; remote execution NOT RUN. |
| AC-005–007 | Controller owns sequencing and disposition. Optional native advisory output cannot change disposition. Tests exercise bounded calls, retries, deadlines, invalid limits and failures. Monetary reservation unsupported: a requested monetary cap rejects before dispatch. |
| AC-008–011 | Snapshot inventory and deterministic profile routes; docs/auth and unknown-provenance counterexamples. Unknown/generated units raise the depth floor. This does not prove semantic risk-classification accuracy. |
| AC-012–015 | Unit/lens and separate check obligations; explicit no-match exclusions; failed/missing scope remains incomplete. Context-gap capture prevents clean approval. Automatic bounded retrieval and expanded follow-up scheduling DEFERRED. |
| AC-016–020 | Bounded parallel tasks, integrity-checked checkpoints/resume, result and assessment validation, supplied-evidence restrictions, contradiction fixtures. All-stage context-byte reservations remain partial: specialist envelope bytes reserved, adjudication/native individually input/call bounded. Cross-specialist duplicate/correlation consolidation and comprehensive output-conflict replay NOT COMPLETE. Invalid provider items can reject their full report rather than preserving unrelated valid items. |
| AC-021–024 | Base/head/profile hashes, evidence locators and hashes, explicit per-unit coverage notes, positive HEAD changed-line anchors, coverage ledger. Deleted-line/file-level finding locations DEFERRED and cannot become accepted findings. Evidence hashes prove identity, not truth. Evidence references currently render source locators rather than clickable source URLs. |
| AC-025–026 | Current/stale/unknown GitHub-head checks and resume checks in fixtures. Historical snapshot basis explicit. No live PR approval/publication was exercised. |
| AC-027–028 | Four deterministic report categories, blocker-preservation and Markdown escaping tests. Strengths/future guidance generation DEFERRED; empty sections are visible. No probabilistic editorial layer implemented. |
| AC-029–032 | Deterministic reducer fixtures: clean current complete review, unknown/stale, unresolved finding, blocker with missing coverage. Merge eligibility NOT_EVALUATED until a rule-evidence adapter exists. Model-backed materiality is advisory and does not amount to human acceptance. |
| AC-033–034 | External trusted profiles, base-only guidance, literal Git paths, no head-code execution, environment credential transport, seeded HTTP-secret non-echo tests. Live credential scan recorded separately; not a comprehensive security certification. |
| AC-035 | Target execution DISABLED. Disposable secretless check execution and its resource/isolation validation NOT IMPLEMENTED. Required check bindings without evidence remain incomplete. |
| AC-036 | Verified OpenAI-compatible Nous inference plus native Laya/Typesafe request probes. Unsupported primitive rejects. GLiNER NOT IMPLEMENTED or claimed equivalent. Native probabilities uncalibrated, observational only. |
| AC-037 | READ_ONLY enforced; publication rejected. No GitHub write path, auto-merge or repair. |
| AC-038 | GitHub secret metadata is names only; actual Nous/Laya/Typesafe credentials resolved locally without printing values. No inference backend inferred from Droid aliases. |

## Nonfunctional boundaries

NFR-001–006 are exercised by scoped controller/snapshot/report fixtures, with the feature gaps above. NFR-007–008 have transport canaries, no target-code execution, read-only API use, and existing-repository status checks; hostile-input coverage is necessarily bounded. NFR-009 remains partial for deduplication and conflict replay. NFR-010 records endpoint/model identifiers and hashes; an alias or endpoint-reported label is not proof of physical checkpoint identity. NFR-011 is explicitly UNMET for adoption: no independent human labels, held-out effectiveness estimate, Droid baseline, error-rate thresholds, or sponsor-selected quality gate. NFR-012 records elapsed time, calls, available usage and estimated configured-price cost; absent usage, native pricing and bill reconciliation remain unknown.

The provider is an external data recipient. Credentials are not included in prompts; repository excerpts intentionally are. Profile authors must decide what context their provider may receive.

## Delivery gates

Implementation is usable for bounded local experiments, with conditions above. It is not a production acceptance or quality release gate. A green test run cannot clear a required SlopSearX portal check, establish that a model finding is true, or justify retiring Droid. See `PILOT-RESULTS.md` for the fixed real-commit sample, source hashes, outcomes, and remaining practical work.

## Observed local verification

The packaged project installed successfully into an isolated temporary virtual environment; the installed `pr-review` entry point returned help. Final pytest and lint/format results are recorded in `artifacts/verification.json`. Official checkout/setup-python/upload-artifact commit pins resolved through GitHub. An exact-value scan of known live Nous/Laya/Typesafe credentials found zero matches in 153 source/artifact files at scan time (`artifacts/credential-scan.json`); this scoped check does not certify every possible secret pattern.

The final live sample exposed invalid gap targets, ambiguous scope-completion inputs, and an HTTP 402. Those are unresolved operational/quality conditions, documented in PILOT-RESULTS. Full-request sizing is now verified against actual mock HTTP bytes. Absolute hostile slow-stream HTTP deadlines and process-isolated workers are not validated; the pilot runner enforces an additional 360s process timeout. The controller's total-context ledger covers specialist requests; semantic/native requests remain individually byte bounded and globally call bounded but need an all-stage reservation ledger.
