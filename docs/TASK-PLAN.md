# Implementation plan — initial read-only pilot

Approval source: Magnus, 2026-09-26: “Let’s build and test against recent commits”; project name accepted as provisional. Design SPEC v0.1.0, independent Gate1 CONDITIONS. The instruction authorizes implementation and bounded inference tests; it does not authorize PR publication, deployment, auto-merge, or declaring a calibrated quality gate.

## Tasks and ownership

| Task | Owner | Completion evidence | Spec trace | Dependencies |
|---|---|---|---|---|
| T-001 Immutable Git snapshots and context | Luna build_cli | Actual Git fixtures: renamed/deleted/binary/unusual paths, base-policy authority, bounded context gaps | AC-002, AC-008, AC-021–AC-026, AC-033 | None |
| T-002 Risk planning and coverage | Luna build_core | Proposed profile rules + tiny auth/prose counterexamples; required project-check obligations | AC-006–AC-015 | Snapshot contract |
| T-003 Deterministic scheduler/ledger/reconciliation/reducer | Luna build_core | Budget/failure/contradiction/duplicate/resume/stale fixtures; honest coverage and preserved blockers | AC-005, AC-016–AC-020, AC-022–AC-032 | Snapshot/plan/provider interfaces |
| T-004 Hosted and native model adapters | Luna build_providers | Actual native contract verification plus bounded HTTP boundary tests; malformed/unavailable is explicit | AC-004, AC-017, AC-034, AC-036, AC-038 | Native endpoints/contracts, environment credential reference |
| T-005 CLI and Actions input | Luna build_cli + root integration | CLI help/dry-run/JSON/exits and read-only event adapter; separate example workflow | AC-001, AC-003, AC-004, AC-025–AC-026, AC-033, AC-037, AC-039 | T-001–T-004 |
| T-006 Packaging/profile/verification/recent-commit experiment | Root with independent Luna review after slot frees | Focused tests, real CLI reports for selected current first-parent commits, findings adjudication with limitations and evidence | All ACs accounted in VERIFICATION; NFR-001–NFR-012 | T-001–T-005 |

Critical path: shared contract → snapshot/plan/provider parallel work → integrated CLI → actual provider canary → recent commits → independent implementation review → verification/pilot report. No empirical runtime estimate promised.

## Gate2 — root oversight review

Verdict: CONDITIONS, implementation may proceed while bounded setup choices resolve. Every AC has a task owner and verification slot. Agents own disjoint files, communicate producer/consumer interfaces, root repairs integration. Defaults are explicit pilot ceilings in IMPLEMENTATION-BOUNDARIES; user build authority permits provisional reversible choices. Exact quality thresholds remain unset. SlopSearX committed guidance refreshed from current bare HEAD; profile candidate is versioned and never treated as branch protection. Nous endpoint/model/public pricing verified; key remains process-only. Native Laya/Jev support independently verified before enabling calls. No head-code execution; sandbox check execution (AC-035) intentionally disabled rather than weakened. Cases with absent required external check evidence remain incomplete. See VERIFICATION for precise support/gaps.

## Stop rule and recovery

At most six representative recent first-parent changes plus one optional-native comparison initially; max12 provider calls/run,300s/run,3concurrency,0retries by default. Stop expanding when the sample resolves basic operation. Failures drive concrete fixes and new run IDs; retain unsuccessful artifacts. No quality/adoption assertion from this sample. Copy deliverable to a separate local repository only after checks; preserve all source and reports, rollback is abandon the new repository, existing projects unchanged. No remote repository creation or push assumed.

## Gate3 / Gate4 pilot outcome

Local build/contract checks and packaging completed; real public-commit reports delivered. Gate3 CONDITIONS for an experimental CLI, not full spec conformance. Gate4 NOT READY for adoption: six final cases remain incomplete, invalid gap targets and static-coverage interpretation need input-contract work, required checks and broader reconciliation features are deferred, and the final provider run returned HTTP402. No production rollout or Droid replacement authorized by this evidence. Root integration fixes after independent Luna review include full serialized request accounting, a finite budget adjustment and optional-gap routing; new tests cover these, but the independent review was not repeated on every root integration edit.
