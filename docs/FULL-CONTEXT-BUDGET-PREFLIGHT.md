# PR464 Full-Context Budget Preflight

This is an offline admission and serialization measurement for the frozen PR464 review inputs. It evaluates one temporary test-budget proposal against the actual CLI, snapshot collector, planner, engine admission path, and provider request serializer. It does not establish review quality, production cost, a production budget, or a completed review.

## Frozen inputs and provenance

- Source commit: `432eeb9e44177de7f82e8795aa713cec5b70fe0d`.
- Repository and PR: `magnus919/SlopSearX` PR 464; base `20a743f0434a1843aa00068483f608f1e213b2af`; head `bffc26f9e4bf95aca0c252e88a2396d03ece854c`.
- Profile: `slopsearx-production-v3-context-selection-window40-probe-20260926`; SHA-256 `7b694f29197df5a89316651c0af9741f4d4a66bebe9100be42f958433df70e7a`.
- Captured check fixture SHA-256: `3ac1c5194c8a308e2147ed5c414f3a9c378184535047794eb3fa380a7044dfb9`.
- Original provider config SHA-256: `db5975f1fe007962593d543788261900fbdcf7a7bf4c6caf345f8b42462ba313`.
- Proposed provider-config copy SHA-256: `2520a3c6ee3b1c8205e729361b164d6aeee018d0ca03fe1111cd866e833ce7de`.
- Runner SHA-256: `4d3796164a272789d97a65afbf9648ec32c1975033e2d11362909e60440ab744`.
- Exact preflight result SHA-256: `08888791331f6fd3ff42cfc13bd684784885277f3f5c7019a099ea907ab32975`.
- Detailed run manifest SHA-256: `7e8def6d20bc25b2b64b1917d6d832b1fccb62b7ef408bbf3830ecdf3adad67b`.
- Separate full-plan allowance interpretation SHA-256: `8c047f6441a9384e3af77978d47539628fb81e8ed61c2ac5b3ba4fb8094468e3`.
- Temporary limits file SHA-256: `43829e63ce146333f4adf9ac60de62e768cf1892d0e14411311c7b852b054fdd`.

The complete local artifacts, including per-request body hashes and all 18 obligation records, are in `/private/tmp/pr-review-v3-fullcontext-96k-432eeb9-20260926/`. Source and input hashes matched before and after the run. The prior 64 KB preflight used source commit `9f05e11e628ee129aa37e2246890d25d8705576c`; it shared the PR pair, profile, and check fixture hashes but used different source and budget/configuration revisions. Treat its numbers as historical pressure evidence, not a controlled comparison.

## Temporary proposal and measured admission

The isolated limits file proposed:

| Limit | Proposal |
|---|---:|
| Per-task input | 96,000 bytes |
| Aggregate context input | 3,000,000 bytes |
| Provider-call slots | 30 |
| Per-task output | 32,768 bytes |
| Aggregate output | 983,040 bytes |
| Output tokens per call | 4,096 |
| Retries per task | 0 |
| Overall deadline | 300 seconds |
| Concurrent scopes | 3 |

The provider config copy retained the configured endpoint `https://inference-api.nousresearch.com/v1`, model `upstage/solar-pro4:free`, and credential environment-variable *name* `NOUS_API_KEY`. It changed only response bytes (16,000 to 32,768), output tokens (1,800 to 4,096), and provider timeout (75 to 60 seconds). No credential value was read. The process ran with the configured credential variable unset.

The actual planning and serializer path produced 14 tasks: 12 specialist request bodies and two deterministic check tasks. The 12 serialized specialist bodies total 887,648 bytes; the largest body was 86,581 bytes. Engine admission adds a 1,024-byte per-task sizing allowance, making the largest admission size 87,605 bytes and the summed specialist admission sizes 899,936 bytes. All 12 fit the proposed 96,000-byte per-task ceiling. The request bodies had no context omissions, no required-context omissions, and the resulting snapshot had zero context gaps. The 12 specialist requests cover all 16 changed-unit/lens obligations; the plan also contains two project-check obligations.

All 18 obligations remain `NOT_STARTED` with `INCOMPLETE` disposition. The offline interceptor stopped every budget reservation before persistence, so no request or check task was dispatched. There were zero provider transport attempts, zero GitHub check-adapter invocations, and zero target-code execution. The two historical check records were present and identity-bound in the snapshot, but their deterministic check tasks were not evaluated in this preflight. No provider response, finding, or adjudication was produced.

## Remaining allowance, not measured demand

The raw preflight summary reports 18 call slots and 589,824 output bytes remaining after the 12 specialist requests. That view is specifically after specialist requests. For a more conservative projection across the full 14-task plan, count each deterministic check task as one generic call slot and one 32,768-byte output ceiling. This follows the engine's no-estimator fallback (`provider_calls: 1`, `max_output_bytes: max_output_bytes_per_task`) in [`engine.py`](../src/pr_review_harness/engine.py#L650-L666); `BudgetLedger` enforces those call and output totals as separate limits in [`budget.py`](../src/pr_review_harness/budget.py#L93-L108).

Under that projected accounting, the 14 planned tasks leave at most 16 call slots and 524,288 output bytes for later candidate adjudication. Specialist request estimates use exact serialized body sizes, totaling 887,648 bytes. Each deterministic check task receives the engine fallback estimate of one generic call and 2,628 input bytes from its two canonical unit-diff evidence records, leaving 2,107,096 bytes under the 3,000,000-byte aggregate input cap after all 14 planned tasks. This fallback estimate does not measure a GitHub HTTP request. The 1,024-byte allowance is added for specialist per-task admission, but is not charged to the aggregate input total by the current `BudgetLedger`. A future adjudication request would be limited to a 94,976-byte body when applying the same 1,024-byte per-task allowance, 32,768 output bytes, and 4,096 output tokens per call. These are ceilings only; no adjudication demand was observed.

The raw preflight field shows 2,112,352 aggregate input bytes remaining after specialist requests alone. The separate versioned allowance interpretation adds the two check-task fallback estimates (2,628 bytes each), leaving 2,107,096 bytes after the full 14-task plan. The check tasks reference captured check evidence through their bindings while their plan `evidence_ids` are empty; `_evidence_for()` supplies two unit-diff records for the generic fallback size estimate. The estimate does not measure a GitHub HTTP request body.

## Historical 64 KB pressure

The earlier offline preflight at source `9f05e11` planned five specialist requests totaling 307,717 serialized bytes against a 300,000-byte aggregate context limit. Ten of 18 obligations were skipped before review because required context could not fit the 64,000-byte per-task limit; required context was not silently dropped. That run was also `NOT_STARTED`/`INCOMPLETE` and made no external calls.

The new run demonstrates that the same frozen PR/profile/check identity can be serialized for all planned specialist obligations under the proposed 96 KB per-task limit and a 3 MB aggregate input ceiling. Because source revision and multiple limits/provider caps differ, this is not a single-variable benchmark and does not prove efficiency or review quality. The higher ceiling is a test proposal only; it does not change shipped defaults or production acceptance criteria.
