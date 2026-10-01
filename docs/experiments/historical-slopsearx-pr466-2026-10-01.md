# Historical SlopSearX PR466 functional diagnostic

[Hosted run 36872770979](https://github.com/groktopus/codereview/actions/runs/36872770979) completed successfully using trusted harness revision `0dd6145f921216f7d753f06dcc4849e75aed9cd4`. This was one owner-authorized, read-only run of the existing production CLI and classifier adapters. No target code ran and no review was published.

## Frozen input and result

The target was `magnus919/SlopSearX` PR466, base `63e3ecd2f09d79c34e3594a3be74f017a1c5a12c`, head `7bce9dd246f141eb961c52ae96061203a98f083b`, profile `slopsearx-production-v8-static-review-boundaries`. Checks came from the retained historical snapshot, not the current PR API. The result's freshness basis is `HISTORICAL_SNAPSHOT`; its `CURRENT` state compares fixed revisions only.

Disposition was **INCOMPLETE**, coverage **PARTIAL**: 12 complete and 3 partial obligations out of 15. Merge eligibility was `NOT_EVALUATED`. Two requested retrievals remained unresolved: an unsupported symbol target for `make_http_app` caller context and a broad `tests/` path outside the trusted allowlist. This was not a budget-exhaustion explanation for those retrieval failures.

One medium OAuth-test claim remained `NEEDS_EVIDENCE` / `UNRESOLVED` and was omitted from recommendation sections. Static inspection of the exact HEAD shows the revoked-token probe uses POST at `tests/test_mcp_oauth.py:349`, contradicting the model's claim that it remains GET. The cited HEAD window and diff already contained that correction. BASE/HEAD confusion is a failure hypothesis, not a proven cause. The file-level null-line candidate also lacked the required task-scoped full-file anchor; that validation must remain enforced.

## Accounting and classifier evidence

Seven primary model HTTP responses and one Jev response were recorded: eight actual provider exchanges. Primary usage was 85,018 input tokens plus 3,982 output tokens, 89,000 total. Jev usage and billing were unknown. Recorded HTTP request bytes totaled 354,571; response bytes totaled 13,423. These are local exchange observations, not independent delivery attestations.

The budget recorded ten provider-call reservations, including two local deterministic checks with no HTTP exchange. This exposed an accounting defect: those checks consumed provider-call capacity. Reserved input/output bytes were 389,656 / 160,000; reserved output capacity is not actual output usage. The original result is preserved, including the discrepancy.

Jev returned an uncalibrated advisory `Noul` probability of 0.67 with recommendation `UNRESOLVED`. Configured model `jev-latest` reported `jev-1.13.0`. The candidate-bound claim assessment was `NOT_RUN` with `PRIMARY_CANDIDATE_INVALID`; this run does not demonstrate that constituent classification resolved the unsupported claim.

Result JSON SHA-256: `96817e8b6c17c99b097f93894d8ebc0e10ccb755211ca919bdfda2a194c2e60d`. Original report SHA-256: `1009d71378f0c7e7d43da182988534ec27499ffb8424d04c4639c1698a604efb`. GitHub artifact IDs were `11167846625` (prepare) and `11167741966` (review). No raw prompts, credentials, or private provider configuration are included here.

## Follow-up boundaries

The source corrections separate bounded local checks from provider reservations and explicitly render historical freshness. A separate versioned profile candidate can bind exact captured security-test and MCP-documentation evidence to implementation tasks. Directory access and unsupported symbol lookup must not be broadened to clear the observed gaps. Repository documentation can establish the declared transport contract; it cannot establish actual external-client usage.

Provider-free preparation of the v9 candidate exposed a further limit: the MCP binding's existing BASE implementation/dependency context plus related changed-HEAD test and documentation evidence exceeds its unchanged 18,000-byte cap. The candidate preserves the dependency context and records required-context gaps. This demonstrates bounded selection and failure behavior; it does not demonstrate that the historical review now receives all needed context or would complete. V8, target selection, task ownership and obligations remain unchanged.

The case was selected before observing the incumbent's comments. Droid's exact-head historical run posted an assessment but had a failed workflow conclusion; it is neither a successful execution baseline nor a correctness label. Its output was not sent to the candidate models.

This diagnostic supplies functional and failure evidence. It does not establish semantic accuracy, calibration, a production publication path, or replacement readiness. Human labels remain unavailable; model agreement would still be advisory. No follow-up provider run is claimed by this record.
