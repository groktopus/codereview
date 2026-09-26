# Current v3 context baseline

This is an offline measurement of the current v3 SlopSearX review path. It records request sizing and budget admission, not review quality. The measurement double used the normal snapshot collector, planner, engine grouping, and the production provider's exact request serializer; it returned inert test data and made no provider/API calls. No target code was executed.

The immutable bare-repository inputs were base `20a743f0434a1843aa00068483f608f1e213b2af` and head `bffc26f9e4bf95aca0c252e88a2396d03ece854c`. The profile was `slopsearx-production-v3-check-bindings`, SHA-256 `9c03e1547300c48ebd676b0499e5e5e76210214c5f8d52427ace7b0af388e73c`. Snapshot `snap-a0f0c664b84294536355820e` contained 6 changed units, 24 evidence records, and no snapshot gaps. The raw plan had 10 tasks and 18 obligations; normal engine grouping produced 11 final tasks: 9 specialist chunks and 2 deterministic check tasks. The check adapter was not configured.

With the configured 300,000-byte shared context/input budget, the first attempt estimated all 9 specialist requests at 558,724 aggregate serialized bytes. Each request fit the 64,000-byte per-task input limit; the largest was 62,549 bytes. Thus aggregate demand exceeded the shared budget by 258,724 bytes. Four specialist reservations totaling 246,825 bytes were admitted before the remaining requests could not fit; 5 tasks were skipped for context budget and 2 check tasks were skipped because their adapter was unavailable. This demonstrates an aggregate request-budget bottleneck, not evidence that policy or review obligations can be dropped.

Two measurement attempts are retained. Attempt 1 has four worker-start failures because the wrapper held an unpicklable lock; no fake provider invocation succeeded. Attempt 2 removed that wrapper lock, admitted four requests, and recorded four inert fake invocations; it still skipped the same 7 tasks under the shared budget. The second attempt therefore confirms admission behavior for the first four calls, but does not independently size the five requests never admitted. Both engine results are `INCOMPLETE`/`PARTIAL`; their coverage and findings are not quality evidence.

| Artifact | SHA-256 |
|---|---|
| Attempt 1 summary | `17e2331d3fed03ee4ae5734a57a27552854c521ebc1e79cdc15dfc2a20c769ef` |
| Attempt 1 sealed result | `253754f5630fd943952b336a04d88d68d35418be3a9ef41159866e0405f56e20` |
| Attempt 2 summary | `df0c84f23934ec2a6af36bbb8bb03e26189d60f22173d394d319e7ebaccc76b0` |
| Attempt 2 sealed result | `747e5fc23e2485206b2ba49df164647c67ad70d3891765d05baab4d1f8b4dcc5` |
| Provenance sidecar | `df6544f47e278700a291ce31126cfeee366151d3c81efd25f6590d430fc5fcdb` |

The artifacts are under `/tmp/pr-review-v3-exact-normal-baseline-20260926/` and `/tmp/pr-review-v3-exact-normal-baseline-20260926-retry1/`; the provenance sidecar is `provenance.json` in the first directory. The sidecar binds artifact hashes, profile/provider configuration hashes, runtime, plan, and the core contract hash. Source and wrapper file hashes in it were captured after the runs, not before invocation, so they are post-run fingerprints rather than proof that the same bytes were present at invocation. The engine core contract hash recorded in each run matches the current hash (`6d152a1382168d6ea30d917228fc832cc517366f8ac4e6f9d891e8369bf16431`). Do not treat the sidecar as a signed or independently attested execution record.

The useful next step is to reduce redundant context while preserving the original obligation and policy denominator. Any selector should report every original scope, classify applicability separately from source extraction, retain unresolved applicability explicitly, and compare exact serialized requests and budget admission against this baseline. No clause or lens should disappear merely to fit the budget, and this measurement does not authorize such a reduction.
