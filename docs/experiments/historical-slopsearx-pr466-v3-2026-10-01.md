# Historical SlopSearX PR466 v3 diagnostic

The single bounded v3 diagnostic was [run 36925966131](https://github.com/groktopus/codereview/actions/runs/36925966131), dispatched from trusted harness main `e41bd6c5a159cf017dc943fb3bd1b9f75a3e212c`. Its prepare and live-diagnostic jobs both succeeded. Main's post-merge verification run [36918784533](https://github.com/groktopus/codereview/actions/runs/36918784533) passed all ten jobs at that exact commit.

The target was `magnus919/SlopSearX` PR466, frozen base `63e3ecd2f09d79c34e3594a3be74f017a1c5a12c` and head `7bce9dd246f141eb961c52ae96061203a98f083b`. The run used experimental profile `slopsearx-production-v11-related-implementation-context-candidate` (SHA-256 `5afcbf3cf5af235a97b59487303c28cb5c5f0942dc51cccc1ff84178617853d3`), historical checks SHA-256 `c7d3a28b0e12583dceb0021b04814573706f202a188e4cbed2d1ebde821d5963`, and limits SHA-256 `964a11a8de3bfd47520ea62e358c954dceb1ac7da7f0648ef4db11d6f885870e`. Limits remained ten provider calls, zero retries and follow-ups, 80,000 input bytes per task, 600,000 aggregate context bytes, and a 600-second deadline.

The provider-free prepare admitted all 15 planned obligations across seven primary requests totaling 417,632 serialized bytes. The largest request was 72,737 bytes. It made zero provider calls and executed no target code. Optional-stage demand was unknown at prepare time. The prepare observation SHA-256 is `8f0b98c6a2f6b879cb9e1496d406ee20432782165900718d145c84e26476d173`.

The full review result was **INCOMPLETE / PARTIAL**: 10 obligations `COMPLETE`, five `PARTIAL`, zero findings, zero claim assessments, and merge eligibility `NOT_EVALUATED`. Freshness is labeled `CURRENT` with basis `HISTORICAL_SNAPSHOT`; the result compares the frozen base/head and does not establish current PR state.

Four partial obligations were tied to two unresolved context gaps. The correctness task requested `make_http_app / FastMCP http_app stateless JSON mode` without a supported path or symbol binding. Retrieval failed with `symbol_lookup_not_in_allowlist_contract`, a 90-byte envelope, and zero retrieved bytes; this gap affected three obligations. The v11 profile did supply the HEAD `slopsearx/mcp/security.py` source window and diff to the planned tasks, but that did not resolve this separate request. A second request for `slopsearx/mcp/security.py` retrieved 2,761 bytes, but the result records `FOLLOWUP_TASK_BUDGET_EXHAUSTED`; with follow-ups capped at zero, one correctness obligation remained partial. The fifth partial obligation was a tests-lens row marked `REQUIRED_OUTPUT_QUARANTINED`: report notes referenced unknown evidence and were quarantined. These are unresolved evidence states, not findings that the target code is defective.

The two deterministic portal-check obligations were marked `COMPLETE` using the captured historical check evidence. No target tests or application code ran. No injection attack ran, no review was published, and no target configuration or Droid state changed.

The result records eight actual HTTP response receipts: seven LLM responses and one Jev response. Each LLM request returned HTTP 200 in one attempt. Provider-reported LLM usage totals 103,042 prompt tokens and 3,907 completion tokens (106,949 total). Jev returned one `Noul` advisory with recommendation `UNRESOLVED` and probability 0.66; it is marked `advisory_uncalibrated`, and Jev token usage is unknown. The budget records eight of ten provider-call reservations and two local deterministic checks, which consume no provider calls. There were zero retries. Billing and cost remain `UNKNOWN`.

The `CURRENT` label must not be read as a check of live GitHub PR state: `freshness_basis` is `HISTORICAL_SNAPSHOT`. The result establishes neither the truth of a finding nor accuracy, calibration, causal improvement, attack resistance, or cutover readiness. The prior v2 result remains a separate historical observation; this v3 record does not rewrite it. The standing bounded-test authority in `AGENTS.md` covers this public, fixed-scope read-only test within the configured endpoints and existing caps. Publication, target changes, target-code execution, new providers/endpoints, and Droid cutover remain outside that authority.

## Retained artifact provenance

The run artifacts were downloaded by artifact name into the private local directory `/private/tmp/codereview-pr466-v3-run-36925966131` (mode `0700`). This is a local evidence path, not a durable repository artifact. GitHub artifact IDs were `11193248336` (prepare) and `11193942091` (review); both were non-expired at retrieval. Only the prepare observation, review result, and review report were retained there.

- `prepare/prepare-observation.json`: 14,671 bytes; SHA-256 `8f0b98c6a2f6b879cb9e1496d406ee20432782165900718d145c84e26476d173`
- `review/review-result.json`: 117,342 bytes; SHA-256 `bf8cb5dd24db32979100f4dc12012d293577d3457b66d62e0c0d68f20abf265e`
- `review/review-report.md`: 20,090 bytes; SHA-256 `d8f105233b6e6962b60058ecb9cc80ad755797834e8af3cd76483baa995c9049`

No secret values, raw provider request/response bodies, or prompts are included in this record. The standalone artifacts are bounded review evidence, not an independent validation of model statements or a quality certificate.
