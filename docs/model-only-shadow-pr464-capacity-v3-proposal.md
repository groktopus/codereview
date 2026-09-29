# PR-464 source-audit capacity v3

The frozen v2 PR-464 audit cap is 64,000 request bytes. Exact provider-free serialization from the prepared snapshot and all ten selectable tasks produces source-only requests from 74,486 to 91,832 bytes. The plan-ranked no-candidate task produces 74,521 bytes, which explains the held rehearsal before any source-auditor call.

The v3 cap is 96,000 bytes. It admits all ten measured requests and leaves 4,168 bytes above the largest request. The writer provider configuration already allows 128,000 request bytes. The source prompt, schema, model, 1,800 output-token limit, 64,000 response limit, call count, deadline, and zero-retry policy stay the same. The request retains the complete task and source evidence; no evidence is trimmed.

The [provider-free proposal](../experiments/model-only-shadow-live-pr464-plan-v3-proposal.json) records the pre-freeze measurements. The [active v3 plan](../experiments/model-only-shadow-live-pr464-plan-v3.json) binds the frozen PR, snapshot, profile, all request descriptors, and the committed runtime. The existing v2 plan and v1 limit file remain the historical record.

The trusted case policy, verifier, and selected workflow use the v3 plan and v2 audit limits for PR-464. The engine serializes every selectable source-auditor request before writer dispatch and rejects the review if any request exceeds the plan's cap. A future source-module change requires a new provider-free preparation and runtime pin before this plan can run again.
