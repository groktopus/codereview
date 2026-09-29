# PR-464 source-audit capacity proposal

The frozen v2 PR-464 audit cap is 64,000 request bytes. Exact provider-free serialization from the prepared snapshot and all ten selectable tasks produces source-only requests from 74,486 to 91,832 bytes. The plan-ranked no-candidate task produces 74,521 bytes, which explains the held rehearsal before any source-auditor call.

The proposed v3 cap is 96,000 bytes. It admits all ten measured requests and leaves 4,168 bytes above the largest request. The writer provider configuration already allows 128,000 request bytes. The source prompt, schema, model, 1,800 output-token limit, 64,000 response limit, call count, deadline, and zero-retry policy stay the same. The request retains the complete task and source evidence; no evidence is trimmed.

[`experiments/model-only-shadow-live-pr464-plan-v3-proposal.json`](../experiments/model-only-shadow-live-pr464-plan-v3-proposal.json) binds every measured size and request hash to the frozen PR, snapshot, and profile. It is a proposal, not an executable plan: the runtime revision, module count, and module-tree hash remain pending because PR #157 and the other v3 identity migrations must land in one final stack. The existing v2 plan and v1 limit file remain the historical record.

Before activation, regenerate the v3 runtime pins from the final stacked source, bind the resulting plan digest in the verifier and trusted case policy, and update the selected workflow and runner inputs to use the v3 plan and v2 limits. The engine then serializes every selectable source-auditor request before writer dispatch and rejects the review if any request exceeds the plan's cap.
