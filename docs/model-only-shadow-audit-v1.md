# Model-only shadow audit v1

The shadow runner performs three bounded calls over one frozen case packet:

1. A source-only OpenAI-compatible auditor receives the frozen task and cited source evidence. Its output is sealed locally before Jev is called, and its request never includes the writer candidate.
2. The existing `ClaimAssessmentAdapter` asks Jev to classify that candidate against the same evidence.
3. A separate claim-facing auditor receives the candidate, Jev's typed classifications, and only the cited source evidence. It does not receive the source-only auditor output.

The CLI is `scripts/run_shadow_audit.py`. It requires `--live` before it can dispatch. It permits at most one call per stage, has per-request byte limits and a finite deadline, does not retry, execute target code, or publish a review. Run with a reviewed `model-only-shadow-case.v1` JSON packet, separate provider configs, a trusted TypeSafe decision config, and a new output directory. The emitted manifest contains statuses, identities, and hashes. Exact request and structured-response bytes remain in mode-0600 files beneath a mode-0700 output directory; do not upload those files as CI artifacts.

The packet must carry the full original snapshot. Its `snapshot_hash` is recomputed using the harness snapshot contract over every snapshot field other than `snapshot_id` and `snapshot_hash`. The frozen PR-457 trial material in `docs/real-case-trial-v1` contains its snapshot digest and evidence bindings, but not the full snapshot payload, so that material alone cannot be used to reconstruct or claim verification of the original snapshot.

This v1 runner is pre-v2 comparison packaging. Its `writer` role envelope is declared from the supplied packet and is not joined to or byte-verified against private writer artifacts. The persisted review result currently stores parsed writer candidate data and task hashes, but not exact writer request/response bytes or the full frozen snapshot. The runner therefore requires an independently captured packet and will not synthesize writer provider artifacts from parsed result JSON. A capture bundle must export the original snapshot and exact writer structured-response bytes and join them to the writer role before a v2 comparison can claim four-role provenance or be verified by the v2 relation contract.

All model judgments are advisory. Unknowns, abstentions, incomplete output, and failures remain explicit. These outputs do not establish accuracy, ground truth, or release readiness. The injection fixture verifies that source text is delivered as untrusted data and does not cross stage boundaries; it does not measure model resistance to prompt injection.
