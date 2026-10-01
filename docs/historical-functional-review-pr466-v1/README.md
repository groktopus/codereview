# Historical PR 466 functional-review diagnostic

This is a bounded diagnostic packet for one historical SlopSearX change: `magnus919/SlopSearX` PR 466, base `63e3ecd2f09d79c34e3594a3be74f017a1c5a12c`, head `7bce9dd246f141eb961c52ae96061203a98f083b`. It uses the v8 static-review profile and preserves the captured checks and prepared request sizing as historical evidence.

The packet is not a quality evaluation, a calibrated comparison, or a cutover decision. Human labels are unavailable. The Jev assessment is advisory and cannot establish correctness. The current provider configuration identity is `UNKNOWN`; no credential values or actual endpoint/model identity are recorded here.

## Evidence files

| File | Purpose |
|---|---|
| [`manifest.json`](manifest.json) | Binds the case, profile, check and limits hashes, unknown provider identity, and the retained prepare-only sizing observation. |
| [`historical-checks.json`](historical-checks.json) | Exact captured check JSON bytes from the historical preparation; SHA-256 `c7d3a28b0e12583dceb0021b04814573706f202a188e4cbed2d1ebde821d5963`. |
| [`limits.json`](limits.json) | Finite runtime limits for a future authorized diagnostic; SHA-256 `5b92e2381ba6c15e8afc2b77d7437d3cbb53a8ff6275e1b18617218753b364d6`. |

The check capture says it was collected at `2026-09-27T04:06:00Z` for the exact PR base/head above. Its `complete: true` field describes that captured snapshot. The results are historical and are not a claim about current check status or freshness.

The profile is `slopsearx-production-v8-static-review-boundaries`, at `profiles/slopsearx.json`, SHA-256 `cc9c4631882662c27be5fb8534e65abbd352489afefa78e9dd3d3160fe0b1c65`. The manifest binds the profile file digest rather than provider secrets or an inferred live configuration identity.

## Retained prepare-only observation

The retained preparation recorded seven primary request descriptors totaling `353,963` serialized input bytes. That preparation used `--max-claim-assessments 0`; the proposed diagnostic allows at most one claim assessment, so the retained primary sizing is not a new sizing result for that run. It recorded `PREPARED_ONLY`, zero provider calls, and no target-code execution. The manifest retains the seven descriptor sizes and hashes plus the descriptor-set hash, but no request bodies. This is sizing evidence from a prior preparation, not a new review result or a provider-dispatched run.

## Bounded diagnostic scope

The current plan uses the existing CLI primary review plus at most one Jev claim assessment (`--max-claim-assessments 1`). It does not add a separate source auditor. The provider-call limit is ten total, with a twelve-call case ceiling retained for future capacity accounting; unused headroom is not permission to add model roles. Calls do not retry. Context follow-ups are disabled. The review engine deadline is 600 seconds; the wrapper subprocess timeout is 630 seconds to bound process startup and shutdown around the engine deadline. Other configured limits are 600,000 context bytes, 64,000 input bytes per task, 16,000 output bytes per task, and 1,800 output tokens.

Any later diagnostic run must use the exact manifest identity and historical check file. It must report dynamic demand, missing evidence, abstentions, failures, or over-cap conditions without converting them to a clean result. A Jev label remains advisory; no score or model agreement is ground truth. This packet does not complete the 39 acceptance criteria, 12 nonfunctional requirements, or six delivery milestones, and it does not establish replacement readiness.

No provider call, GitHub API request, PR mutation, or target-code execution occurred while preparing these files. The workflow/CLI owner is responsible for the later bounded entrypoint; this directory contains no credentials and does not itself dispatch it.
