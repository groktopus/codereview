# Historical PR 466 related implementation context trial (v3)

This closed, non-default diagnostic packet binds the v11 candidate profile to the same historical PR 466 base/head and captured check snapshot as v1 and v2. The v11 candidate retains the existing policy and review scope while supplying a narrowly selected HEAD source window for `slopsearx/mcp/security.py` alongside its exact diff. It is an experiment in request context selection; it is not deployed and does not establish better review quality.

The limits are byte-identical to v2: 10 provider calls total, zero retries and follow-ups, 80,000 input bytes per task, 600,000 context bytes, and a 600-second deadline. A fresh offline prepare admitted 15 of 15 planned obligations across seven primary requests totaling 417,632 serialized bytes; the largest request was 72,737 bytes. It made zero provider calls and executed no target code. Three call slots remain after primary review, but optional-stage demand is unknown until primary results exist.

The prepare used placeholder provider configuration for request sizing. Provider identity remains `UNKNOWN`. The checks document is a historical snapshot, not a statement about current PR or branch status. Selection requires explicitly choosing `pr466-v3`; v1 remains the default and v2 is unchanged.

| File | Purpose |
|---|---|
| [`manifest.json`](manifest.json) | Fixed PR/base/head, profile and input hashes, fresh prepare-only descriptors, and read-only scope. |
| [`historical-checks.json`](historical-checks.json) | Byte-identical v2 captured checks; SHA-256 `c7d3a28b0e12583dceb0021b04814573706f202a188e4cbed2d1ebde821d5963`. |
| [`limits.json`](limits.json) | Byte-identical v2 limits; SHA-256 `964a11a8de3bfd47520ea62e358c954dceb1ac7da7f0648ef4db11d6f885870e`. |
| [`profiles/slopsearx-v11-related-implementation-context-candidate.json`](../../profiles/slopsearx-v11-related-implementation-context-candidate.json) | Candidate profile bound by the manifest SHA-256. |

Admission is not review completion, truth validation, calibrated performance, or release readiness. The packet authorizes no dispatch; any future run requires its own authorization.
