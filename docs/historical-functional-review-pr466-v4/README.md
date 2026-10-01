# Historical PR 466 dependency-context trial (v4)

This closed, non-default packet tests the v12 dependency-context profile on the same fixed PR 466 base/head pair and captured historical check snapshot as v1–v3. The profile keeps the v11 task scope, required checks, context bindings, and limits while adding a bounded, source-revision-bound projection of Python dependency declarations and lock metadata to relevant review inputs. The projection is evidence about declared dependencies at the selected revision; it does not establish which packages were installed or resolve runtime behavior.

The packet uses the exact v2/v3 limits: 10 provider calls, zero retries and follow-ups, 80,000 input bytes per task, 600,000 context bytes, and a 600-second deadline. A fresh provider-free prepare at source revision `1f99d58eb5bd009da62a0537be7e7eed7cf88f5b` admitted all 15 planned obligations across seven primary requests totaling 441,227 serialized bytes. The largest request was 77,234 bytes. The dependency projection appeared in five primary task inputs and was bound to the PR HEAD. Optional-stage and total runtime demand remain unknown until primary results exist.

Sizing used placeholder provider configuration. Provider identity is `UNKNOWN`. The captured checks are a historical snapshot, not current PR or branch status. Select this case explicitly with `pr466-v4`; the workflow default remains v1. This prepare observation does not establish runtime completion, review quality, calibration, installed dependency state, or cutover readiness.

| File | Purpose |
|---|---|
| [`manifest.json`](manifest.json) | Binds fixed PR identity, profile/check/limit hashes, the fresh prepare-only descriptors, and the read-only scope. |
| [`historical-checks.json`](historical-checks.json) | Byte-identical captured check snapshot; SHA-256 `c7d3a28b0e12583dceb0021b04814573706f202a188e4cbed2d1ebde821d5963`. |
| [`limits.json`](limits.json) | Byte-identical v2/v3 limits; SHA-256 `964a11a8de3bfd47520ea62e358c954dceb1ac7da7f0648ef4db11d6f885870e`. |
| [`profiles/slopsearx-v12-dependency-context-candidate.json`](../../profiles/slopsearx-v12-dependency-context-candidate.json) | Non-deployed v12 dependency-context candidate; SHA-256 is recorded in the manifest. |
