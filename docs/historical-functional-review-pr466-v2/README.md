# Historical PR 466 bounded-context trial (v2)

This non-deployed trial applies a distinct v10 identity to the measured v9 24KB SlopSearX context-selection experiment for the same fixed historical PR 466 base/head pair and captured check snapshot as v1. The HEAD-side test and documentation windows were already part of v9. The v10 profile is semantically identical to that measured v9 profile except for its version string; it preserves the same BASE dependencies, policy paths, lenses, risk rules, required checks, and task scope. The v2 limits raise only `max_input_bytes_per_task` from the historical 64,000-byte cap to 80,000 bytes. Context remains 600,000 bytes, provider calls remain capped at 10, retries and follow-ups remain disabled, and the review deadline remains 600 seconds. This is an experimental capacity setting, not a deployed default or evidence of improved review quality.
The prepare record’s `source_revision` identifies the harness source used for that local measurement; `profile_sha256` separately binds the external profile file. The prepare-only sizing used placeholder provider configuration for serialization. Provider identity remains UNKNOWN, and these request descriptors do not attest a production endpoint or model.

## Fixed evidence

| File | Purpose |
|---|---|
| [`manifest.json`](manifest.json) | Binds PR/base/head, profile and limits hashes, unchanged historical check identity, provider identity as UNKNOWN, and this prepare-only observation. |
| [`historical-checks.json`](historical-checks.json) | Byte-identical captured check document from v1; SHA-256 `c7d3a28b0e12583dceb0021b04814573706f202a188e4cbed2d1ebde821d5963`. Its freshness basis remains `HISTORICAL_SNAPSHOT`. |
| [`limits.json`](limits.json) | Exact v1 limits with only `max_input_bytes_per_task` changed to 80,000 bytes. |
| [`profiles/slopsearx-v10-bounded-head-context-trial.json`](../../profiles/slopsearx-v10-bounded-head-context-trial.json) | Distinct trusted experimental profile, version `slopsearx-production-v10-bounded-head-context-trial`; SHA-256 is recorded in the manifest. |

## Provider-free prepare observation

The production CLI `--prepare-only` path admitted all 15 of 15 planned obligations across seven primary requests totaling 394,539 serialized bytes. Each primary request was within the experimental 80,000-byte per-task cap, and the aggregate primary bytes were within the 600,000-byte context cap. The manifest records each request size and input hash. The run made zero provider calls and executed no target code.

A separate local check of the actual wrapper's `prepare --case pr466-v2` entry point also admitted all 15 obligations: seven requests totaled 394,490 bytes with the wrapper's sizing configuration. These are separate placeholder-config observations, not identical production request descriptors. Live execution must size its actual trusted configuration before any provider call.

This does not establish runtime completion: after primary review, three call slots remain, but candidate counts, optional-stage request sizes, and total runtime demand are unknown until primary results exist. Claim assessment is capped at one; summary advisory capacity is one; follow-ups and source-auditor calls are disabled. No provider identity is recorded. This packet does not establish accuracy, calibration, replacement readiness, or cutover evidence.

The separate v1 packet and deployed v8 profile remain unchanged. The experiment is read-only and does not update SlopSearX or its configuration.
