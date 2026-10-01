# Historical PR466 static-assessment diagnostic v5 — 2026-10-01

[Run 36938919590](https://github.com/groktopus/codereview/actions/runs/36938919590) completed both jobs at source `dd2ffe68f4650f6023de4dd77aac972777269a8c`. The reviewed source PR190 had independent Luna review and 20 enabled checks passing at its exact head; [post-merge run 36938901546](https://github.com/groktopus/codereview/actions/runs/36938901546) passed all ten jobs. CI success is implementation evidence, not review-quality evidence.

## Frozen scope and preparation

Target: `magnus919/SlopSearX` PR466, base `63e3ecd2f09d79c34e3594a3be74f017a1c5a12c`, head `7bce9dd246f141eb961c52ae96061203a98f083b`. Profile v13 SHA-256: `f1a566359a7a5a9af317159dcc962e8b0223e90513516cc25a4f785200ee3156`. Checks SHA-256: `c7d3a28b0e12583dceb0021b04814573706f202a188e4cbed2d1ebde821d5963`. Limits SHA-256: `964a11a8de3bfd47520ea62e358c954dceb1ac7da7f0648ef4db11d6f885870e`.

Provider-free preparation admitted all 15 obligations across seven primary requests totaling 441,143 bytes (largest 77,234), with zero provider calls or target execution. The exact HEAD dependency projection is 858 bytes and records declarations/lock absence; installed FastMCP runtime remains unknown. V13 changes only the profile version and tests-lens criterion relative to v12. This one nonrandomized observation does not establish a causal effect of the prompt change.

## Observed review

The result is **INCOMPLETE / PARTIAL**: 12 obligations complete, three partial, merge eligibility `NOT_EVALUATED`. No blocker or recommendation was presented. The partials are dependency correctness (SDK compatibility across declared versions unresolved), dependency security (required coverage note quarantined), and documentation tests assessment (implementation evidence reported absent). Related HEAD evidence was supplied, but no installed-runtime execution was established. These states remain partial; they are not relabeled as completed assessments.

One candidate remained `NEEDS_EVIDENCE`, with validation reason `location_or_evidence_not_validated`. Semantic claim assessment was `NOT_RUN / PRIMARY_CANDIDATE_INVALID`. It claimed the revoked-token probe still uses GET at `tests/test_mcp_oauth.py:363`. Exact HEAD lines 349–354 use POST and expect 401; line 363 is an unrelated client-registration assertion. BASE lines 347–348 contained the old GET. Its cited HEAD source window covers lines 327–373 and contradicts the observation. This refutes that textual candidate; it does not execute or certify OAuth behavior. The candidate was withheld from recommendations rather than accepted as a finding.

Six optional strengths were quarantined as `invalid_report_note`; one required security coverage note was quarantined as `invalid_coverage_note`. Raw discarded note contents were not retained, so the specific live validation causes are unknown. A separately reproduced adapter defect retains external note fields where engine settlement requires `detail`; fixing that defect does not retrospectively establish every live note's shape.

## Usage and effects

Eight settled provider-call records: seven LLM and one Jev, zero retries. Two local deterministic checks and one bounded context retrieval are separate. The retrieval returned a 90-byte envelope and zero source bytes because the symbol lookup was outside its supported contract. LLM usage: 112,690 input plus 4,133 output tokens, 116,823 total. Jev usage, billing, and spend remain unknown. Jev returned advisory uncalibrated Noul `UNRESOLVED`, probability 0.66. Reserved context was 479,321/600,000 bytes; reserved output was 160,000/192,000 bytes, with no recorded budget breaches. Reservations and local HTTP observations are not proof of remote billing.

The workflow has contents-read permission, uses a bare target repository, and did not execute target code, publish a report to the PR, change target configuration, or mutate the target PR. These scoped observations do not establish universal effect isolation, accuracy, calibration, injection resistance, or Droid replacement readiness.

## Retained artifact identities

| Artifact | SHA-256 |
|---|---|
| prepare-observation.json | `ec5977f1b7a5c24e77b5d225140a74c101819e305e402261146b4e5dfa462ee5` |
| review-result.json | `208e859cdccddd7233e73dcb4e85754f1e2033658a05518f71404fdceff2fa8e` |
| review-report.md | `4c357ce3d99e6a79d17dc05f58032e9ac891646441ceb00e2d49ea05c06907c5` |

The next comparison must bind a reviewed contract/schema revision and fresh exact request preparation. Do not silently update historical packets or retry identical inputs to select a favorable result.
