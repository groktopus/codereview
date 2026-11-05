# Changelog

All notable changes to `pr-review-harness` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow the
[package versioning policy](docs/VERSIONING.md). Entries describe source changes;
a version heading does not by itself assert that a tagged GitHub Release exists.
See [RELEASING.md](docs/RELEASING.md) for the release procedure.

## [Unreleased]

### Added

- Owner-approved bounded evidence waivers for `pr-review review`: `--waiver FILE` accepts a strict `review-evidence-waiver.v1` object bound to a named reviewer, written reason, exact repository/base/head, and timezone-aware issue/expiry (issued time must not be in the future and lifetime is capped at 90 days). Exact planned obligations or uniquely matching reason codes can turn only the matching required `PARTIAL`/`NOT_STARTED`/`UNKNOWN` rows into `WAIVED`; a reason code matching more than one obligation is rejected, and every target is resolved to exactly one planned obligation before dispatch, rejecting ambiguous check aliases and any two targets that overlap the same obligation. Waived rows never become `COMPLETE`, never clear findings or blockers, and are rejected before provider dispatch when invalid, expired, out of scope, duplicated, overbroad, or unknown. A run with any waived obligation reports `COMPLETE_WITH_WAIVERS` and is capped at `COMMENT`; the waiver presence/source digest is bound into the request hash and resume identity. Results and reports expose `waiver_receipt`, `waivers_applied`, `waivers_not_applied`, and waived completeness entries with the source file SHA-256. The completeness taxonomy and run metrics add a distinct `WAIVED` count; `complete_ratio` still counts only complete evidence. The feature records a scoped, one-time 565-line source allowance in [ADR 0011](docs/adr/0011-bounded-evidence-waiver.md); the general feature budget is not renewed. See [review completeness](docs/REVIEW-COMPLETENESS.md#4-bounded-evidence-waiver).

## [0.1.2] - 2026-11-04

### Added

- Release `0.1.2` retains the SHA-pinned `actions/attest-build-provenance` v2.4.0 action for wheel and sdist attestations; `v0.1.0` remains unsigned while `v0.1.1` and `v0.1.2` carry keyless GitHub OIDC provenance.
- Owner-accepted synthetic model-teacher adjudication ([ADR 0010](docs/adr/0010-synthetic-model-teacher-adjudication.md)): a `reviewer_kind: synthetic` labels extension with exact model/prompt/rubric/run/hash provenance, separate human and synthetic arms, and rejection of synthetic packets mislabelled as human. Human packets remain optional.
- `review-evaluation-scorecard.v2` and `review-evaluation-scorecard-gate.v2`: per-evaluation-arm `human` and `synthetic` label arms, synthetic-only `COMPLETE` without human packets, synthetic metrics scoped as non-human, and arm-specific regression checks (`<metric>:<arm>:<label-arm>`).
- Retained synthetic QM-2 pilot over the fixed six-case subset: the six exact diffs, exact teacher prompt, request binding prompt/diff hashes and byte counts, raw teacher response, six-packet teacher output, and `labels-synthetic-v1.json` with `reviewer_kind: synthetic` packets. Five complete cases are `NO_KNOWN_MATERIAL_DEFECTS` with empty findings; `qm1-slopsearx-pr770` is `INCOMPLETE`/`INCONCLUSIVE` because the frozen manifest records incomplete evidence. The scorecard remains `MISSING_DATA` without prediction runs, and the pilot makes no human-truth, quality, or replacement claim.
- VD-4 canonical formatting: `ruff format` now defines repository formatting at the configured 120-column width, the maintained tree (`src/`, `scripts/`, `experiments/`, `tests/`, and the remaining Python files) is formatted, and a `Formatting and complexity ratchets` CI job runs `ruff format --check .`. The sha256-pinned historical compatibility fixtures remain excluded from formatting because reformatting them would break their VD-3 pins.
- VD-4 complexity guard: `scripts/check_complexity.py` fails functions over 150 physical lines unless they appear in the explicit checked-in `scripts/complexity-baseline.v1.json`, and a baselined function may not grow past its recorded length. It supports manifest and `--diff-base` modes, emits JSON and Markdown reports, and is exercised by `tests/test_complexity_guard.py` and a seeded CI failure.
- VD-4 pre-commit configuration: `.pre-commit-config.yaml` pins `ruff-pre-commit` to the locked ruff release, runs `ruff check --fix` and `ruff format` matching CI, and runs the complexity guard.
- VD-3 pin-refresh tooling `scripts/refresh_compatibility_pins.py`: dry-run by default with atomic `--confirm` writes, mandatory `--reason` and `--source-revision` provenance, SHA-256 recomputation for every `pin_files` entry, refusal of missing files or an unchanged pin set, and an append-only `refresh_history` recording the name, old/new digests, timestamp, reason, and source revision. It makes no network requests and emits sanitized output; `tests/test_refresh_compatibility_pins.py` covers each refusal and the provenance record.
- Canary-only review publication adapter `scripts/canary_publish_review.py`: a one-shot, pinned `magnus919/SlopSearX` PR 1097 command requiring `--authorize-publish`, a non-symlinked owner-only PEM, a writable receipt directory preflight, and a repository-scoped `pull_requests:write` installation token. It fails closed on moved/closed heads, verifies existing marker reviews by bot author, `COMMENTED` state, commit, and exact body SHA-256, writes atomic `VERIFIED` or `ALREADY_PUBLISHED` receipts, and is not wired into the CLI or Actions publication paths.

### Changed

- Re-baselined the recorded `src/pr_review_harness` physical line count from 30,870 to 31,725 after canonical formatting and added a one-time, measured 855-line `formatting_normalization_allowance_lines` to the CA-2 source-line gate (the owner approved an allowance of up to 900 lines; the manifest records the exact measured delta). The 500-line feature budget and the 25% CA-2 outcome are unchanged; the allowance is formatter normalization, not feature headroom (see [ADR 0001](docs/adr/0001-post-ca2-feature-budget.md)).
- `CONTRIBUTING.md`, the README, `docs/ARCHITECTURE.md`, `docs/RELEASING.md`, and the VD-4 issue record document the new formatting, pre-commit, and complexity commands, the immutable-fixture exclusion, and the remaining VD-4 lint-expansion and typing work.

## [0.1.1] - 2026-11-02

### Added

- Keyless GitHub OIDC build provenance attestations for the release wheel and source distribution: the release build job runs the SHA-pinned `actions/attest-build-provenance` v2.4.0 after the artifacts and their evidence are verified, with `subject-path` covering `dist/*.whl` and `dist/*.tar.gz`. The build job has only `contents: read`, `id-token: write`, and `attestations: write`; consumers verify with `gh attestation verify <artifact> --repo groktopus/codereview`. The existing unsigned `provenance.json` and CycloneDX SBOM remain attached as the inspectable unsigned layer, and `v0.1.0` remains unsigned.

## [0.1.0] - 2026-11-02

Initial source version of the read-only review harness.

This section records the source changes included in the release; it is not
evidence that a tag or GitHub Release exists.

### Added

- `pr-review` CLI with `review`, `publish` (read-only preview), and `stats` commands.
- Deterministic snapshot, planner, stage scheduler, budget, and disposition pipeline over immutable Git objects.
- OpenAI-compatible primary review provider plus optional advisory Jev and native claim-assessment adapters.
- Bounded context selection, external check ingestion, claim reconciliation, and incomplete-reason reporting.
- Contract and version registry with supported, deprecated, archived, and experimental identities.
- GitHub Actions reusable analysis workflow and a separately installed target-local protected-publication runtime.
- Versioned artifact contracts and schemas for review results, run summaries, price tables, and cross-model comparisons.
- Packaging as a wheel and source distribution with an installed-entry-point smoke test.
- Operations, deployment, provenance, threat-model, and verification documentation.
- Version policy, changelog, machine-readable release policy, and a tag-gated release workflow that attaches wheel/sdist checksums and notes.
- Hash-locked development/test environment: `uv.lock` plus a SHA-256-hashed `requirements-dev.lock` exported from `pyproject.toml`, a mandatory `lock-freshness` CI job (`uv lock --check` and byte-identical export diff), and a scheduled `uv audit --locked` vulnerability scan that does not gate pull requests (RS-4).
- A documented public import/CLI surface and internal-module policy (`docs/PUBLIC-API.md`) plus a support and install matrix (`docs/SUPPORT-MATRIX.md`) covering Python 3.11–3.14 and Linux, macOS, and Windows install smoke checks, linked from the root README and the documentation index.
- Executable RS-4 contracts: an import-surface test, a zero-runtime-dependency invariant test over `pyproject.toml` and the built wheel's `METADATA`, lock freshness/hash tests, and SHA-pinning/scheduled-scan workflow checks.
- An `install-matrix` CI job that installs the built wheel without development dependencies into fresh environments and runs `pr-review --help` on every documented combination.
- Frozen evaluation corpus v1: 41 real merged-PR cases across two public repositories, all three splits, with source manifests and no labels or quality claims (QM-1).
- Versioned QM-2 labeling rubric/protocol, including severity, introducedness, evidence, abstention, independent/adjudicated packets, `reviewer_kind` rules, provenance, and relabeling as new packet versions, plus an empty six-case labeling pilot subset.
- Deterministic QM-3 quality scorecard generator and regression gate over corpus/predictions/labels, with completion, precision/recall bounds and denominators, abstention, duplicate/unadjudicated counts, `APPROVE`-with-known-defect counts, per-arm missing status, evaluator revision, and input hashes; missing labels/arms are reported as missing and accuracy remains refused.
- A `quality-scorecard` CI job that generates and uploads the empty-pilot scorecard and demonstrates a seeded regression fails the gate while empty data returns `MISSING_DATA`.
- Decision-record index and lightweight ADRs for architecture, transport, publication authorization, provider boundaries, evaluation gates, license, and release policy, with an executable index/field/status/safety-link check.
- PR-diff GA-2 enforcement: the review receipt accepts an optional `decision_records` list, and a fail-closed `Decision record links` check reads the changed-file list from the read-only GitHub API and requires indexed, `Accepted` decision records on the pull request base revision when a safety-invariant path changes (issue #270; branch protection was absent at release time — historical note: it was enabled after `v0.1.0`, requiring both review checks with a sole-maintainer administrator bypass).
- Release supply-chain evidence: a deterministic CycloneDX SBOM generated from the built wheel and sdist, explicitly unsigned build provenance, a two-build reproducibility check recorded per release, release-asset SHA-256 coverage, and consumer verification documentation in `docs/SUPPLY-CHAIN.md`.
- A `Supply chain` CI job that runs the reproducibility check and SBOM/provenance verification on normal pushes and pull requests, plus release-workflow integration that publishes the evidence as release assets.
- Path-specific CODEOWNERS, an ownership/review/incident/credential record, backlog triage states and issue forms, and a structural check that keeps module ownership and the open-issue table consistent.

### Changed

- Publication remains disabled by default; the CLI `publish` command only renders a preview and the central publisher job is hard-disabled.
- Run metrics represent unknown token, latency, and cost values as `UNKNOWN` rather than zero.

### Security

- Read-only CodeQL, dependency-review, and secret-scanning workflows.
- Provider credentials are referenced through environment variable names and are never written to configuration files or logs.
- Target code, hooks, tests, and builds are not executed during review.

[Unreleased]: https://github.com/groktopus/codereview/compare/v0.1.2...HEAD
[0.1.1]: https://github.com/groktopus/codereview/releases/tag/v0.1.1
[0.1.0]: https://github.com/groktopus/codereview/releases/tag/v0.1.0

[0.1.2]: https://github.com/groktopus/codereview/releases/tag/v0.1.2
