# Changelog

All notable changes to `pr-review-harness` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow the
[package versioning policy](docs/VERSIONING.md). Entries describe source changes;
a version heading does not by itself assert that a tagged GitHub Release exists.
See [RELEASING.md](docs/RELEASING.md) for the release procedure.

## [Unreleased]

### Added

- Frozen evaluation corpus v1: 41 real merged-PR cases across two public repositories, all three splits, with source manifests and no labels or quality claims (QM-1).

### Added

- Decision-record index and lightweight ADRs for architecture, transport, publication authorization, provider boundaries, evaluation gates, license, and release policy, with an executable index/field/status/safety-link check.
- Release supply-chain evidence: a deterministic CycloneDX SBOM generated from the built wheel and sdist, explicitly unsigned build provenance, a two-build reproducibility check recorded per release, release-asset SHA-256 coverage, and consumer verification documentation in `docs/SUPPLY-CHAIN.md`.
- A `Supply chain` CI job that runs the reproducibility check and SBOM/provenance verification on normal pushes and pull requests, plus release-workflow integration that publishes the evidence as release assets.
- Path-specific CODEOWNERS, an ownership/review/incident/credential record, backlog triage states and issue forms, and a structural check that keeps module ownership and the open-issue table consistent.


## [0.1.0] - 2026-11-02

Initial source version of the read-only review harness.

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

### Changed

- Publication remains disabled by default; the CLI `publish` command only renders a preview and the central publisher job is hard-disabled.
- Run metrics represent unknown token, latency, and cost values as `UNKNOWN` rather than zero.

### Security

- Read-only CodeQL, dependency-review, and secret-scanning workflows.
- Provider credentials are referenced through environment variable names and are never written to configuration files or logs.
- Target code, hooks, tests, and builds are not executed during review.

[Unreleased]: https://github.com/groktopus/codereview/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/groktopus/codereview/releases/tag/v0.1.0
