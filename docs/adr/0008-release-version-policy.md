# 0008 — Release and version policy: SemVer plus independent contract versions

- **Status:** Accepted
- **Date:** 2026-11-02
- **Owner:** Repository maintainers (`groktopus/codereview`; `.github/CODEOWNERS` names `@magnus919`).
- **Decision authority:** Repository owner, through merged pull request [#294](https://github.com/groktopus/codereview/pull/294) (RS-2) and the release-policy statement in [VERSIONING.md](../VERSIONING.md).
- **Scope:** Package versions, contract-version identities, changelog, release tags, and the tag-triggered release workflow.
- **Evidence:** Commit `99bf34f`; [VERSIONING.md](../VERSIONING.md); [RELEASING.md](../RELEASING.md); [release-policy.v1.json](../../scripts/release-policy.v1.json); [release.yml](../../.github/workflows/release.yml); [test_version_policy.py](../../tests/test_version_policy.py); [test_release_workflow.py](../../tests/test_release_workflow.py); [RS-2](../issues/06-release-and-supply-chain.md).
- **Reversal/expiry:** No expiry. A change to version semantics, tag rules, or the release trigger requires a new or superseding record.
- **Supersedes:** None.
- **Superseded by:** None.
- **Related:** [ADR 0007](0007-license.md) supplies the license metadata; [RS-3](../issues/06-release-and-supply-chain.md) covers SBOM and attestation, which this record does not claim.

## Context

The package version was `0.1.0` with no policy for breaking contract changes, no changelog, and no tags or releases, even though the project versions review contracts, claim assessments, canary receipts, artifacts, and profiles independently. Consumers could not pin or upgrade deliberately, and release behavior was undefined.

## Decision

- Use `MAJOR.MINOR.PATCH` semantic versioning for the Python package, with a `v` tag that exactly equals `project.version`.
- Version contract identities independently in `contract_registry.json`; a package release never silently changes an existing contract's meaning. Incompatible changes create a new identity and a package release that declares it.
- Keep a `CHANGELOG.md` with `Unreleased`, classified entries, and a `Breaking` section for incompatible changes. Every behavior or promised-surface change updates it in the same pull request.
- Treat a tag as immutable once its GitHub Release exists. The release workflow does not create tags; it builds and verifies the tagged revision and refuses to overwrite an existing release.
- Release only from `main` after the required checks pass at the exact revision. The workflow uses the repository `GITHUB_TOKEN`, does not publish to PyPI, and escalates write permission only in the release job.
- `scripts/check_version_policy.py` and its tests enforce the version, changelog, registry, tag shape, and release-policy consistency.

## Consequences

- Consumers can pin a package version and separate contract identities deliberately.
- A contract change without a release-policy update fails the metadata checks.
- The first source version is `0.1.0`; this record does not claim that a tag or GitHub Release exists.
- Pre-1.0 rules still require a `Breaking` entry and migration note for incompatible changes.
- Supply-chain attestation and reproducibility remain RS-3 gaps, not part of this release policy.

## Alternatives considered

- **Calendar versioning.** Rejected: the project needs compatibility signaling for contracts, not date-based marketing versions.
- **Version only the package and not contracts.** Rejected: contracts, profiles, and receipts change independently and consumers must pin them.
- **Create releases from the workflow.** Rejected: a tag must be the trigger, and the workflow must not invent release identity.
- **Publish to PyPI as part of the first release.** Rejected for now: it adds an external publication and credential surface that RS-2 does not authorize.
- **Move or delete a published tag after a bad release.** Rejected: publish a follow-up patch instead.

## Evidence status

The policy, scripts, workflow, and tests are `OBSERVED` in the repository at the named revision. No tag, GitHub Release, or PyPI publication is claimed by this record.
