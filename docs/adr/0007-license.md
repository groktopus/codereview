# 0007 — License: MIT for original code and documentation

- **Status:** Accepted
- **Date:** 2026-11-01
- **Owner:** Repository owner (`@magnus919`; `.github/CODEOWNERS`), who authored and merged the change.
- **Decision authority:** Explicit owner decision, recorded by the owner-authored license commit `93f5da7` and merged pull request [#292](https://github.com/groktopus/codereview/pull/292) (RS-1).
- **Scope:** The repository's original source code, documentation, and packaging metadata. Third-party content and retained evidence remain subject to their own terms.
- **Evidence:** [LICENSE](../../LICENSE); `project.license = "MIT"` and `license-files = ["LICENSE"]` in [pyproject.toml](../../pyproject.toml); [PROVENANCE.md](../PROVENANCE.md); commits `93f5da7` and `611baf1`; [RS-1](../issues/06-release-and-supply-chain.md).
- **Reversal/expiry:** No expiry. A different license or dual licensing requires an explicit owner decision and a superseding record; it cannot be changed by a routine pull request.
- **Supersedes:** None.
- **Superseded by:** None.
- **Related:** [ADR 0008](0008-release-version-policy.md) governs release metadata; neither record grants rights to third-party content.

## Context

The public repository had no license before RS-1, so default copyright applied and external use and contribution were legally unclear. The owner selected MIT and added the license together with security, contribution, ownership, and provenance files.

## Decision

- License the repository's original code and documentation under the MIT License, copyright 2026 `groktopus`.
- Declare the same license in package metadata using the PEP 639 expression `MIT` with the `LICENSE` file.
- Do not infer a license for provider output, target-repository content, frozen evidence, or other third-party material from this repository's MIT license.
- Keep the license and packaging declaration consistent; a change to either is a governance change, not a routine metadata edit.

## Consequences

- External use and contribution have a clear default license.
- The MIT text and the package metadata must stay synchronized.
- Retained evidence remains auditable but is not relicensed by this decision.
- The repository makes no warranty or support commitment beyond the license text and the security policy.

## Alternatives considered

- **Apache-2.0.** Considered; not selected by the owner. It adds an explicit patent grant and notice obligations that the project did not choose to adopt.
- **Dual license or a source-available license.** Rejected: the owner chose a simple permissive license for a public harness.
- **No license.** Rejected: default copyright would leave external use and contribution unclear.

## Evidence status

The license text, package metadata, and owner-authored merge are `OBSERVED` in the repository. This record is not legal advice.
