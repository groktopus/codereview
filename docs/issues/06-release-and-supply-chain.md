# Theme: Release and supply chain

**Scorecard dimension:** Operational and release readiness (current: C−)
**Target:** a licensed, versioned, reproducible release with SBOM, signed artifacts, a changelog, and locked development dependencies; a documented public API and install matrix.
**Why:** the CI already builds and smoke-tests wheel/sdist, but there are no releases, tags, license, changelog, or SBOM. A public repository without a license is not usable by anyone else, and "0.1.0" with floating dev dependencies is not reproducible.

---

## RS-1 — Add license and project governance files

- **Priority:** P1 (treat as immediate; the repository is public)
- **Dimensions:** Operational readiness; Governance
- **Problem:** The public repository has no LICENSE, SECURITY.md, or CONTRIBUTING.md. Without a license, default copyright applies and external use/contribution is legally unclear. Security reporting and contribution expectations are undocumented.
- **Scope:**
  - Choose and add a license (owner decision), with SPDX identifier in `pyproject.toml`.
  - Add SECURITY.md: supported versions, private reporting channel, response expectations, and scope.
  - Add CONTRIBUTING.md: development setup, test/lint commands, commit/PR expectations, compatibility-pin policy, review requirement.
  - Add CODEOWNERS (with GA-3).
  - Add a short provenance note for the project's own evidence/artifacts.
- **Exit criteria:** License is present and declared; GitHub detects it; SECURITY.md and CONTRIBUTING.md exist and are linked from README; the package metadata carries the license.
- **Verification:** `gh repo view --json licenseInfo`; wheel metadata; link check.
- **Depends on:** owner license decision.
- **Non-goals:** choosing a license on the owner's behalf.

---

## RS-2 — Establish versioning, changelog, tags, and a release pipeline

- **Priority:** P1
- **Dimensions:** Operational readiness
- **Problem:** There are no tags or releases and no changelog. Version is `0.1.0` with no policy for breaking contract changes, even though the project versions contracts, profiles, and receipts. Consumers cannot pin or upgrade deliberately.
- **Scope:**
  - Adopt semantic versioning for the package and a separate, explicit versioning rule for review/claim/canary contracts.
  - Add a changelog generated from merged changes, with breaking-change sections.
  - Cut signed/tagged releases from green main; attach wheel, sdist, checksums, and release notes.
  - Define what a version promises: CLI surface, artifact schema, contract compatibility.
  - Keep release notes free of quality or replacement claims.
- **Exit criteria:** At least one tagged release exists with artifacts and notes; every subsequent merge is classified for changelog impact; the version policy is documented and enforced.
- **Verification:** `git tag`, GitHub release assets, changelog entries, version-policy test.
- **Depends on:** RS-1.
- **Non-goals:** promising stability before the contract registry (CA-3) exists.

---

## RS-3 — Produce SBOM, provenance, and reproducible artifacts

- **Priority:** P2
- **Dimensions:** Operational readiness; Security
- **Problem:** The build records SHA-256 sums, but there is no SBOM, no artifact attestation, and no reproducibility check. Supply-chain claims rest on pinned Actions alone.
- **Scope:**
  - Generate an SBOM (CycloneDX or SPDX) for wheel and sdist, including the Python runtime constraints.
  - Emit build provenance/attestation (for example SLSA-style) and sign release artifacts.
  - Verify reproducibility: rebuild from the same source and compare hashes where feasible; document non-determinism if found.
  - Publish hashes and verification instructions with each release.
- **Exit criteria:** Every release has an SBOM and attestation; consumers can verify signatures/hashes; a reproducibility check runs in CI and its result is recorded.
- **Verification:** release assets; `cosign`/`sigstore` verification; rebuild hash comparison.
- **Depends on:** RS-2.
- **Non-goals:** claiming bit-for-bit reproducibility where timestamps or toolchains prevent it.

---

## RS-4 — Lock dependencies and publish the package contract

- **Priority:** P2
- **Dimensions:** Operational readiness; Security
- **Problem:** Runtime dependencies are deliberately empty (a strength), but development dependencies are floating ranges (`pytest>=8`, `ruff>=0.9`, …) with no lockfile or hashes. There is no documented public API surface or install matrix beyond implicit CI coverage.
- **Scope:**
  - Add a lockfile with hashes for the development/test environment and use it in CI.
  - Add dependency review and a scheduled vulnerability scan.
  - Document the supported Python versions, OS assumptions, and the public import surface; mark internal modules private.
  - Add an install matrix test for the documented combinations.
  - Keep the zero-runtime-dependency property as an explicit invariant with a test.
- **Exit criteria:** CI installs from a locked, hash-verified set; the zero-runtime-dependency invariant is tested; the public API and support matrix are documented; dependency review is active.
- **Verification:** lockfile hash check; `pip install --require-hashes`; an import-surface test; a dependency-review run.
- **Depends on:** RS-1.
- **Non-goals:** adding runtime dependencies without an explicit decision record.
