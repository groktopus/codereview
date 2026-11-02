# Supply chain and release evidence

**Status:** current release evidence contract. **Owner:** groktopus/codereview
maintainers. **Issue:** #261 (RS-3).

This document describes the evidence attached to a GitHub Release for
`pr-review-harness`, how to verify it, and what it does not prove. The release
workflow and the retained workflow run are the authority for whether a release
and its assets exist; this document is not evidence that a release has been
created.

When a release is published, its assets are a wheel, a source distribution,
`SHA256SUMS`, a CycloneDX SBOM, unsigned provenance, the reproducibility
report, and `RELEASE-NOTES.md`. Starting with `0.1.1`, the release build job also
records a keyless GitHub OIDC build provenance attestation for the wheel and
source distribution; GitHub stores that attestation in its attestations API
rather than attaching it as a file asset. The workflow does not publish to PyPI
and does not create tags. The artifacts themselves are not signed: the signed
layer is the attestation, while the attached `provenance.json` and SBOM remain
unsigned, self-asserted evidence. The earlier `v0.1.0` release has no
attestation and remains unsigned.

## Release assets

| Asset | Produced by | What it establishes |
|---|---|---|
| `pr_review_harness-<version>-py3-none-any.whl` | `check_reproducible_build.py` (first of two builds) | The installable wheel. |
| `pr_review_harness-<version>.tar.gz` | `check_reproducible_build.py` (first of two builds) | The source distribution. |
| `SHA256SUMS` | `sha256sum` over the wheel, sdist, SBOM, provenance, reproducibility report, and release notes | SHA-256 of each listed asset. |
| `pr-review-harness-<version>.cdx.json` | [`scripts/generate_sbom.py`](../scripts/generate_sbom.py) | CycloneDX 1.5 inventory of the actual wheel and sdist. |
| `provenance.json` | [`scripts/generate_provenance.py`](../scripts/generate_provenance.py) | Source revision, workflow ref, builder identity, and artifact hashes, explicitly marked unsigned. |
| GitHub build provenance attestation | Pinned `actions/attest-build-provenance` in the release `build` job | Signed, keyless statement binding the wheel and sdist digests to this repository, workflow, and source revision; stored by GitHub's attestations API, not listed in `SHA256SUMS`. |
| `REPRODUCIBILITY.json` / `REPRODUCIBILITY.md` | [`scripts/check_reproducible_build.py`](../scripts/check_reproducible_build.py) | Two-build hash comparison and recorded non-determinism. |
| `RELEASE-NOTES.md` | `scripts/check_version_policy.py` | Changelog-derived release notes. |

`SHA256SUMS` covers the evidence files as well as the distributions, so a
tampered SBOM or provenance file fails `sha256sum -c`.

## SBOM

The SBOM is generated from the built wheel and sdist, not from
`pyproject.toml`. For each distribution it reads the embedded `METADATA` or
`PKG-INFO` and records:

* package name and version, taken from the distribution metadata;
* the SPDX license identifier `MIT` (SBOM generation fails if an artifact
  declares a different license);
* `Requires-Python` (for example `>=3.11`);
* a zero runtime-dependency count, with SBOM generation failing if any artifact
  declares a non-extra `Requires-Dist`;
* each distribution file name, size, kind, and SHA-256.

The document is CycloneDX 1.5 JSON. The serial number is a UUIDv5 derived from
the package identity and artifact hashes, so the same artifacts produce the same
SBOM. `metadata.timestamp` is written only when `--created` or
`SOURCE_DATE_EPOCH` is supplied; the release workflow supplies the tagged
commit's timestamp. The generator is stdlib-only and adds no runtime dependency.

Limits: the SBOM inventories the distributions and their package metadata. It
does not enumerate every file inside the archives, and it does not attest the
development environment or development dependencies (RS-4 covers locking).

## Provenance

`provenance.json` is an in-toto Statement v1 with an SLSA provenance v1
predicate shape. It records:

* every release artifact and its SHA-256 under `subject`;
* the repository, source revision, source ref, workflow ref, and workflow SHA;
* the builder identity, invocation id, Python version, builder image, and build
  command;
* the tagged commit's `SOURCE_DATE_EPOCH`;
* `signing.status: "unsigned"` with `signature: null`, a reason, and explicit
  limitations.

The builder identity and workflow fields are **self-asserted by the release
script**. Anyone who can run the script can write the same fields. The file
makes the build inputs inspectable and lets a consumer bind the published
artifact hashes to a recorded source revision; it does not authenticate the
builder.

`provenance.json` is retained as unsigned, human-inspectable metadata. It is
not a signature and must not be described as one; the signed layer is the
separate GitHub build provenance attestation described below.

## Signed build provenance attestation

Starting with `0.1.1`, the `build` job of
[`.github/workflows/release.yml`](../.github/workflows/release.yml) attests the
wheel and source distribution after their checksums, SBOM, and provenance have
been verified:

* it uses `actions/attest-build-provenance` pinned to a full commit SHA
  (v2.4.0);
* `subject-path` covers `dist/*.whl` and `dist/*.tar.gz`, so one attestation
  binds both distribution digests;
* the build job requests only `contents: read`, `id-token: write`, and
  `attestations: write`; GitHub exchanges the workflow's OIDC token for a
  short-lived Sigstore signing certificate, so no long-lived signing key or
  repository secret is used;
* GitHub stores the resulting Sigstore bundle in the repository's attestation
  store and records it in the public transparency log when the repository is
  public.

The attestation is not attached as a release asset and is not listed in
`SHA256SUMS`. The general verification form is
`gh attestation verify <artifact> --repo groktopus/codereview`. Verify each
downloaded artifact against the repository:

```sh
gh attestation verify ./pr_review_harness-0.1.1-py3-none-any.whl \
  --repo groktopus/codereview
gh attestation verify ./pr_review_harness-0.1.1.tar.gz \
  --repo groktopus/codereview
```

A passing verification establishes that the attestation was issued by this
repository's release workflow for that exact artifact digest through a GitHub
Actions identity. It does not prove that the source is correct or that the
review harness is effective, and it does not replace checking the checksums and
SBOM. If attestation creation fails, the build step fails and the `publish` job
does not run.

`v0.1.0` was published before the attestation step existed: it remains unsigned
and has no GitHub attestation. Do not claim an attestation for `v0.1.0`
artifacts, and do not treat a later version's attestation as covering them.

## Reproducibility

The release build and the `Supply chain` CI job run
`scripts/check_reproducible_build.py`. It copies the source tree twice, builds a
wheel and sdist in each copy with a fixed `SOURCE_DATE_EPOCH`, `PYTHONHASHSEED`,
timezone, and locale, and compares the results at two levels:

* artifact SHA-256 (byte-for-byte);
* archive member content (names, modes, sizes, and file hashes).

The report has one of three statuses:

| Status | Meaning |
|---|---|
| `REPRODUCIBLE` | Every artifact is byte-for-byte identical. |
| `CONTENT_REPRODUCIBLE` | Artifact bytes differ, but every archive member is identical. |
| `NOT_REPRODUCIBLE` | Archive content or the artifact set differs. |

The implementation-time run on Python 3.14 with `build` 1.6.1 and setuptools
84.2.1 produced `CONTENT_REPRODUCIBLE`: the wheel was byte-for-byte identical,
while the source distribution differed only in gzip-header and tar entry mtimes (including directory entries). setuptools does not clamp those timestamps to
`SOURCE_DATE_EPOCH`; file contents were identical. This is recorded as
non-determinism, not as bit-for-bit reproducibility. The status can change with
the Python, `build`, setuptools, or zlib versions, which is why the report is
retained per release.

`CONTENT_REPRODUCIBLE` does not fail the CI job; `NOT_REPRODUCIBLE` does. Pass
`--require-identical-artifacts` to treat `CONTENT_REPRODUCIBLE` as a failure.

Run the check locally:

```sh
python3 -m pip install --require-hashes --no-deps -r requirements-dev.lock
python3 -m pip install --no-deps --no-build-isolation -e .
python3 scripts/check_reproducible_build.py \
  --source-date-epoch "$(git show -s --format=%ct 'v0.1.1^{commit}')" \
  --json-out /tmp/reproducibility.json \
  --summary /tmp/reproducibility.md
```

Or compare two existing distribution directories without rebuilding:

```sh
python3 scripts/check_reproducible_build.py \
  --compare /tmp/release-a /tmp/release-b \
  --source-date-epoch 1762074000
```

## Verify a published release

Download the assets and verify the checksums first:

```sh
gh release download v0.1.1 --dir /tmp/pr-review-release
cd /tmp/pr-review-release
sha256sum -c SHA256SUMS
```

Then verify the signed build provenance attestation for each distribution:

```sh
gh attestation verify ./pr_review_harness-0.1.1-py3-none-any.whl \
  --repo groktopus/codereview
gh attestation verify ./pr_review_harness-0.1.1.tar.gz \
  --repo groktopus/codereview
```

For `v0.1.0`, `gh attestation verify` has nothing to verify: that release
remains unsigned and predates the attestation step.

Then check that the SBOM, provenance, and checksums agree with the actual files.
Use the verification script from the repository at the same tag:

```sh
git clone https://github.com/groktopus/codereview /tmp/pr-review-repo
git -C /tmp/pr-review-repo checkout v0.1.1
python3 /tmp/pr-review-repo/scripts/verify_release_artifacts.py \
  --dist /tmp/pr-review-release \
  --sbom /tmp/pr-review-release/pr-review-harness-0.1.1.cdx.json \
  --provenance /tmp/pr-review-release/provenance.json \
  --checksums /tmp/pr-review-release/SHA256SUMS \
  --source-revision "$(git -C /tmp/pr-review-repo rev-parse HEAD)" \
  --workflow-ref "groktopus/codereview/.github/workflows/release.yml@refs/tags/v0.1.1"
```

A passing result prints `Release verification: PASS (signed: no)`. That script
verifies the unsigned `provenance.json` and SBOM layer; the `signed: no` is
expected there even for `0.1.1` because the signed attestation is verified
separately with `gh attestation verify`. To make unsigned provenance fail the
script, pass `--require-signed`; that flag always fails today because
cryptographic signature verification is not implemented in the script, even if
a provenance merely claims a signature.

Inspect the evidence directly:

```sh
jq '.metadata.component | {name, version, licenses, properties}' \
  /tmp/pr-review-release/pr-review-harness-0.1.1.cdx.json
jq '{subject, signing, source: .predicate.buildDefinition.externalParameters.source}' \
  /tmp/pr-review-release/provenance.json
jq '{status, artifact_hashes_match, content_matches, non_determinism}' \
  /tmp/pr-review-release/REPRODUCIBILITY.json
```

The Python requirement and zero-runtime-dependency claim can also be checked
from the installed package:

```sh
python3 -m venv /tmp/pr-review-release-venv
/tmp/pr-review-release-venv/bin/python -m pip install ./*.whl
/tmp/pr-review-release-venv/bin/python -c \
  "import importlib.metadata as m; d=m.metadata('pr-review-harness'); print(d['Requires-Python']); print(d.get_all('Requires-Dist') or 'no runtime dependencies')"
```

## CI integration and permissions

* `.github/workflows/test.yml` has a `Supply chain` job that builds twice, writes
  the reproducibility report, generates an SBOM and unsigned provenance, verifies
  them, runs `tests/test_supply_chain.py`, and retains the evidence for the run.
* `.github/workflows/release.yml` runs the same check before publishing and then
  creates the signed attestation. The `build` job has `contents: read`,
  `id-token: write`, and `attestations: write`; the two write scopes exist only
  for keyless attestation, and the job never receives `contents: write`. Only
  the `publish` job has `contents: write`, and it re-verifies the downloaded
  checksums, SBOM, and provenance before creating the release.
* Every action is pinned to a full commit SHA. The workflow reads no repository
  secrets and does not publish to PyPI.
* `.github/workflows/test.yml` installs the development/test environment from
  `requirements-dev.lock` with `pip --require-hashes` in the tests, coverage,
  compatibility, documentation, build, and supply-chain jobs. The mandatory
  `lock-freshness` job runs `scripts/check_dev_lock.py` (`uv lock --check`, a
  byte-identical `uv export` diff, per-requirement SHA-256 hashes, no
  editable/direct-URL/alternate-index entries) and the lock/public-surface
  regression tests. `uv` is pinned in the `dev` extra and by
  `[tool.uv].required-version`, so the freshness check uses the reviewed
  generator release. The full commands are in [`SUPPORT-MATRIX.md`](SUPPORT-MATRIX.md).
* `.github/workflows/security.yml` has a `vulnerability-scan` job that runs
  `uv audit --locked` against the hash-locked set on the weekly schedule and on
  manual dispatch only. It is not a pull-request gate, so a newly published
  advisory cannot make an unrelated PR flaky; a failing scan identifies the
  advisory in its output and retained artifact. Dependency review is opt-in via
  the `DEPENDENCY_GRAPH_ENABLED` repository variable; the activation steps and
  the compensating guidance job are documented in
  [`SUPPORT-MATRIX.md`](SUPPORT-MATRIX.md#dependency-review-conditional-variable).

## Residual gaps

* `provenance.json` and the SBOM remain unsigned and self-asserted. The
  attestation is the signed layer for the `0.1.1`-and-later wheel and sdist; it
  authenticates the release workflow and artifact digests, not the correctness
  or quality of the source. The earlier `v0.1.0` release remains unsigned and
  has no attestation.
* The tag signature is not verified in CI. A signed tag is a local operator
  practice until a verification step exists.
* The sdist is not byte-for-byte reproducible with the current setuptools
  toolchain; the report records `CONTENT_REPRODUCIBLE` and the affected
  timestamps. The wheel was byte-for-byte identical in the recorded run.
* Builder identity and workflow fields in `provenance.json` are self-asserted.
  The attestation provides a GitHub-issued builder identity, but the project
  retains no independent builder or separate transparency-log audit.
* The SBOM covers distribution metadata and artifact hashes, not every file
  inside the archives, and not development dependencies.
* The release workflow has not been exercised by a real tag or release in this
  change; a workflow file is not evidence that a release exists.
