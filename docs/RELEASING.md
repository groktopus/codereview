# Releasing

**Status:** release procedure. **Owner:** groktopus/codereview maintainers. **Issue:** #260 (RS-2); supply-chain evidence in #261 (RS-3).

This document describes how a release is cut from green `main`. It does not
assert that any tag or GitHub Release exists; the repository state, the tag
list, and the release page are the authority. The first release uses the same
procedure as every later release.

## Preconditions

1. The release commit is on `main` and every enabled required check passed at
   that exact revision (the `Harness verification` and `Security scanning`
   workflows).
2. The working tree is clean and `main` is up to date with the remote.
3. The version, `CHANGELOG.md`, and any contract registry changes are already
   merged. The release commit is the tag target; do not tag an unmerged branch.
4. No external credential is needed. The workflow uses the repository-scoped
   `GITHUB_TOKEN` only to create the GitHub Release, and it publishes no Python
   package.

## Prepare the version

1. Choose the version using [VERSIONING.md](VERSIONING.md).
2. Set `project.version` in [`pyproject.toml`](../pyproject.toml).
3. Move the `Unreleased` entries in [`CHANGELOG.md`](../CHANGELOG.md) under a new
   `## [<version>] - YYYY-MM-DD` heading, add a fresh empty `Unreleased`
   section, and put incompatible changes under `### Breaking`. Add the new
   compare/release link definitions at the bottom.
4. If the release adds, deprecates, or removes a contract identity, update
   [`contract_registry.json`](../src/pr_review_harness/contract_registry.json),
   its schema if the registry shape changed, [`CONTRACT-REGISTRY.md`](CONTRACT-REGISTRY.md),
   and `scripts/release-policy.v1.json` when a new artifact schema or artifact
   identity is introduced.
5. Run the local gates:

```sh
python3 -m pip install -e '.[dev]'
python3 -m pytest -q -m "not compatibility"
python3 -m pytest -q -m compatibility
ruff check .
python3 scripts/check_changelog.py
python3 scripts/check_version_policy.py
python3 scripts/check_docs_index.py
python3 scripts/check_relative_links.py
```

6. Open a pull request, let the required checks pass, and merge it to `main`.

## Create the tag

The tag is the release trigger. Create it only after the release commit is on
`main` and green:

```sh
git switch main
git pull --ff-only
git log -1 --format='%H %s'
# Signed tag (preferred when a release key is configured):
git tag -s v0.1.0 -m "pr-review-harness 0.1.0"
git tag -v v0.1.0
# Annotated fallback when no signing key is configured:
# git tag -a v0.1.0 -m "pr-review-harness 0.1.0"
# git tag -n99 v0.1.0
git push origin v0.1.0
```

Use one of `-s` or `-a`; a lightweight tag is not accepted by this procedure.
CI verifies that the tag resolves to the checked-out commit and matches
`project.version`, but it does **not** verify the tag signature. The release
artifacts are also unsigned; see [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md).

Do not create the GitHub Release by hand before the tag exists. The release
workflow runs `gh release create --verify-tag`; without an existing tag the
step fails before any release is created. If a release already exists for the
tag, the workflow fails instead of overwriting it.

## Trigger the workflow

[`.github/workflows/release.yml`](../.github/workflows/release.yml) has two
triggers:

| Trigger | Behavior |
|---|---|
| Push of a tag matching `v*.*.*` | Builds and publishes that tag. The tag must already exist; the push is the tag creation. |
| `workflow_dispatch` with a `tag` input | Re-runs the pipeline for an **existing** tag. It never creates a tag or a release for a missing tag. |

The workflow runs two jobs:

| Job | Permission | Work |
|---|---|---|
| `build` | `contents: read` | Check out the tag, verify the tag equals the package version, has a changelog section, and is an ancestor of the default branch. Build the wheel and sdist twice with a `SOURCE_DATE_EPOCH` derived from the tag commit and compare them; generate the CycloneDX SBOM, unsigned provenance, and reproducibility report; write and verify `SHA256SUMS`; verify that the SBOM, provenance, and checksums agree; retain the distribution and evidence artifacts. |
| `publish` | `contents: write` | Check out the verification scripts at the tag, download the retained assets, verify the checksums, SBOM, and provenance again, refuse to overwrite an existing release, and create the GitHub Release with the wheel, sdist, `SHA256SUMS`, SBOM, provenance, reproducibility report, and notes. |

The top-level workflow permission is `contents: read`; only the `publish` job
escalates to `contents: write`. Every action is pinned to a full commit SHA
consistent with the repository's other workflows. The workflow does not read
repository secrets, does not publish to PyPI, does not create tags, and does not
request `id-token` or `attestations` permissions. The supply-chain evidence is
unsigned; see [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md).

The separate `Supply chain` job in
[`.github/workflows/test.yml`](../.github/workflows/test.yml) runs the same
two-build comparison and SBOM/provenance verification on normal pushes and pull
requests, so the checks are not release-only.

## Manual dispatch

Use **Actions → Release → Run workflow** and enter an existing tag such as
`v0.1.0`. Dispatch is for rebuilding or retrying an existing tag. It rejects:

* a tag that does not exist;
* a tag whose version does not equal `project.version`;
* a tag whose commit is not the checked-out revision;
* a tag with no `CHANGELOG.md` section;
* a tag that is not an ancestor of the default branch;
* a tag that already has a GitHub Release.

## Cut the first release

The first release is `v0.1.0`. After the preparation pull request is merged:

```sh
git switch main
git pull --ff-only
python3 scripts/check_version_policy.py
# Signed tag (preferred when a release key is configured):
git tag -s v0.1.0 -m "pr-review-harness 0.1.0"
git tag -v v0.1.0
# Annotated fallback when no signing key is configured:
# git tag -a v0.1.0 -m "pr-review-harness 0.1.0"
# git tag -n99 v0.1.0
git push origin v0.1.0
```

The pushed tag starts the release workflow. Watch the `Release` run:

```sh
gh run list --workflow release.yml --limit 5
gh run watch <run-id>
```

If the workflow fails, no release is created for that tag unless the failure
occurred after `gh release create`. Inspect the failed job and fix the source;
never move or delete a published tag.

## Verify a published release

Replace `v0.1.0` with the actual tag:

```sh
gh release view v0.1.0 --json tagName,url,assets
gh release download v0.1.0 --dir /tmp/pr-review-release
cd /tmp/pr-review-release
sha256sum -c SHA256SUMS
python3 -m venv /tmp/pr-review-release-venv
/tmp/pr-review-release-venv/bin/python -m pip install ./*.whl
/tmp/pr-review-release-venv/bin/pr-review --help
```

Verify that the SBOM, provenance, and checksums agree with the downloaded
artifacts, using the verification script from the same tag:

```sh
git clone https://github.com/grokopus/codereview /tmp/pr-review-repo
git -C /tmp/pr-review-repo checkout v0.1.0
python3 /tmp/pr-review-repo/scripts/verify_release_artifacts.py \
  --dist /tmp/pr-review-release \
  --sbom /tmp/pr-review-release/pr-review-harness-0.1.0.cdx.json \
  --provenance /tmp/pr-review-release/provenance.json \
  --checksums /tmp/pr-review-release/SHA256SUMS \
  --source-revision "$(git -C /tmp/pr-review-repo rev-parse HEAD)" \
  --workflow-ref "grokopus/codereview/.github/workflows/release.yml@refs/tags/v0.1.0"
```

The expected result is `Release verification: PASS (signed: no)`. The
provenance is unsigned by design; `--require-signed` fails until a real
signature exists.

Also verify the tag and metadata against the checkout:

```sh
git fetch --tags
git rev-parse --verify 'v0.1.0^{commit}'
python3 scripts/check_version_policy.py --tag v0.1.0
```

The release is verified when the GitHub Release exists at the pushed tag, the
wheel, sdist, `SHA256SUMS`, SBOM, provenance, and reproducibility report are
present, `SHA256SUMS` validates in a clean directory, `verify_release_artifacts.py`
passes, and the wheel installs and runs outside the checkout. `SHA256SUMS` is
not a signature, and the reproducibility report does not claim bit-for-bit
reproducibility where the recorded result says `CONTENT_REPRODUCIBLE`. See
[SUPPLY-CHAIN.md](SUPPLY-CHAIN.md) for formats, limits, and local checks.

## Failure and rollback

* **Build or verification failure:** no release is created. Fix the source and
  rerun from a new tag. Do not publish a partial asset set.
* **Existing release for the tag:** the workflow fails rather than overwriting
  it. Publish a new patch version instead.
* **Bad release content:** do not move or delete the tag. Publish a follow-up
  patch release with the correction. Deleting a GitHub Release or tag is an
  external effect that requires the project owner's explicit decision.
* **Tag points at the wrong commit:** stop. Do not force-push the tag. The tag
  must be recreated only under an owner-approved incident procedure.
* **Manual dispatch failure:** the tag is already public; rerun after fixing
  the workflow or publish a new patch. Dispatch never creates a tag.

## Changelog classification for every merge

Every merge that changes behavior or a promised surface must update
`Unreleased` in the same pull request. Classify the change deterministically:

```sh
python3 scripts/check_changelog.py --classify "feat: add a JSON stats export"
python3 scripts/check_changelog.py --classify "fix: reject an empty base revision"
python3 scripts/check_changelog.py --classify "feat!: remove the legacy limits profile"
```

The first two print `Added` and `Fixed`; the third prints `Breaking`. An
`unclassified` result means the commit type is unknown and a human must choose
the section. `tests/test_changelog.py` and `tests/test_version_policy.py` check
the parser, classifier, and repository metadata; CI runs them with the normal
test suite.

## Residual gaps

* Artifacts and provenance are unsigned. There is no Sigstore signature or
  GitHub artifact attestation, so consumers can verify hashes and recorded build
  inputs but not origin authenticity. Adding a signature needs an
  owner-approved signing credential or attestation job.
* The tag signature is not verified in CI. A signed tag is a local operator
  practice until a verification step exists.
* The source distribution is `CONTENT_REPRODUCIBLE`, not byte-for-byte
  reproducible, with the current setuptools toolchain; the retained report
  records the gzip-header and directory-entry timestamp differences.
* The workflow does not publish to PyPI. Installation remains from the attached
  wheel or a source checkout.
* The release workflow's end-to-end behavior is only established by a real
  release run; a workflow file in a merged branch is not evidence that a release
  exists.
