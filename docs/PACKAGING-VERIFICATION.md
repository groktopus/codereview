# Packaging and CI verification

The release candidate is a wheel plus source distribution built from a reviewed Git revision. Editable installs do not establish that the published wheel works.

## Source archive contents

`MANIFEST.in` explicitly includes the authored inputs needed to inspect and run the source-test path: scripts, example JSON, review profiles, workflow definitions, documentation, the public minimized PR #464 check-evidence fixture, and the five source files that make up the Actions artifact-uploader bridge (`action.yml`, its two `.mjs` modules, and npm package/lock metadata). Packaging tests compare every bridge file's archived bytes directly to the working-tree source. The manifest does not include the ignored `artifacts/` directory, `node_modules`, live provider catalogs, credential files, build output, or transient run output. Keep this allowlist deliberate when new tests begin reading repository support files.

These support files are source-distribution contents, not installed runtime data. The packaging test builds both distributions, checks the sdist fixture and test support paths, and confirms those repository-only trees do not enter the wheel. To verify the archive manually without modifying the checkout:

```sh
tmp=$(mktemp -d)
python -m build --sdist --outdir "$tmp/dist"
mkdir "$tmp/source"
tar -xzf "$tmp/dist"/*.tar.gz -C "$tmp/source"
cd "$tmp/source"/*
PYTHONPATH=src python -m pytest -q tests/test_checks.py tests/test_injection_trials.py tests/test_test_matrix.py tests/test_packaging.py
```

The source tests use fake transports and controlled Git fixtures; they do not make provider calls. The build and extracted tests validate packaging and repository behavior only, not installed-wheel runtime behavior or provider/model quality.

The Actions uploader bundle is deliberately source-distribution-only. The normal Actions workflow checks out the pinned trusted harness source and runs `npm ci --ignore-scripts --no-audit --no-fund` in `scripts/actions-artifact-uploader` before invoking the local action. The bundle expects the GitHub Actions Node 24 runtime and its runtime artifact service; it is not part of the Python wheel and is not a general installed-wheel uploader API. Wheel verification therefore covers the Python CLI/runtime and does not establish that the external Actions receipt bridge is available outside that workflow environment.

## Local build and smoke test

From a clean checkout, build both distributions, record their digests, install the wheel in a new environment, and run the smoke script with the checkout outside the process working directory:

```sh
python3 -m pip install '.[dev]'
python3 -m build --wheel --sdist --outdir dist
sha256sum dist/*
python3 -m venv /tmp/pr-review-wheel
/tmp/pr-review-wheel/bin/python -m pip install dist/*.whl
/tmp/pr-review-wheel/bin/python scripts/package_smoke.py \
  --cli /tmp/pr-review-wheel/bin/pr-review
```

The smoke test confirms that the entry point belongs to the selected environment, `--help` is usable, dry-run emits valid JSON, the publication gate rejects writes, and a provider-free review creates durable JSON and Markdown reports entirely under a temporary directory outside the source tree. The fixture uses controlled Git commits; no target project code executes.

## Continuous integration

`.github/workflows/test.yml` runs pytest and Ruff on Python 3.11, 3.12, 3.13, and 3.14. A separate build job produces a wheel and sdist and records SHA-256 digests. Installed-wheel smoke jobs install that exact uploaded wheel into fresh environments outside the checkout on Python 3.11 and 3.14. The artifact is retained for seven days for the run.

The regular test workflow has only `contents: read` and no provider credentials. CI executing this repository's own tests/build metadata is not a PR-analysis job. The PR-analysis workflow is separate and does not execute the target PR tree.

## Evidence still required before release

- A successful Actions run on each supported Python version and successful installed-wheel jobs, with the wheel digest retained.
- Review of the generated wheel contents, source revision, and dependency inventory for a release candidate.
- An observed GitHub PR analysis run using a caller workflow and separately pinned trusted harness/profile SHA, checked fresh-head behavior, and reviewed artifact retention; this repository change has not triggered or verified a remote Actions run.
- An independently verified provider/model selection and representative review-quality evaluation. Current test-model compatibility does not establish production suitability or parity with Droid.
- Owner approval for any publication behavior, deployment, cutover, or required-check use. This package does not enable those effects.

A passing local test suite or installed smoke test covers only its stated software paths. It does not prove workflow permissions in a live repository, GitHub API availability, provider billing, model quality, required-check correctness, operational ownership, retention approval, or release authorization. See [`RELEASE-PLAN.md`](RELEASE-PLAN.md) and [`PRODUCTION-DELIVERY.md`](PRODUCTION-DELIVERY.md) for the full gates.
