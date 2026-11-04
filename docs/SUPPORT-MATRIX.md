# Support matrix, install matrix, and dependency policy

Status: current reference contract for the `0.1.x` package line. It records the
Python and OS combinations the project supports, exactly what CI verifies for
each, how to install the hash-locked development environment, and the dependency
policy (including the dependency-review switch). It is not a release,
replacement, or production-readiness claim; see [`STATUS.md`](STATUS.md) and
[`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md).

## Supported Python versions

| Python | Support | What is verified |
|---|---|---|
| 3.11 | Supported, minimum | Full pytest suite + Ruff + mypy on Linux; wheel install and `pr-review --help` on Linux, macOS, and Windows |
| 3.12 | Supported | Full pytest suite + Ruff on Linux |
| 3.13 | Supported | Full pytest suite + Ruff on Linux; build, documentation, and supply-chain jobs |
| 3.14 | Supported | Full pytest suite + Ruff on Linux; wheel install and `pr-review --help` on Linux, macOS, and Windows |

Python 3.10 and earlier are not supported. Free-threaded builds
(`python3.14t`) and PyPy are not tested and are not supported.

`pyproject.toml` declares `requires-python = ">=3.11"` and classifiers for
3.11–3.14; `tests/test_dependency_supply_chain.py` and
`tests/test_packaging.py` fail if the declaration and the wheel metadata drift.

## Operating systems and install matrix

| OS | Support | What is verified |
|---|---|---|
| Linux (`ubuntu-latest`, x86_64) | Supported, full suite | Every workflow job: tests, coverage, compatibility, build, supply chain, documentation, installed-wheel and install-matrix smoke |
| macOS (`macos-latest`) | Supported for install + CLI smoke | `install-matrix` job: installs the built wheel into a fresh venv and runs `pr-review --help` on Python 3.11 and 3.14. The full pytest suite is not run here. |
| Windows (`windows-latest`) | Supported for install + CLI smoke | `install-matrix` job: installs the built wheel into a fresh venv and runs `pr-review --help` on Python 3.11 and 3.14. The full pytest suite is not run here. |

OS assumptions:

* The CLI, review core, and package are pure Python and use only the standard
  library at runtime. No platform-specific runtime dependency is declared.
* Full-suite CI is Linux-only. Some repository tests are Linux-specific by
  design (the external effect observer uses `strace`), so a macOS/Windows
  checkout is not expected to pass the entire suite.
* The optional Actions artifact-uploader bridge
  (`scripts/actions-artifact-uploader/`) requires the GitHub Actions Node 24
  runtime and the Actions artifact service. It is source-distribution-only and
  is not part of the wheel or of the installed Python API.
* The `github-app` extra enables the optional App credential path; it is not
  required for CLI review.

The exact matrix is implemented by the `install-matrix` job in
`.github/workflows/test.yml`. It downloads the single wheel built by the `build`
job, installs it **without** development dependencies, asserts the installed
metadata declares no runtime `Requires-Dist` entries and
`Requires-Python: >=3.11`, and runs `pr-review --help`. A failure in any
documented combination fails the workflow.

## Installing the package

Runtime install (no dependencies are pulled):

```sh
python3 -m venv /tmp/pr-review
/tmp/pr-review/bin/python -m pip install dist/pr_review_harness-0.1.1-py3-none-any.whl
/tmp/pr-review/bin/pr-review --help
```

Optional extras:

```sh
python -m pip install '.[github-app]'   # optional GitHub App credential path
python -m pip install '.[dev]'          # development/test tooling (use the lock below)
```

## Development/test environment: hash-locked

The development/test set is resolved once from `pyproject.toml` into
`uv.lock` and exported, with hashes, to `requirements-dev.lock`. `uv` itself is
pinned in the `dev` extra and by `[tool.uv].required-version`, so lock generation
and freshness checks use the same reviewed release.

Install it (all requirements are exactly pinned and hash-verified):

```sh
python -m pip install --require-hashes --no-deps -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
```

`--no-build-isolation` uses the locked `setuptools` instead of fetching an
unpinned build requirement. `--require-hashes` fails if any requirement is not
pinned with a SHA-256 hash or if a transitive requirement is missing from the
export.

Verify freshness and the hash contract:

```sh
uv lock --check
python scripts/check_dev_lock.py
# equivalent one-shot export diff:
uv export --locked --format requirements-txt --no-emit-project --extra dev --no-header \
  --output-file requirements-dev.lock
git diff --exit-code requirements-dev.lock
```

Regenerate after a reviewed `pyproject.toml` change (never hand-edit either
lock):

```sh
uv lock
uv export --locked --format requirements-txt --no-emit-project --extra dev --no-header \
  --output-file requirements-dev.lock
python scripts/check_dev_lock.py
```

CI runs the same commands in the mandatory `lock-freshness` job and installs the
lock with `--require-hashes` in the tests, coverage, and compatibility jobs.
The checker prefers the pinned `uv` installed in the current interpreter
(`python -m uv`); when it is invoked outside the locked environment, pass
`--uv /path/to/uv` (the file must report `0.13.6`) or install `requirements-dev.lock` first. A mismatched
`uv` fails with that instruction instead of rewriting the lock.

## Dependency policy

* **No runtime dependencies.** `dependencies = []` is an invariant, not an
  accident. Adding one requires an explicit decision record and an update to the
  public API/support contract; `tests/test_dependency_supply_chain.py` fails
  otherwise. Optional extras are allowed and must remain optional.
* **Development/test dependencies are locked and hashed.** The lock is the only
  supported dev environment. Floating ranges in `pyproject.toml` are inputs to
  `uv lock`, not the installed set.
* **The lock is verified.** `scripts/check_dev_lock.py` requires
  `uv lock --check` to pass, a byte-identical export, at least one SHA-256 hash
  per requirement, and no editable/direct-URL/alternate-index entries.
* **Vulnerability scanning is scheduled, not per-PR.** The `vulnerability-scan`
  job in `.github/workflows/security.yml` runs `uv audit --locked` only on the
  weekly schedule and on manual dispatch. It does not run for pull requests, so
  a new advisory cannot make an unrelated PR flaky; it fails the scheduled run
  with the advisory identity instead. `uv` is installed from the same
  hash-locked dev set.

### Dependency review (active)

The `dependency-review` job in `.github/workflows/security.yml` is active: the
repository variable `DEPENDENCY_GRAPH_ENABLED` is `true` and the dependency graph
is enabled. It runs on every pull request, reviews dependency manifest changes,
and fails on high or critical known vulnerabilities. It never posts a comment
(`comment-summary-in-pr: never`) and keeps `contents: read`.

This repository has no runtime dependencies. The graph's parsing of `uv.lock`
revision 5 / `requirements-dev.lock` was exercised by the activating pull
request (#314), where `Dependency review` passed.

If the graph or variable is later disabled, the `dependency-review-guidance` job
emits a warning annotation and step summary rather than failing silently. The
activation commands remain:

1. Enable **Settings → Code security → Dependency graph**.
2. `gh variable set DEPENDENCY_GRAPH_ENABLED --repo groktopus/codereview --body true`.
3. Re-run a pull request.

## Verification map

| Claim | Check |
|---|---|
| Package and wheel declare Python 3.11+ and zero runtime dependencies | `tests/test_packaging.py`, `tests/test_dependency_supply_chain.py` |
| Dev/test set is exactly pinned, hashed, and fresh | `scripts/check_dev_lock.py`, `tests/test_dependency_supply_chain.py`, `lock-freshness` CI job |
| Hash-verified install works | CI `tests`/`coverage`/`compatibility` jobs (`pip --require-hashes`); local commands above |
| Documented install combinations install the wheel and start the CLI | `install-matrix` CI job (Linux/macOS/Windows × 3.11/3.14) |
| Workflow actions are SHA-pinned and the scan is schedule-only | `tests/test_dependency_supply_chain.py` |
| Public import surface and internal-module policy | [`PUBLIC-API.md`](PUBLIC-API.md), `tests/test_public_surface.py` |

The scheduled scan and install matrix verify the listed combinations only. They
do not prove provider compatibility, review quality, or release authorization.
