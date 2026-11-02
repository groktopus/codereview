# Public API and internal-module policy

Status: current reference contract for the `0.1.x` package line. It records what
is promised to consumers, what is internal, and how the machine-readable surface
in [`public-surface.json`](public-surface.json) is checked. It is not a quality,
replacement, or release-authorization claim; see [`STATUS.md`](STATUS.md).

## Supported consumer surface

The supported, externally documented surface is deliberately small. "Stable"
below means the name is checked by tests and may only change with the versioning
rules in [`VERSIONING.md`](VERSIONING.md); it does not mean every parameter or
record shape is frozen (those follow the [contract registry](CONTRACT-REGISTRY.md)).

| Surface | Exact name | Stability | Notes |
|---|---|---|---|
| Console command | `pr-review` (entry point `pr_review_harness.cli:main`) | Stable | The supported interface for people and automation. Flags and JSON shapes are documented in the root [README](../README.md). |
| Package import root | `pr_review_harness` | Stable | Contains only `__version__`; importing it performs no work. |
| Review orchestrator | `pr_review_harness.engine.run_review` | Stable name; internal record shapes | Deterministic review entry point used by the CLI and Actions adapter. Callers must construct valid versioned records; see `docs/design/CONTRACTS.md`. |
| Guarded publication executor | `pr_review_harness.protected_publication_runtime.run_protected_publication` | Stable name; effect surface | Invoked only by the distributed hard-disabled publication template under `scripts/protected-publication-action/`. It is not a general-purpose publishing API. Default effects remain `READ_ONLY`. |
| Module execution | `python -m pr_review_harness` | Stable | Runs the same CLI entry point; importing `pr_review_harness.__main__` executes it. |

Everything else is **internal**. This includes every other module in
`src/pr_review_harness/` and the two internal stage helpers
`pr_review_harness.review_stages:run_followup_stage` and
`pr_review_harness.review_stages:run_followups`, which are listed in
`public-surface.json` for architecture and ownership checks only. Internal
modules:

* may be renamed, split, merged, or removed in any release without a deprecation
  period;
* are not covered by the versioning promise and should not be imported by
  consumers;
* may expose names with a leading underscore, which are private even inside the
  package;
* are still owned, reviewed, and covered by the repository tests.

The experiment toolkit is not part of the installed package. It lives under
`experiments/harness/` and is source-distribution-only; `import experiments` is
not a supported consumer import. Relocated experiment modules and their
dispositions are recorded in `public-surface.json`.

## Import contract

* Importing any installed module other than `pr_review_harness.__main__` must not
  read provider credentials, dispatch network calls, publish, or execute target
  code. `tests/test_public_surface.py` imports every documented production module
  and fails if one stops importing; the effect-boundary tests cover behaviour.
* The package never installs an experiment package and never imports one from a
  production path (`tests/test_surface_consolidation.py`).
* No runtime dependencies are declared. `pip install pr-review-harness` installs
  the package and its standard-library-only runtime. The only dependency-bearing
  extras are `dev` (development/test tooling) and `github-app` (the optional
  GitHub App credential path). The zero-runtime-dependency invariant is enforced
  by `tests/test_dependency_supply_chain.py` against both `pyproject.toml` and
  the built wheel's `METADATA`.

```sh
# Prove the invariant from an installed wheel
python -c "import importlib.metadata as m; print(m.requires('pr-review-harness'))"
# -> None (or only entries carrying an extra marker)
```

## Supported Python and OS surface

Python 3.11 is the minimum; 3.11 through 3.14 are supported. Linux is the
full-suite platform; the wheel install and `pr-review --help` smoke are also
verified on macOS and Windows. The definitive matrix, install commands,
development-lock commands, and dependency policy are in
[`SUPPORT-MATRIX.md`](SUPPORT-MATRIX.md).

## Verification map

| Claim | Check |
|---|---|
| Documented production modules exist and import | `tests/test_public_surface.py` |
| The manifest matches the installed package | `tests/test_surface_consolidation.py` |
| No runtime dependencies in project or wheel metadata | `tests/test_dependency_supply_chain.py` |
| Module map ownership for every production module | `scripts/check_ownership.py` |
| Dev/test set is pinned, hashed, and fresh | `scripts/check_dev_lock.py`, `tests/test_dependency_supply_chain.py` |

A passing import test does not establish review quality, provider compatibility,
or production readiness, and it does not authorize any external effect.
