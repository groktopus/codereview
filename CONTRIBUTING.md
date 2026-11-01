# Contributing

## Development checks

Install the development dependencies with `python -m pip install -e '.[dev]'`. Run
`python -m pytest -q` for the full suite and `ruff check .` before submitting a
change. Keep historical compatibility checks separately selectable with
`python -m pytest -m compatibility`.

## Historical compatibility pins (VD-3)

Historical evidence is pinned under `tests/fixtures/frozen-runtime-7d550b6` and checked with `pytest -m compatibility`; CI runs that suite as a separate job. These pins are immutable evidence: do not edit a fixture or the manifest to make a current test pass. A legitimate historical migration requires a reviewed change that updates the fixture set, tree pins, verifier literals, and any plan artifacts together. The refresh tooling is tracked separately and is not part of this repository's supported workflow yet.
