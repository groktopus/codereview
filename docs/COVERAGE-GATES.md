# Coverage gates

Coverage is measured in CI on every push and pull request and enforced as a
floor, not a quality claim. The `coverage` job in `.github/workflows/test.yml`
runs the full suite with `pytest --cov`, enforces the recorded floors, appends a
per-module table to the job summary, and retains `coverage.json` plus
`coverage-summary.md` as the `pr-review-coverage-<run id>` artifact for seven
days.

## Current measured coverage

Full suite on Python 3.14 at this change. The issue baseline reports 19,691
statements and 81.4% overall on main; the same suite measured here before the
added tests reports 20,175 statements and 81.83% (Python-version-dependent
statement counts explain the difference).

| Module | Before | After | Floor | Target |
| --- | ---: | ---: | ---: | ---: |
| overall | 81.83% | 85.27% | 85.00% | 85% |
| `github.py` | 61.88% | 100.00% | 98.00% | 90% |
| `publisher.py` | 71.04% | 100.00% | 99.50% | 90% |
| `checks.py` | 74.26% | 100.00% | 99.50% | 90% |
| `actions_publication.py` | 77.69% | 99.05% | 98.50% | 90% |
| `cli.py` | 76.21% | 97.36% | 97.00% | 90% |

The VD-1 target is met: overall ≥85% and all five enforced modules ≥90% (20,618 statements at this base).
`publisher.py` and `checks.py` are fully covered. The remaining uncovered lines
are defence-in-depth guards that cannot be reached through public state:

- `actions_publication.py` (11 lines: 1184, 1274, 1371, 1423, 1519, 1529, 1889,
  1914, 2000, 2003, 2073): earlier validation in `_artifact_metadata`,
  `_historical_content_blob`, `GitHubPublicationPolicy.__post_init__`,
  artifact intake, `_credential`, and the review body/marker checks makes these
  duplicate checks unreachable; 1371 is a structurally consistent foreign
  historical policy that the existing v4 probe rejects earlier; 2073 is
  unreachable because `_parse_utc`'s regex admits only `Z`/`+00:00`.
- `cli.py` (24 lines): unreachable limit/None guards (306, 322, 350, 377) and the
  effects-heavy `_run_one` review-dispatch paths (917-919, 928, 983, 1024-1025,
  1032, 1122-1129, 1134, 1138, 1164, 1385), deliberately out of scope for this
  issue because they require a subprocess/engine end-to-end fixture.

The gate is a floor, not a claim that every remaining line is independently
justified.

## Enforced floors

Floors live in `scripts/coverage_gate.py` (`FLOORS`). They are a ratchet at the
level actually achieved by the checked-in tests: a floor may be raised after
new tests land, and lowering one is a deliberate, reviewable change — never a
way to make a red run green. The gate fails when any declared module is absent
from the report, so a module cannot silently drop out of measurement.

`TARGET_OVERALL` (85%) and `TARGET_CRITICAL` (90%) in the gate script record the
issue target; the summary table shows it next to every floor. The floors carry
a small tolerance below the measured value so runner variation does not produce
false failures; a real test removal still fails the gate.

## Local use

```sh
python -m pytest -q --cov=pr_review_harness \
  --cov-report=json:coverage.json --cov-report=term
python scripts/coverage_gate.py --coverage-json coverage.json
```

`--summary PATH` also writes the markdown table to a file; without it the table
is printed and, when `GITHUB_STEP_SUMMARY` is set, appended to the job summary.

## Seeded-failure check

The gate's behaviour is covered by `tests/test_coverage_gate.py` (below-floor,
missing-module, and absent-report cases). To demonstrate the CI gate itself
fails on a coverage drop, generate a report with the added coverage tests
removed (for example `pytest ... --ignore=tests/test_coverage_*.py` or by
temporarily removing one added test file) and run the gate on it. It exits `1`
and marks every module below its floor `FAIL`. The pre-change suite produced:

```text
overall 81.83% < 85.00% FAIL
github.py 61.88% < 98.00% FAIL
publisher.py 71.04% < 99.50% FAIL
checks.py 74.26% < 99.50% FAIL
actions_publication.py 77.69% < 98.50% FAIL
cli.py 76.21% < 97.00% FAIL
```

Revert the seed afterwards; the recorded floor is not lowered in the committed
tree.
