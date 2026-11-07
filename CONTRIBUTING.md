# Contributing

## Development checks

The development/test environment is hash-locked in `requirements-dev.lock`
(generated from `pyproject.toml` with the pinned `uv`; see the
[support matrix](docs/SUPPORT-MATRIX.md)). Install it, then the editable project
without resolving new dependencies:

```sh
python -m pip install --require-hashes --no-deps -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
python scripts/check_dev_lock.py   # uv lock --check + byte-identical export diff
```

Run `python -m pytest -q` for the full suite before submitting a change. Keep
historical compatibility checks separately selectable with
`python -m pytest -m compatibility`. Do not hand-edit either lockfile; if a
reviewed change alters `pyproject.toml`, regenerate both with the commands in
the support matrix. Runtime dependencies must stay empty; see the
[public API and internal-module policy](docs/PUBLIC-API.md).

### Formatting, lint, and complexity (VD-4)

`ruff format` is the canonical formatter at the configured 120-column line
length. CI runs:

```sh
ruff check .
ruff format --check .
python scripts/check_complexity.py
```

Run the same commands locally before opening a pull request; to apply the
formatter, run `ruff format .`. The formatter deliberately skips the sha256-pinned
historical compatibility fixtures under `tests/fixtures/frozen-runtime-7d550b6/`
and `tests/fixtures/*-base.py`. Those files are immutable evidence (VD-3);
reformatting them would break their pins. Everything else, including `src/`,
`scripts/`, `experiments/`, and `tests/`, is formatted.

Install the [pre-commit](https://pre-commit.com/) hooks to run the same gates on
every commit:

```sh
pre-commit install
pre-commit run --all-files
```

[`.pre-commit-config.yaml`](.pre-commit-config.yaml) pins `ruff-pre-commit` to
the exact lint/format release in `requirements-dev.lock`, runs `ruff check --fix`
plus `ruff format`, and runs the complexity guard. `--fix` is a pre-commit
convenience; the resulting tree still has to pass the non-fixing CI checks.

The complexity guard is a ratchet, not a refactoring mandate. It measures each
function's physical span and fails any function over 150 lines that is not in
the explicit checked-in baseline
([`scripts/complexity-baseline.v1.json`](scripts/complexity-baseline.v1.json)).
A baselined function may not grow past its recorded length. If it shrinks to
the threshold or below, it is no longer an offender, so the entry fails as stale
until it is removed or the baseline is deliberately regenerated; a removed or
renamed entry fails the same way. Use `--diff-base <revision>` to check only functions touched since
a revision (useful before opening a pull request), and
`--update-baseline` only as a reviewed maintenance action when a legitimate
refactor or rename changes the offender set. The immutable historical fixtures
are excluded from the scan for the same reason they are excluded from
formatting.

**Remaining VD-4 work:** the lint rule set is still the original
`E4/E7/E9/F/I` selection; expanding to `B`, `SIM`, `UP`, `C4`, and `RUF` is a
separate reviewed change. Type checking remains limited to the strict
`.pyi` boundary contracts in `pyproject.toml`; repository-wide `mypy` adoption
is not part of this change and remains open VD-4 work.

## Merge review evidence (GA-1)

Every pull request must carry a review receipt in its body before merge. Fill in
the fenced `review-receipt` block from the pull request template as the
reviewer, and replace every placeholder. The `Review receipt` workflow
(`.github/workflows/review-receipt.yml`) validates the block on open, edit,
push, and reopen.

A receipt records the reviewer identity and kind (human or agent), the full
reviewed head SHA, an independence statement, the scope examined, a
`CLEAR`/`NOT CLEAR` verdict, evidence links or commands, a timestamp, and the
post-merge verification procedure. The reviewed SHA must equal the pull request
head; self-review must be declared as such; an agent reviewer must record its
protocol; and `NOT CLEAR` blocks. Merge only after the required checks are green
at the exact reviewed head, then verify the merge commit and its checks. The
field contract, exit codes, owner settings action, and enforcement limits are in
[review evidence](docs/REVIEW-EVIDENCE.md).

## Decision records (GA-2)

Major decisions and their owners are recorded in the
[decision-record index](docs/adr/README.md), with status, date, evidence, and
reversal conditions. The surfaces that require a record are listed in
[`docs/adr/safety-invariants.json`](docs/adr/safety-invariants.json): exact
paths, directory paths, and globs, plus the manifest file itself.

**Enforcement is active.** A pull request that changes a path that carries a
**safety invariant** must cite a decision record in the `decision_records` list of its review receipt
(an ID such as `0002`, a `docs/adr/NNNN-*.md` path, or an https link to that
file). The `Decision record links` workflow
([`.github/workflows/decision-record-links.yml`](.github/workflows/decision-record-links.yml))
reads the changed-file list from the read-only GitHub API and fails closed
unless every cited record already exists on `main`, is listed in the index, and
has Status **Accepted**. It never checks out or executes pull request code. Land
the accepted record first and cite it from the change; a record added by the same
pull request is not on the base revision yet.

A proposed record is a proposal, not approval. Do not mark a record accepted
without recorded decision authority, and do not invent an owner, approval, or
evidence link. Run both checks before opening the pull request:

```sh
python scripts/check_decision_records.py
python scripts/check_decision_record_links.py --event event.json --changed-files changed-files.json
```

The structural check verifies that the index covers every record, required
fields and statuses are valid, safety-invariant surfaces map to accepted
records, and the process is documented here and in the pull request template.
The diff check verifies the receipt links. Neither judges whether the evidence is
sufficient. Failure codes, the fixture format, and the limits are in
[review evidence](docs/REVIEW-EVIDENCE.md).

**Required on `main`.** `Decision record links` (like `Review receipt`) is a
required status check. The sole maintainer retains an explicit administrator
bypass, so the owner can merge their own PRs; every non-admin merge requires the
check. GA-2 closes with the sampled safety-invariant trace in PR #310, whose
receipt cites accepted records `0002` and `0009`.

## Ownership, review routing, and backlog triage (GA-3)

[`.github/CODEOWNERS`](.github/CODEOWNERS) assigns every path to the recorded
accountable owner, with narrower groups for core review, publication/effects,
security/credentials, workflows, docs, and release. The owner is one person:
the repository is honestly **bus factor 1**. Do not invent a second human or
describe an agent as one.

[Ownership, review authority, and access record](docs/OWNERSHIP.md) documents
the module map, the independent read-only agent review protocol and its limits,
publication incident/rollback ownership, credential rotation/recovery, and the
freeze rules if the maintainer is unavailable. An agent review can produce a
GA-1 receipt; it cannot approve live publication, credentials, releases,
repository settings, or a merge.

New findings use the issue forms under
[`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/). The
[backlog triage rules](docs/BACKLOG.md) define the five open states, state
labels, owners, closure-evidence rules, and the current mapping. An
issue closes only with observable evidence for its exit criteria, not because a
pull request merged.

Run the structural check before changing CODEOWNERS, the ownership record, the
backlog table, or a production module:

```sh
python3 scripts/check_ownership.py
```

## Versioning, changelog, and releases

Package and contract versions follow the [versioning policy](docs/VERSIONING.md).
Every pull request that changes behavior or a promised surface updates the
`Unreleased` section of [`CHANGELOG.md`](CHANGELOG.md) in the same change. Use
`python scripts/check_changelog.py --classify "<conventional commit message>"`
to choose the category; `!` or a `BREAKING CHANGE:` footer means `Breaking`.

Run the release-metadata checks before opening the pull request:

```sh
python scripts/check_changelog.py
python scripts/check_version_policy.py
```

Do not create tags, GitHub Releases, or version bumps outside the
[release procedure](docs/RELEASING.md). Maintainers cut releases only from green
`main`; the release workflow itself never creates a tag.

## Historical compatibility pins (VD-3)

Historical evidence is pinned under `tests/fixtures/frozen-runtime-7d550b6` and checked with `pytest -m compatibility`; CI runs that suite as a separate job. These pins are immutable evidence: do not edit a fixture or the manifest to make a current test pass. A legitimate historical migration requires a reviewed change that updates the fixture set, tree pins, verifier literals, and any plan artifacts together.

Refresh the file pins with [`scripts/refresh_compatibility_pins.py`](scripts/refresh_compatibility_pins.py). It is dry-run by default, performs no network access, and prints only sanitized names and digests:

```sh
python scripts/refresh_compatibility_pins.py \
  --reason "Reviewed migration of the historical fixture set" \
  --source-revision <40-hex-commit>
```

Review the reported old and new hashes, then re-run with `--confirm` to rewrite [`pins.json`](tests/fixtures/frozen-runtime-7d550b6/pins.json) atomically. The tool appends the changed file's `name`, `old_sha256`, `new_sha256`, `timestamp`, `reason`, and `source_revision` to `refresh_history` and updates `pins` plus `pin_revisions` only for changed files; it preserves the schema and historical revision. It refuses to run without a reason of at least 10 characters, a 40-hex source revision, and at least one changed pin, and it also refuses missing files or an unchanged pin set. Pins require reviewed provenance: never run `--confirm` merely to make a compatibility test pass.

Scattered SHA-256 literals that pin historical evidence or contract artifacts are recorded as named entries in [`tests/compatibility-pins.v1.json`](tests/compatibility-pins.v1.json) and loaded in tests with `compatibility_pins.pin("<name>")`. Each entry carries its `kind` and `provenance` (`artifact`, `source_revision`, `recorded_at`, and a `reason`). Value pins are semantic identities (module-tree, snapshot, plan, or contract digests), not single-file bytes, so the reviewed replacement is supplied explicitly:

```sh
python scripts/refresh_compatibility_pins.py --value-pins \
  --set <pin-name>=<new-64-hex-sha256> \
  --reason "Reviewed migration of the historical identity" \
  --source-revision <40-hex-commit>
```

The value-pin mode is also dry-run by default and prints the pin, artifact, old digest, and new digest without writing. Re-run with `--confirm` to update the `value` plus `provenance.source_revision`, `provenance.recorded_at`, and `provenance.reason` and to append `name`, `old_sha256`, `new_sha256`, `timestamp`, `reason`, and `source_revision` to `refresh_history`. It refuses a malformed `--set`, an unknown or ambiguous pin, a missing or invalid reason/source revision, an unchanged pin set, and any manifest entry without complete provenance. Tests that assert a historical value pin carry `@pytest.mark.compatibility` so the ordinary suite does not depend on historical evidence; a mismatch uses `compatibility_pins.assert_pin_value(...)`, whose error names the module, historical revision, and the exact refresh command.

**VD-3 remains open.** Production scripts and current-source capture still carry inline historical identity digests, so the single-manifest exit criterion is not yet met. These runtime surfaces must not import test fixtures; moving their authorities to a runtime-neutral canonical manifest is remaining implementation work, not an approved exception. Some historical comparisons still use bare assertions, and frozen tree-pin remediation needs a distinct reviewed migration procedure rather than the file-byte refresh command. Do not copy digests into new tests: add or reuse a named manifest entry instead.

Synthetic fixture and serialization-golden digests are not compatibility pins: they are derived from local test data and may be regenerated with the test fixture. Keep those literals inline and put an explicit `# vd3-non-pin: <reason>` comment on the line directly above them. [`tests/test_compatibility_pins.py`](tests/test_compatibility_pins.py) fails when a 64-character hexadecimal literal appears in the test suite outside `tests/fixtures` without either a named manifest entry or that marker, and it also detects unreferenced manifest entries.
