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

Run `python -m pytest -q` for the full suite and `ruff check .` before submitting
a change. Keep historical compatibility checks separately selectable with
`python -m pytest -m compatibility`. Do not hand-edit either lockfile; if a
reviewed change alters `pyproject.toml`, regenerate both with the commands in
the support matrix. Runtime dependencies must stay empty; see the
[public API and internal-module policy](docs/PUBLIC-API.md).

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

Historical evidence is pinned under `tests/fixtures/frozen-runtime-7d550b6` and checked with `pytest -m compatibility`; CI runs that suite as a separate job. These pins are immutable evidence: do not edit a fixture or the manifest to make a current test pass. A legitimate historical migration requires a reviewed change that updates the fixture set, tree pins, verifier literals, and any plan artifacts together. The refresh tooling is tracked separately and is not part of this repository's supported workflow yet.
