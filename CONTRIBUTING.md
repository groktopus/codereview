# Contributing

## Development checks

Install the development dependencies with `python -m pip install -e '.[dev]'`. Run
`python -m pytest -q` for the full suite and `ruff check .` before submitting a
change. Keep historical compatibility checks separately selectable with
`python -m pytest -m compatibility`.

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
