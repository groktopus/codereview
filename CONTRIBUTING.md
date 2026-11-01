# Contributing

## Development checks

Install the development dependencies with `python -m pip install -e '.[dev]'`. Run
`python -m pytest -q` for the full suite and `ruff check .` before submitting a
change. Keep historical compatibility checks separately selectable with
`python -m pytest -m compatibility`.

## Historical compatibility pins (VD-3)

Historical fixtures are retained evidence, not snapshots to refresh as part of an
ordinary source edit. A compatibility failure identifies the module, frozen
revision, and the remediation command. First determine whether the changed bytes
are meant to replace historical evidence or whether the fixture was accidentally
modified. Preserve the prior blob and its review context either way.

The provenance-gated refresh tool supports only the bounded
`tests/fixtures/frozen-runtime-7d550b6` compatibility set. Preview an intentional
refresh by supplying all provenance, then review the proposed old/new digest
record:

```sh
python scripts/refresh_compatibility_pin.py \
  --module context_selector.py \
  --reason 'Describe why this historical fixture must change' \
  --source-revision <full-git-commit> \
  --dry-run
```

Only after reviewing the dry-run, repeat the command without `--dry-run` to
update the fixture-set manifest. The manifest records the old and new blob
SHA-256, reason, source commit, and UTC timestamp in append-only refresh history.
The tool refuses a request without a non-empty reason and an available full Git
commit, including in dry-run mode. Do not manually edit the manifest to bypass
those checks. Other source, run, snapshot, and protocol hashes intentionally
remain in their owning records until their distinct semantics and provenance
have been audited; this tool must not be used to rewrite them.
