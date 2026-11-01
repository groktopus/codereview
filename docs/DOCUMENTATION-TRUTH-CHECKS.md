# Documentation truth checks (DT-3)

These source-only checks run on pull requests and pushes to `main`. They do not
fetch external URLs, infer truth from wording, or claim review quality. The
relative-link checker reads repository files only; `README.md` and all Markdown
under `docs/` are checked, including `docs/issues/`.

## Local commands

```sh
python3 scripts/check_relative_links.py
python3 scripts/check_docs_index.py
python3 scripts/check_docs_truth.py \
  --sha-manifest scripts/documentation-sha-references.v1.json \
  --contract-ids scripts/documentation-contract-ids.v1.json
```

The truth checker returns exit code 0 when clean, 1 for findings, and 2 for
invalid inputs or an unusable manifest. `--json` emits a stable report with
`schema_version`, `documents_checked`, and structured findings. Findings name
file, line, code, and a correction. SHA provenance manifests are required and
kept separate from prose so no external-repository revision is implicitly
claimed as a local commit.

## What is checked

- **Relative links:** inline/reference Markdown links in README and docs paths
  supplied to `scripts/check_relative_links.py`. HTTP(S), mail/tel/data/FTP,
  protocol-relative, and fragment-only references are ignored; fenced code is
  skipped. No external links are requested.
- **Claims:** only the DT-3 seed vocabulary (`production ready`, tool/system
  `replaces`, and an unqualified `is/are/was/were/remains accurate`) in files
  linked by the `Current` section of `docs/README.md`, plus root `README.md`.
  A same-sentence Markdown evidence link or an explicit qualifier such as
  `not`, `unknown`, or `unmeasured` satisfies this narrow lint. It intentionally
  does not attempt general semantic review. A new phrase needs a focused test
  before being added; do not expand this to historical issue/evidence files.
- **Commit references:** code-formatted 7–40 character hexadecimal strings
  outside fenced code in the same living set are checked against
  `scripts/documentation-sha-references.v1.json`. Each entry identifies the
  exact SHA, `repository`, `scope`, and attribution evidence. Local scopes
  (`local`, `historical-local`) must resolve to commit objects in this checkout.
  Target-side refs (`magnus919/SlopSearX`, `foreign-target`) are not checked
  against this object database; their attribution is explicit. Historical local
  refs absent from this checkout are explicitly `historical-not-retained` and
  are not locally verified. An absent/unknown record fails as
  `UNSCOPED_SHA`; a bad local object fails as `SHA_NOT_IN_REPOSITORY`.
  The manifest is a seed inventory rather than generated data; review it when document revisions are added, changed, or removed, and keep provenance statements backed by named source context.
- **Superseded contracts:** the checker compares living doc references to the
  registry's `deprecated` set, limited by the versioned
  `documentation-contract-ids.v1.json` selection. Mark a reference `deprecated`
  or `archived`; the registry's `### Deprecated contracts` section is
  self-describing. The selected list is intentionally small and must be updated
  alongside a contract migration.

The contract-ID list is a versioned projection of identifiers that DT-3 has
reviewed for prose references; it should be regenerated/updated when registry
entries change. Archived evidence and dated snapshots are
preserved and excluded from claim lint. The index and link checker continue to
cover them.

## Status freshness and OE-3 integration

The fresh/stale check is composable but does **not** run against
`docs/STATUS.md` in default CI yet. The companion
`scripts/documentation-truth-evidence.v1.json` records the DT-1 evidence revision
and narrow observed source paths as an OE-3 handoff, but it is intentionally not
a default CI gate: newer source commits postdate that observation. This change
does not rewrite the page or present a fresh review as performed.
Use a fixture to exercise the check:

```sh
python3 scripts/check_docs_truth.py \
  --sha-manifest scripts/documentation-sha-references.v1.json \
  --contract-ids scripts/documentation-contract-ids.v1.json \
  --freshness-manifest tests/fixtures/docs_truth/freshness-stale.json
```

The fixture is expected to fail with `STATUS_STALE`. CI validates that exact
seeded failure; it does not claim current status evidence is fresh. The callable
`check_status_freshness(root, manifest_path, head="HEAD")` and CLI
`--freshness-manifest` form the integration boundary for OE-3. The manifest
schema is `documentation-evidence.v1`:

```json
{
  "schema_version": "documentation-evidence.v1",
  "documents": [{
    "document": "docs/STATUS.md",
    "evidence_revision": "<full local commit SHA at which evidence was checked>",
    "evidence_date": "YYYY-MM-DD",
    "source_paths": ["src/pr_review_harness/cli.py"],
    "evidence_links": ["../src/pr_review_harness/cli.py"]
  }]
}
```

Required evidence fields are: repository-relative `document`; existing full
40-character local `evidence_revision`; `evidence_date` (date evidence was
produced, not the edit date); non-empty relevant repository-relative
`source_paths`; and non-empty `evidence_links`. Source paths define the exact
freshness dependency set. Each source's latest commit at the selected `head`
must be an ancestor of the evidence revision; a later source change fails as
`STATUS_STALE`. Evidence links must resolve inside the checkout; external links
are allowed as strings but never fetched. Invalid or missing data is an error,
not a pass. OE-3 can generate this manifest from its evidence artifacts without
changing the checker or allowing this checker to invent owners, decisions, or
quality claims. Current integration deliberately does not claim status freshness
until its evidence owner refreshes the record.

## Seeded failure coverage

`tests/test_docs_truth.py` proves the checkers reject a broken relative link, a
stale evidence revision, an unqualified phrase, a nonexistent local SHA, an
unscoped SHA, and a deprecated contract missing its marker. It also covers
valid local/foreign SHA attribution, qualified/evidence-linked claims, and a
current freshness record. Fixtures remain synthetic; no external project or
network is accessed.
