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
python3 scripts/generate_status_evidence.py --check
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
  Each claim occurrence is evaluated independently. Direct negatives
  (`is not accurate`, `does not replace`, `not production ready`) are allowed;
  later contrast clauses, another table row, or another sentence cannot qualify
  the claim. A nearby link waives only its same-row claim when its label
  identifies evidence (`test evidence`, `run`, or `artifact`); unrelated
  navigation links do not. This is a narrow syntactic lint, not general semantic
  review. Add phrases only with focused positive and adversarial tests. Historical
  issue/evidence documents remain outside the claim-lint target.
- **Commit references:** code-formatted 7–40 character hexadecimal strings
  outside fenced code in the same living set are checked against
  `scripts/documentation-sha-references.v1.json`. Each entry identifies a
  `kind` (`commit`, `run-id`, or `artifact-digest`), exact `value`, `repository`,
  `scope`, and attribution evidence.
  Backtick contents are parsed as whole tokens, never as matching prefixes:
  7–40 hexadecimal characters (including digits only) are commit candidates;
  41–63 hex characters fail as `MALFORMED_SHA`. A 64-character token is an
  `artifact-digest` only when nearby wording explicitly says SHA-256/digest/hash;
  other overlong tokens fail. Decimal run/job/check/artifact/review IDs are
  `run-id` only when nearby wording explicitly names one, and must be 7–12
  digits. Everything else remains a commit candidate, so an unknown numeric
  token is not ignored. Local commit scopes (`local`, `historical-local`) must
  resolve to commit objects in this checkout. Target-side commits
  (`magnus919/SlopSearX`, `foreign-target`) and run IDs/artifact digests are
  explicitly attributed but not checked as local commits. Historical local refs
  absent from this checkout use `historical-not-retained` and are not locally
  verified. An absent/unknown record fails as `UNSCOPED_SHA`; bad local objects
  fail as `SHA_NOT_IN_REPOSITORY`. The manifest is a seed inventory rather than
  generated data; review it when references change and keep provenance statements
  backed by named source context.
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

OE-3 adds a separate derived page, [STATUS-EVIDENCE.md](STATUS-EVIDENCE.md), and
`scripts/documentation-status-evidence.v1.json`. They are generated from checked-in
artifacts by `scripts/generate_status_evidence.py`; the `status-evidence` CI job
verifies reproducibility, artifact links, contract labels, and freshness, and
seeded stale and superseded-contract failures. The generated block records the
owner-reviewed page's `STATUS_STALE` finding verbatim and never writes
`docs/STATUS.md` or claims an owner review. The DT-1 handoff manifest for
`docs/STATUS.md` therefore remains a non-passing record until an owner refreshes
it; only the derived page's own artifact dependency set is gated as fresh.

## Seeded failure coverage

`tests/test_docs_truth.py` proves the checkers reject a broken relative link, a
stale evidence revision, an unqualified phrase, a nonexistent local SHA, an
unscoped SHA, and a deprecated contract missing its marker. It also covers
valid local/foreign SHA attribution, qualified/evidence-linked claims, and a
current freshness record. Fixtures remain synthetic; no external project or
network is accessed.
