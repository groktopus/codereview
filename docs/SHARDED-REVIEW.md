# Lens-sharded review wrapper

`scripts/sharded_review.py` runs one bounded review per review lens over the
same immutable base/head pair and merges the shard results deterministically.
It exists because a single plan for a large change can exhaust the shared
context or provider budget and return only partial coverage.

The wrapper is local orchestration. It reads trusted JSON inputs, starts
`python -m pr_review_harness review` once per lens, and writes a combined local
result. It never calls a network API itself, never publishes a review, and
never executes target code. The review subprocess remains read-only
(`--effect-policy READ_ONLY`).

The owner approved a one-off CA-2 budget exception for this wrapper. It is a
separate `scripts/` tool; it does not add code to `src/pr_review_harness` and
does not change the package feature budget recorded in
[ADR 0001](adr/0001-post-ca2-feature-budget.md).

## Command

```sh
python scripts/sharded_review.py \
  --repo /path/to/repository \
  --base <base-sha> \
  --head <head-sha> \
  --profile profiles/generic.json \
  --provider-config /trusted/provider.json \
  --limits /trusted/limits.json \
  --output artifacts/sharded-review \
  --mode FOCUSED \
  --json
```

| Argument | Meaning |
|---|---|
| `--repo` | Local Git repository or bare object repository. |
| `--base`, `--head` | Explicit immutable revisions. The same pair is passed to every shard. |
| `--profile` | Trusted external profile JSON. A temporary single-lens copy is created for each shard. |
| `--provider-config` | Optional trusted provider configuration passed to every shard. |
| `--limits` | Optional trusted finite limits file passed unchanged to every shard. |
| `--output` | A `.json` file path, or a directory. A directory receives `sharded-review.json`. |
| `--lenses` | Optional comma-separated override. Default: the profile's `required_lenses`, or `correctness,tests,maintainability` when that field is absent or empty. |
| `--mode` | Optional `AUTO`, `LIGHT`, `FOCUSED`, or `DEEP`; passed to every shard. |
| `--json` | Emit the combined result on stdout as one JSON value. |

Exit code `0` means the combined result is `COMPLETE`; `1` means the combined
result was written but is `INCOMPLETE`; `2` means the wrapper rejected its
inputs before a run.

The wrapper forwards only the arguments listed here. It does not provide a
decision-provider, claim-assessment cap, price table, or check evidence file.
A profile whose preflight requires those inputs is rejected by the review
subprocess and appears as a failed shard; use a profile that is valid under
the listed arguments, or run the core CLI directly.

## Per-lens profile copy

For each selected lens the wrapper writes a temporary profile copy derived from
the trusted profile:

- `required_lenses` becomes exactly `[lens]`.
- `docs_lenses`, `documentation_lenses`, `default_lenses`, and `security_lenses`
  are filtered to the selected lens when present.
- `review_criteria` keeps only the selected lens entry.
- `risk_rules` keeps only rules that explicitly name the selected lens, and
  each retained rule is narrowed to that lens. Rules for other lenses are
  removed so a shard cannot silently expand its scope.

All other profile fields (context selection, checks, policy paths, effect
policy, classifications, repository identity) are copied unchanged.

Each shard gets its own temporary output directory. The wrapper requires exit
code `0` and exactly one `*.json` result in that directory. A different exit
code, a missing result file, multiple result files, or invalid JSON becomes an
explicit failed shard. Nothing is skipped because a shard failed.

## Merge contract

The combined document uses `schema: "review-sharded-result.v1"`.

- **Disposition:** `INCOMPLETE` if any shard is `INCOMPLETE`, `UNKNOWN`, or
  `FAILED`, or if any shard coverage is not `COMPLETE`. Otherwise
  `REQUEST_CHANGES` if any shard requests changes, else `COMMENT` if any shard
  comments, else `APPROVE`.
- **Completeness:** `COMPLETE` only when every requested shard ran, produced a
  result, reported `COMPLETE` coverage, and returned `APPROVE`, `COMMENT`, or
  `REQUEST_CHANGES`.
- **Findings:** the union of all shard findings, deduplicated by
  `(path, title)` when both are present, otherwise by the stable `finding_id`,
  otherwise by a SHA-256 hash of the finding. The first occurrence wins and
  shard order follows the requested lens order.
- **Context gaps:** the union of all shard context gaps, deduplicated by
  `proposal_id`, then `(reason_code, path)`, then a stable hash.
- **Reasons:** each shard records reasons for an incomplete result, and the
  combined `incomplete_reasons` array names every shard that was not usable.
  No shard is dropped or silently replaced.
- **Provider/cost:** provider identities are deduplicated; provider-call
  reservations are summed; billed and estimated micro-unit costs are summed
  only when every shard reports known values. Otherwise the total is
  `UNKNOWN`.

Example shape:

```json
{
  "schema": "review-sharded-result.v1",
  "disposition": "COMMENT",
  "completeness": "COMPLETE",
  "lenses": ["correctness", "tests", "maintainability"],
  "shards": [
    {
      "lens": "correctness",
      "disposition": "COMMENT",
      "coverage": "COMPLETE",
      "findings": [],
      "result_sha256": "<sha256 of the shard result bytes>",
      "exit_code": 0,
      "reasons": []
    }
  ],
  "findings": [],
  "context_gaps": [],
  "incomplete_reasons": [],
  "provider": {"identities": [], "provider_calls_reserved": 3},
  "cost": {
    "billed_microunits": "UNKNOWN",
    "estimated_microunits": 1234,
    "billing_known": false,
    "estimate_known": true
  }
}
```

## Verification

```sh
ruff format --check scripts/sharded_review.py tests/test_sharded_review.py
ruff check scripts/sharded_review.py tests/test_sharded_review.py
python -m pytest tests/test_sharded_review.py -q
python scripts/check_complexity.py --json
python scripts/check_docs_index.py
```

The tests use injected fake shard entries. They cover all-complete approval,
one request-changes shard, one incomplete shard, duplicate-finding dedupe,
per-lens profile generation, missing/failed shards, and combined-output
writing. The wrapper is not a replacement for the review engine and does not
make a model-quality claim; it only changes how a bounded review is divided and
recombined.
