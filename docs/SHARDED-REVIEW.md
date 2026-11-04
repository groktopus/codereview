# Path-scoped sharded review

`scripts/sharded_review.py` splits a large changed-file set into bounded batches
and runs the **full trusted profile** once per batch. Each shard is restricted to
its own paths; no lens, risk rule, required check, policy rule, or review
criterion is removed. The combined artifact is complete only when every shard is
complete.

The script is read-only. It invokes the existing
`python -m pr_review_harness review` entry point in a separate process for each
batch, passes `--effect-policy READ_ONLY`, and never publishes a review, writes
a comment, or contacts a provider itself.

## Profile path scope

Profiles may carry an optional `scope_paths` list of nonempty `fnmatch`
patterns:

```json
{
  "version": "slopsearx-production-v8-static-review-boundaries",
  "scope_paths": ["src/pr_review_harness/planner.py", "tests/test_planner.py"]
}
```

Validation and planning semantics:

- `scope_paths` must be a nonempty list of unique, nonempty strings.
- When present, `plan_review` filters the changed inventory to units whose path
  matches at least one pattern **before** routing, risk rules, check bindings, or
  coverage obligations are constructed.
- Every supplied pattern must match at least one changed unit. An unmatched
  pattern raises an explicit `ValueError`; it never becomes a silently empty or
  partially scoped plan.
- Required snapshot gaps and explicit check unit bindings are restricted to the
  same units. A check whose explicit units are all outside the scope is recorded
  as `NOT_APPLICABLE` instead of becoming a scoped obligation.
- All other profile semantics are unchanged. The scoped plan for a set of paths
  matches the unsharded plan restricted to those paths: the same units, lenses,
  risk reasons, and check scope are preserved.

The generated profile retains the source profile's version and repository
identity, but it is a derived run input, not a replacement registered profile.
The orchestrator records the source profile SHA-256 and each generated shard
profile SHA-256 so the derivation is auditable.

## Partition contract

Changed files come from the immutable Git diff:

```python
git -C <repo> diff --name-only -z <base>..<head>
```

The command is a fixed argument array; no shell interpolation is used. The
default batch size is 6 and `--batch-size` changes it. Paths are kept in diff
order and partitioned into disjoint, ordered batches. Before any provider work,
the orchestrator asserts that the multiset union of batches equals the exact
diff set and that no path appears in more than one batch. A missing or
overlapping path is a hard orchestration error, not a partial review.

## Per-shard execution

For each batch the script:

1. Copies the full profile and sets `scope_paths` to the batch's exact paths.
   `*`, `?`, and `[` in a literal path are escaped as `[*]`, `[?]`, and `[[]`,
   so an exact path cannot become a broader glob.
2. Writes the generated profile under `<output>/<shard-id>/profile.json` and
   records its SHA-256.
3. Runs `python -m pr_review_harness review` with explicit `--base` and
   `--head`, a separate `--output` directory, a deterministic `--run-id`, and
   `--effect-policy READ_ONLY`.
4. Passes the configured provider/decision/limits/check inputs through
   unchanged. The script does not add a provider, endpoint, model, or limit.
5. Removes `GITHUB_EVENT_PATH`, `GITHUB_TOKEN`, `GH_TOKEN`, `ACTIONS_*`, and
   `PUBLISH_REVIEW` from the child environment. The child receives no event
   identity or publication switch from the parent shell.
6. Records the shard's base, head, generated profile hash, result hash,
   disposition, coverage state, and explicit incomplete reasons.

A required claim reconciliation policy needs its exact decision-provider
configuration, exactly as it does without sharding. A profile whose required
claim stage cannot be configured fails before provider work; sharding does not
weaken that requirement.

## Completeness, disposition, and merging

A shard is complete only when the subprocess exits zero, its durable result
exists, its coverage state is `COMPLETE`, and no coverage row, policy, freshness,
or budget condition marks the result incomplete. The combined `completeness` is
`COMPLETE` only when every expected batch is complete. A missing result, timeout,
nonzero exit, or partial coverage makes the combined artifact `INCOMPLETE` and
preserves the per-shard reasons in `incomplete_reasons`.

Disposition uses the harness's blocker-preserving precedence:

```text
REQUEST_CHANGES > INCOMPLETE > COMMENT > APPROVE
```

A known blocker in any complete shard therefore survives an incomplete sibling.
If no blocker exists, an incomplete shard prevents approval and yields
`INCOMPLETE`.

Findings are deduplicated by path/location/title/observation. When duplicate
records disagree, the strongest status and blocking class wins, and every
contributing shard id is retained. Context gaps and snapshot gaps are
deduplicated by their resolved unit and target; affected obligation and evidence
ids are unioned. Findings, gaps, and snapshots from different shards are never
silently dropped.

## Output

The default combined path is `<output>/review-sharded-result.json`; `--result`
overrides it. The record uses schema `review-sharded-result.v1` and includes:

- `schema`, `created_at`, `repo`, `base_sha`, `head_sha`, `batch_size`;
- `diff_files`, `diff_files_sha256`, and a `partition` assertion record;
- source `profile` path/hash/version and `limits` path/hash;
- `completeness`, `disposition`, merged `findings`, `context_gaps`, and
  `snapshot_gaps`;
- `coverage` totals and incomplete reason codes;
- one `shards` entry per batch with paths, base/head, generated profile hash,
  result path/hash, disposition, coverage state, and reasons;
- `incomplete_reasons` and deduplicated provider identities.

The command exits `0` only for a complete combined artifact. A complete review
with `REQUEST_CHANGES`, `COMMENT`, or `APPROVE` is still exit `0`; incomplete or
failed orchestration is exit `1`; invalid inputs are exit `2`.

## Example

```bash
python scripts/sharded_review.py \
  --repo /path/to/repository \
  --base <full-base-sha> \
  --head <full-head-sha> \
  --profile profiles/generic.json \
  --provider-config /trusted/provider.json \
  --limits profiles/ordinary-review-limits-v3.json \
  --batch-size 6 \
  --output artifacts/sharded-review \
  --json
```

Sharding reduces each provider request's changed-unit set; it does not create
missing evidence. A shard that lacks required CI evidence, policy context, or a
provider result remains explicitly incomplete. Use the report to add the missing
evidence, not to relax the profile.
