# Bounded free-model test matrix

`scripts/run_test_matrix.py` runs the read-only review CLI against an explicit immutable revision pair and an explicit allowlist of test models. It records operational compatibility evidence by model. It does not run reviewed code, publish comments, select a production provider, or claim review quality.

## Select the revisions deliberately

The frozen `historical-pilot-v1` sample replays six purposive first-parent base/head pairs from the earlier SlopSearX pilot. Those pairs are pilot context; they are not exact PR-only diffs for the Droid review case and are not a held-out quality set.

For an exact change, provide its full immutable base and head SHAs:

```sh
python3 scripts/run_test_matrix.py \
  --pair <BASE_SHA>..<HEAD_SHA> \
  --repo /path/to/slopsearx \
  --profile profiles/slopsearx.json \
  --model solar --model stepfun \
  --model-catalog artifacts/nous-model-catalog.json \
  --output artifacts/test-matrix
```

The matrix labels explicit pairs `EXPLICIT_REVISION_PAIRS`; it does not verify PR identity. It rotates the selected model order deterministically by pair, then evaluates every selected model on the same pair. Model results remain separate. There is no automatic retry, paid fallback, or substitute model.

## Bind captured check evidence to one pair

Use repeatable `--checks-json PAIR_ID=PATH` only when a captured, versioned check-run document is intentionally part of the experiment. For explicit pairs, IDs are assigned in input order (`pair-01`, `pair-02`, and so on). The runner requires the evidence repository to match the trusted profile's `repository`, the captured head to match that pair, and any captured base to match when present. It records the evidence file hash and the explicit pair binding in the matrix input identity, stages the exact captured bytes for that run, and rechecks the file hash around dispatch. Evidence is never copied implicitly to another pair, including another pair with the same head. This is a historical input; the matrix does not fetch current checks or make a freshness claim.

For example, the known PR #464 pair can include its captured check evidence for `pair-01`:

```sh
python3 scripts/run_test_matrix.py \
  --pair 20a743f0434a1843aa00068483f608f1e213b2af..bffc26f9e4bf95aca0c252e88a2396d03ece854c \
  --repo /path/to/slopsearx \
  --profile profiles/slopsearx.json \
  --model solar \
  --model-catalog artifacts/nous-model-catalog.json \
  --checks-json pair-01=tests/fixtures/pr464-check-evidence.json \
  --output artifacts/pr464-matrix
```

The fixture is bound to `magnus919/SlopSearX`, PR 464, and head `bffc26f9e4bf95aca0c252e88a2396d03ece854c`; its source capture does not carry a base SHA, so this example's explicit immutable pair supplies the base identity. Captured passing checks can satisfy only matching check obligations. They do not establish a current check state, complete review coverage, or review quality. The run still requires the normal fresh model catalog and provider setup described above.

## Preflight and finite limits

Before dispatch, the runner verifies each provider config against its exact allowlisted model ID, Nous endpoint, environment-variable credential reference, and configured zero input/output price. It also requires a captured `/v1/models` catalog sourced from that endpoint, no older than five minutes by default, with exactly one matching model record and zero prompt/completion pricing for each selected model. The manifest captures the catalog timestamp, exact file hash, source, selected IDs, and observed prices. Refresh the catalog immediately before a live matrix; its price is still an observation, not a billing guarantee.

The runner enforces finite per-run and whole-matrix wall deadlines, a bounded provider call count, no retries, bounded context/input/output bytes, and a bounded output-token count. It does not fabricate an operator monetary reservation from a price estimate. Provider-estimated cost and provider-billed cost are reported separately; billed cost remains `UNKNOWN` unless authoritative provider metadata supplies it.

The child process receives a fresh temporary home and a small environment allowlist. Only the selected config's named credential environment variable passes through, and only to the CLI transport. Secret values are never written into the manifest. The reviewed repository is passed to the CLI as a source of Git objects; the runner does not execute its code or install its dependencies.

The runner fingerprints relevant harness, profile, provider-config, and source files. Each run checks for source/config/profile changes before and after dispatch; a change stops further scheduling and labels results incomplete. Module mode pins imports to this source tree and records its source hash. An installed executable is identified by path and executable hash, but its imported package source is explicitly `UNKNOWN`; the manifest does not claim that it ran the workspace tree.

## Retained evidence and interpretation

The JSON manifest records the immutable base/head pair, sample kind, profile and source hashes, provider-config and effective-limits hashes, model alias, provider-reported model IDs when present, per-run status/exit/latency/output hashes, bounded task-status/error and quarantined-item counts, token usage, provider-estimated cost, provider-billed cost, and unknown states. Child stdout/stderr are hashed and discarded. Raw prompts, findings, provider output, and credential values are not copied into the matrix manifest.

`COMPLETED` means the bounded CLI subprocess returned a valid JSON result and exit code zero. It does not mean the review is correct or complete. `HTTP 429`, schema rejection, timeouts, invalid output, source mutation, and skipped work are retained as failed/incomplete operational results. Interpret them per model and revision pair. A transport-compatible model, zero listed price, static `COVERED` note, or clean CLI exit is not review-quality evidence or cutover approval.

Run local verification without provider calls:

```sh
PYTHONPATH=src python3 -m pytest tests/test_test_matrix.py -q
```

The tests use local Git fixtures, a captured catalog fixture, an injected fake CLI result, and short local child processes. They do not contact Nous or another provider.
