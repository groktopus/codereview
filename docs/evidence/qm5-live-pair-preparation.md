# QM5 live-pair preparation v1

This first implementation slice prepares one selected reciprocal pair from the
frozen `examples/evaluation/adversarial-pairs-v1` inventory. It verifies the
manifest, every listed file hash, exact inventory membership, and safe fixture
paths before constructing deterministic local synthetic Git snapshots. The
generated Git commits are real local objects for those fixture bytes; they are
not upstream commits and do not replace the authored placeholder identities.

Run the provider-free preparation entry point with the exact checked-out source
revision, one allowlisted pair, and a new output directory:

```sh
python scripts/run_qm5_live_pair_trial.py \
  --prepare-only \
  --pair-id adv-v1-diff \
  --source-revision "$(git rev-parse HEAD)" \
  --run-id local-review-001 \
  --run-attempt 1 \
  --output-dir /path/to/new-preparation
```

The output contains `qm5-live-pair-preparation.v1.json` and two bare local Git
repositories under `snapshots/`. The artifact maps authored pair, case, and
harness run IDs as provenance to namespaced preparation IDs; records actual
base/head commit and tree IDs, source-derived diff anchors, exact source and
corpus digests, and the current `selected-native-paired-claim.v2` caps. Caps
remain 5 calls per case (4 primary and 1 claim assessment), zero retries. The
prepared artifact is marked `READ_ONLY`, `NOT_DISPATCHED`, and effect
observation `UNKNOWN`.

For this two-case pair, the artifact also records a derived ceiling of 10 calls
(8 primary and 2 claim assessments) across the pair. Each case retains the v2
limits independently; the pair ceiling is their arithmetic sum.

The artifact records relevant worktree state and compares the adapter, cap
contract source, and CLI bytes with the named source revision. A dirty
development preparation is explicitly `DIRTY_UNVERIFIED`, has
`dispatch_eligible: false`, and cannot be created by the CLI, which requires a
clean relevant source tree.

This command does not read provider configuration, access the network, execute
fixture code, or dispatch a review. Live execution is deliberately unavailable
in this slice and fails closed. Do not interpret a prepared pair as a model
result, an effect observation, or a quality measurement. The authored corpus
and its predictions, labels, manifest, scorecard, and historical evidence are
unchanged.
