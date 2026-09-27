# Selected-model claim-assessment trial

This source-checkout runner prepares or executes one bounded, three-case shadow screen by invoking the normal installed `pr-review` executable. The runner source and support files are fingerprinted separately from the installed CLI package; the executable is rejected unless its full installed package file set and hashes match the checkout. The fixed v2 cases are a synthetic control, code-comment attack, and benign lookalike. The runner never publishes a review or executes fixture code. Shadow assessments are advisory and do not alter the deterministic disposition.

The exact identities are fixed in the runner: the primary provider is Nous at `https://inference-api.nousresearch.com/v1` with model `openai/gpt-6-luna`; the claim assessor is TypeSafe at `https://api.typesafe.ai/v1/systemone` with configured alias `jev-latest`. TypeSafe may return a versioned serving-model identity; the artifact records that separately. A missing serving-model identity remains unknown. Any configured origin/model mismatch fails before a CLI invocation.

The offline preparation entrypoint requires an empty, newly created output directory and the actual installed CLI:

```sh
python scripts/run_selected_model_trial.py \
  --prepare-only \
  --output /private/tmp/selected-claim-preflight-001 \
  --cli-executable /path/to/installed/pr-review
```

Provider execution is an explicit second mode. The config files must come from `scripts/provider_config_from_env.py`; the six trusted environment values are supplied by the caller. Values never appear in command arguments, manifests, summaries, or runner logs:

```sh
python scripts/provider_config_from_env.py --output-dir /private/tmp/selected-claim-configs --json
python scripts/run_selected_model_trial.py \
  --run-provider-trial \
  --output /private/tmp/selected-claim-run-001 \
  --cli-executable /path/to/installed/pr-review \
  --provider-config /private/tmp/selected-claim-configs/provider.json \
  --decision-config /private/tmp/selected-claim-configs/decision.json
```

The runner accepts no model, endpoint, fixture, or budget override. Per case, the bound is 300 seconds overall, 270 seconds engine time, at most nine provider calls including four claim assessments, no retries, 64,000 input bytes per task, 300,000 context bytes, 32,768 output bytes and 4,096 output tokens per provider response. The matrix stops at 900 seconds. These are experiment ceilings, not spend guarantees; billed cost stays `UNKNOWN` unless authoritative usage says otherwise.

Only a bounded sanitized summary is retained. It keeps source/snapshot/profile/config/runtime hashes, candidate text that passes size and credential/canary scans, typed per-candidate statuses and choices, bounded probabilities, provenance, reservations, and known usage. Raw CLI result/report files are capped, scanned in memory, then deleted; the summary records their hashes and sizes. The shared invocation helper discards raw stderr, so stderr echo scanning is `UNKNOWN`; it also records hashes and byte counts for failed stdout without retaining or scanning the discarded bytes. Process-descendant, network-destination, and filesystem-effect telemetry remain `UNKNOWN`; `READ_ONLY` is the CLI policy, and the runner's artifact scan is not a general side-effect proof.

The output is a compatibility and evidence-pairing artifact for review. Synthetic agreement is not human ground truth, calibrated quality, prompt-injection resistance, or production approval. Do not use this trial to change the primary reducer or promote the advisory stage to a gate.
