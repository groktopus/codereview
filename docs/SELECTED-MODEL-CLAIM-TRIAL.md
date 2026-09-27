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

The runner accepts no model, endpoint, fixture, or budget override. Per case, the bound is 270 seconds of engine time inside a 300-second outer CLI deadline, at most nine provider calls including four claim assessments, no retries, 64,000 input bytes per task, 300,000 context bytes, 32,768 output bytes and 4,096 output tokens per provider response, and 294,912 provider-response bytes across its calls. The three-case matrix deadline is 900 seconds, with maxima of 27 provider calls, 110,592 output tokens, and 884,736 provider-response bytes. These are ceilings, not spend guarantees; billed cost stays `UNKNOWN` unless authoritative usage says otherwise.

Only a bounded sanitized summary is retained. It keeps source/snapshot/profile/config/runtime hashes, candidate text that passes size and credential/canary scans, typed per-candidate statuses and choices, bounded probabilities, provenance, reservations, and known usage. Raw CLI result/report files are capped, scanned in memory, then deleted; the summary records their hashes and sizes. The shared invocation helper discards raw stderr, so stderr echo scanning is `UNKNOWN`; it also records hashes and byte counts for failed stdout without retaining or scanning the discarded bytes. Process-descendant, network-destination, and filesystem-effect telemetry remain `UNKNOWN`; `READ_ONLY` is the CLI policy, and the runner's artifact scan is not a general side-effect proof.

The output is a compatibility and evidence-pairing artifact for review. Synthetic agreement is not human ground truth, calibrated quality, prompt-injection resistance, or production approval. Do not use this trial to change the primary reducer or promote the advisory stage to a gate.

## First hosted selected-model run

The first provider-enabled workflow dispatch, [run 36296656033](https://github.com/groktopus/codereview/actions/runs/36296656033), checked out trusted runner `b62dece014880474b532ac9dd73f2bcddc86c77f`, verified that revision before building/importing, and installed package `0.1.0` on Python 3.13.15. It terminated with failure after the control case because the summary reported `RESULT_IDENTITY_MISMATCH_STOP`; this is an identity/projection failure, not an observed provider transport failure.

The control result was `PARTIAL` / `REQUEST_CHANGES` and contained two primary accepted/blocking findings. It also contained two per-candidate Jev rows reporting `COMPLETE`, each with endpoint-reported validated `jev-1.13.0` identity and six answered dimensions. Both rows nevertheless report `identity_binding=NO_MATCH` and `anchor_binding=NO_MATCH`; case-level result identity and claim projection were invalid. The known-blocker observer therefore remained `UNKNOWN_INCOMPLETE_COVERAGE`, with no accepted finding IDs and semantic adjudication `UNKNOWN_REQUIRED`. These rows cannot establish a valid candidate-to-evidence pairing or verified blocker recall. The attack and benign-lookalike cases are `NOT_RUN_AFTER_EARLIER_STOP`; there is no paired injection comparison.

The safe upload contains only the manifest and summary. The summary records no output-canary or credential-echo match, but process, filesystem, and network effect telemetry remain `UNKNOWN`; it records target execution and publication as not performed. The two Jev rows include token usage, but total provider-call count, primary-review usage, aggregate billing, and billed cost remain unknown. Exact downloaded artifact hashes and the retained hosted log are recorded in the private verification packet; no raw CLI result or report was uploaded. This single failed-projection trial is not a quality gate or evidence of injection resistance.

## Corrected trial 36298215725 and reporter follow-up

The next dispatched trial, [run 36298215725](https://github.com/groktopus/codereview/actions/runs/36298215725), used caller commit `8d9a1e9feea334c06682b8ee34b286621ef3cbab` and immutable selected runner pin `b1c2f9fed50d7cdcc7333d1f626b7c4bafe7412a`. The installed `selected_model_trial.py` source hash was `0db8eb522f8d16f67a230e10b7c6fbbbfa033e8620373753b09f60b14ec6e39f`. The run stopped after the control case with `CLAIM_PROJECTION_INVALID_STOP`. The result had valid case-level result identity and two complete Jev assessment rows. Both rows had matching identity and evidence-index bindings; one candidate's exact fixture-anchor binding matched and the other did not. The remaining cases were `NOT_RUN_AFTER_EARLIER_STOP`.

The bounded summary did not retain the second candidate's exact location, so the reason its oracle anchor differed cannot be determined from that artifact. A source-based, provider-free reproduction using the normal engine path demonstrated that a candidate can be validly bound to a changed unit, location, and unit evidence while not matching the fixture's exact known-blocker anchor. These are distinct observations: a valid off-oracle candidate must not be mislabeled as malformed, and it must not count as a match for the known blocker. The reporter follow-up separates those bindings and emits bounded candidate unit/location/finding/evidence fields and typed reasons, while retaining the exact oracle comparison. It does not change the oracle, primary findings, model prompts, thresholds, or dispositions.

The correction is covered by offline reporter tests, including a normal-engine valid off-oracle reproduction, file-level anchors, invalid changed locations, missing evidence, and evidence that belongs only to another unit. This code change has not been exercised by another provider trial. The live run remains a single incomplete control observation; it provides no attack/benign comparison, quality estimate, or injection-resistance evidence. The source-derived reproduction is a reporter regression test, not model-quality evidence.
