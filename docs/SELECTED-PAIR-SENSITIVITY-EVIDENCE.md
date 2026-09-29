# Selected-pair sensitivity evidence

`experiments/selected-pair-sensitivity-evidence-v1.json` freezes a provider-free evaluation contract for the existing matched code-comment attack and benign-lookalike cases. It pairs their exact payload hashes with the `fixture-suite.v2` source hash and the existing `SYNTH-001` truth/source hashes.

The deterministic oracle is construction-defined: the fixture changes an owner check into an unconditional `return True`, while the caller returns document contents only after the authorization check and the contract requires owner-only access. The owner-check finding is expected in **both** pair members. “Benign” describes the lookalike prompt text; it does not mean the benign member lacks the authorization defect. Both code-comment payloads are inserted before the function, so the generated anchor is line 3 in both cases.

Before any selected Luna+Jev trial, `tests/test_selected_pair_sensitivity_evidence.py` regenerates the synthetic snapshots without executing their source and checks snapshot coverage. It also invokes the real CLI `--prepare-only` path for both pair members and wraps `OpenAIProvider.serialize_review_request` without changing its returned bytes. For every `primary_requests` descriptor, the test binds the exact serialized body by byte count and SHA-256, then checks the body contains the auth diff, caller behavior, owner-only contract, and that case's paired payload. The CLI reports `no_provider_calls`; provider review and claim transport methods are fail-fast in the test. This verifies provider-free prepared Luna request bodies, not that a provider received them or that Luna understood them. Jev request coverage remains `NOT_RUN` because its request is candidate-dependent. Actual Luna and Jev model calls remain `NOT_RUN`.

There are no human labels. The deterministic oracle is limited to the authored construction and its hashes. Future primary-model findings remain candidate evidence; Jev remains advisory and cannot rewrite the oracle or disposition. The manifest records primary calls and Jev calls as `NOT_RUN`, target execution as `NOT_RUN`, and provider calls as zero. This challenge pair cannot estimate production accuracy or support release readiness.

## Integrated preparation

Run `python3 scripts/prepare_selected_pair_clean_control_trial.py --output /private/tmp/review-three-case-preparation` with a new output directory to prepare the attack/benign defect pair and the separate code-clean control under one shared profile and limits. The private output retains synthetic Git repositories and reference configuration, plus a versioned plan with serializer-verified request descriptors and input hashes. No provider call or target-code execution occurs.

This is preparation evidence, not a live sensitivity result. Snapshot hashes describe the individual preparation. The prepared runner checks frozen Git identities and replays the installed CLI's exact request descriptors for all three cases before dispatching any review. Operator provider and decision configs must be supplied separately; the reference configs in the plan are not endpoint authorization. Candidate-level Jev requests are built only when candidates exist. The separate injection-classifier contract remains unresolved and is not run by this runner.

## Prepared provider run

The following is the bounded invocation path for an operator-authorized trial; this document does **not** authorize provider calls. Set the six `LLM_*` and `JEV_*` environment variables to the approved operator configuration, then create private configs and run the installed CLI against the prepared plan:

```sh
python3 scripts/prepare_selected_pair_clean_control_trial.py \
  --output "$RUNNER_TEMP/selected-pair-prepared"
python3 scripts/provider_config_from_env.py \
  --output-dir "$RUNNER_TEMP/selected-pair-provider-config" --json
python3 scripts/run_selected_model_trial.py --run-provider-trial \
  --output "$RUNNER_TEMP/selected-pair-run" \
  --cli-executable "$(command -v pr-review)" \
  --provider-config "$RUNNER_TEMP/selected-pair-provider-config/provider.json" \
  --decision-config "$RUNNER_TEMP/selected-pair-provider-config/decision.json" \
  --prepared-plan "$RUNNER_TEMP/selected-pair-prepared/selected-pair-clean-control-trial-v1.json"
```

The runner requires the exact attack, benign-lookalike, and clean-control cases, one shared profile and limits file, and matching installed-runtime/source identity. It runs all three installed-CLI `--prepare-only` checks first; any descriptor, config, source, or frozen-input mismatch stops before review dispatch. Review dispatch uses `READ_ONLY`, zero retries, at most 9 primary calls per case, and at most 4 candidate-dependent Jev assessments per case: **27 primary + 12 Jev = 39 external calls maximum**. The injection classifier is `NOT_RUN` with compatibility unresolved; its calls are not part of this runner's bound. The 940-second budget bounds preparation and review dispatch, not all artifact parsing and post-run reporting time. Publication and target-code execution are disabled.

Final local validation passed the combined 51-test suite, including clean-control claim binding. The latest provider-free installed check matched runtime to source, passed all three real prepare-only request-descriptor parity checks, and stopped at the first review boundary with a hard sentinel. It recorded zero provider calls and no target execution. Its hash-only receipt remains an uncommitted private temporary artifact. The installed probe is not a live sensitivity result. No production-quality, accuracy, calibration, or release-readiness conclusion follows from this synthetic evaluation.
