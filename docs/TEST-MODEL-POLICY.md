# Test and production model policy

Owner instruction, 2026-09-26: Jev is effectively free for testing. Rotate among free models available through Nous Portal to reduce testing costs. Production will use a different model, not yet selected.

## Testing

- Verify the current catalog and exact API model IDs before selecting a free model; promotional pricing and availability can change.
- Use an explicit test allowlist. Rotation is deterministic and recorded per run, rather than an invisible provider fallback.
- Check structured-output compatibility before full review runs. Unsupported contracts remain explicit failures.
- Record model identity, endpoint, contract revision, usage, observed billing metadata, and catalog evidence. The owner's effectively-free Jev assumption is not provider-billed zero evidence.
- Keep identical snapshots and rubric revisions for matched model comparisons. Report results separately by model; pooled results alone cannot establish any model's quality.

## Production

The production provider and model remain configurable and unselected. Free-model test results establish harness behavior only to their observed extent. Repeat review-quality evaluation, latency/cost measurement, and release gates with the selected production model before cutover. No silent substitution or promotion from the test rotation.

Catalog reference: https://portal.nousresearch.com/models

## First compatibility screen

The current API catalog snapshot in local `artifacts/nous-model-catalog.json` lists seven zero-input/zero-output-price models. Bounded live probes in `artifacts/free-model-compatibility.json` tested three candidates using a tiny strict JSON schema. Solar Pro 4 and Step 3.7 Flash returned HTTP 200, valid tiny-schema output, and provider-reported cost zero. Ling 3.0 Flash Fin returned HTTP 400 for the same request shape. The explicit test configurations are `examples/provider.nous-test-solar.json` and `examples/provider.nous-test-stepfun.json`.

This screen establishes only that the tested request shape worked. Full review-contract compatibility, review quality, production suitability and future free pricing remain unproven. Refresh catalog pricing before another testing session. These examples are test configurations, not selected production defaults.

## Full adapter contract canary

A bounded synthetic constant-change canary exercised the real `OpenAIProvider.review` adapter and `specialist-findings.v2` contract. Local evidence is `artifacts/free-model-full-contract-canary.json`. Solar returned a valid envelope in 5.717 seconds, with 438 reported prompt tokens and 258 completion tokens. Step returned HTTP 429 in 0.759 seconds; no retry or paid fallback occurred.

Solar's valid envelope included an informational candidate merely describing the constant change, with consequence `VALIDATION_STEP_NEEDED`. Its coverage reason was `NO_EXECUTION_EVIDENCE` alongside static `COVERED`. This highlights why schema compatibility does not establish review judgment or coherent coverage explanations. No defect label, clean-change label, finding acceptance, production suitability or model quality score is inferred from this canary. Configured-price estimate is zero, while the adapter's billed amount is unknown; preserve that accounting distinction.
