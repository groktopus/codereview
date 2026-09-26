# Deployment configuration

This document describes the generic provider configuration path wired into the reusable read-only analysis workflow. The workflow source accepts operator-selected endpoints and models through trusted `workflow_call` secrets. That source wiring has not been validated in a hosted run, and no production credential or model-quality claim is made here.

## Environment contract

| Name | Workflow binding | Purpose | Intended value |
|---|---:|---|---|
| `LLM_BASE_URL` | Required secret | OpenAI-compatible API root; the adapter appends `/chat/completions`. | Operator-selected root; the first intended deployment is NousPortal. |
| `LLM_MODEL` | Required secret | Model identifier sent to the configured LLM endpoint. | Operator-selected model; no production default is verified. |
| `LLM_API_KEY` | Required secret | Credential used by the LLM adapter. | Operator-managed credential. |
| `JEV_BASE_URL` | Required secret | Native System One API root; the adapter appends `/systemone`. | Operator-selected native Jev root. |
| `JEV_MODEL` | Required secret | Model identifier sent to the native Jev endpoint. | Operator-selected model. |
| `JEV_API_KEY` | Required secret | Credential used by the native Jev adapter. | Operator-managed credential. |

All six values are declared as required reusable-workflow secrets so neither a pull request nor caller inputs can select a destination or model. Only the two `*_API_KEY` values are authentication credentials. Do not place key values in provider JSON, command-line arguments, source control, workflow artifacts, logs, or review inputs. Endpoint and model values must remain controlled by trusted repository configuration.

Configure an endpoint only when it implements the required API contract. The OpenAI-compatible URL is the API root before `/chat/completions`; the native Jev URL is the root before `/systemone`. Roots may have provider-specific paths and do not have to end in `/v1`. The helper rejects URL credentials, query strings, fragments, and roots that already end in the adapter route. HTTPS is required for remote endpoints; HTTP is permitted only for loopback adapters. Endpoint acceptance does not establish service trust, availability, model quality, or semantic equivalence. Pin model identifiers when reproducibility matters and retain provider-reported model identity in each run.

## Mapping to the current provider configuration

The current CLI loads two provider JSON files. `scripts/provider_config_from_env.py` validates all six selected variables, validates the generated objects with the production adapter constructors, and writes `provider.json` and `decision.json` beneath a new output directory. The directory is created with mode `0700`; the files use exclusive creation and mode `0600`. The JSON stores only the two credential environment-variable names, never their values. The helper prints the two file paths (or emits those paths as JSON with `--json`). The reusable workflow stores these ephemeral files under `RUNNER_TEMP`, outside its uploaded artifact directory.

Run it from a trusted deployment step with an output directory that does not already exist:

```sh
python scripts/provider_config_from_env.py \
  --output-dir "$RUNNER_TEMP/pr-review-provider-config-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT" \
  --json
```

Pass the returned `provider_config` path to `--provider-config` and `decision_config` path to `--decision-config`. The helper makes no provider or GitHub requests. It rejects remote plaintext HTTP, URL credentials/query/fragments, missing or oversized values, and roots that already include the final adapter route.

The emitted LLM JSON includes `kind: "openai_compatible"`, `provider_id: "operator_openai_compatible"`, `base_url`, `model`, and `api_key_env: "LLM_API_KEY"`. The helper removes trailing slashes from `LLM_BASE_URL`; the adapter appends `/chat/completions`.

The emitted Jev JSON includes `kind: "typesafe"`, `endpoint`, `model`, and `api_key_env: "JEV_API_KEY"`. The helper forms `endpoint` as `JEV_BASE_URL + "/systemone"`; the API root must not already end in `/systemone`.

The generated files have these shapes; values of the two API-key variables are not included:

```json
{
  "provider_config": {
    "kind": "openai_compatible",
    "provider_id": "operator_openai_compatible",
    "base_url": "<LLM_BASE_URL>",
    "model": "<LLM_MODEL>",
    "api_key_env": "LLM_API_KEY"
  },
  "decision_config": {
    "kind": "typesafe",
    "endpoint": "<JEV_BASE_URL>/systemone",
    "model": "<JEV_MODEL>",
    "api_key_env": "JEV_API_KEY"
  }
}
```

The placeholders above are explanatory; use the generated files rather than copying this sketch. Keep model limits, request/response byte limits, timeouts, and cost estimates in trusted deployment configuration as finite values. Do not infer a spend limit from provider pricing; the deployment owner must set an explicit budget.

## Hosted workflow status

The reusable `pr-analysis.yml` source now declares all six names as required `workflow_call.secrets`, materializes the two configs in `RUNNER_TEMP`, and passes both files to the existing CLI. It does not fetch a Nous model catalog or use a free-test model config; the historical `review-commits.yml` workflow remains a separate bounded free-model test path. The target repository must map each required name from trusted repository secrets. Source wiring has not been exercised in a hosted run, so provider connectivity, runtime success, and review quality remain unverified.

The publication workflow is disabled and has no write-capable review credential. Provider setup does not enable review publication. Do not add a `pull-requests: write` permission or a writer secret as part of ordinary provider configuration.

No production credential values were read or tested while preparing this document.
