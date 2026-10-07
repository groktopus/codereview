# Deployment configuration

This document describes the generic provider configuration path wired into the reusable read-only analysis workflow. The workflow accepts operator-selected endpoints and models through trusted `workflow_call` secrets. See [PILOT-EVIDENCE.md](PILOT-EVIDENCE.md) for dated hosted observations. The current runner and budget revision has been exercised in hosted runs, including selected synthetic cases (37613000271) and a natural review observation (37615254908; caller 9beaa99bf02faee248f399a21df6cacaa9962086, runtime 4fbc3b0a4e45596c3c73685edc8be575e2173e27). The natural review returned `INCOMPLETE / PARTIAL` under its context budget; these observations make no model-quality claim.

## Trusted target profile selection

The reusable workflow resolves `target_repository` through the checked-in `profiles/targets.json` allowlist before it materializes provider configuration. A binding pins the profile path, exact profile-file SHA-256, and profile version; the selected profile must also declare the same repository and version. The caller cannot provide a profile path or digest, and unsupported repositories fail closed instead of receiving the generic profile. To add a repository, review a mapping entry and matching repository-bound profile into the trusted harness revision, then update the caller to pin that revision. The workflow records the selected binding in `profile-binding.json` with the analysis artifact.

## Environment contract

| Name | Workflow binding | Purpose | Intended value |
|---|---:|---|---|
| `LLM_BASE_URL` | Required secret | OpenAI-compatible API root; the adapter appends `/chat/completions`. | Exercised alias: `https://inference-api.nousresearch.com/v1`. |
| `LLM_MODEL` | Required secret | Model identifier sent to the configured LLM endpoint. | Exercised alias: `openai/gpt-6-luna`; not a pinned model-version guarantee. |
| `LLM_API_KEY` | Required secret | Credential used by the LLM adapter. | Operator-managed credential. |
| `JEV_BASE_URL` | Required secret | Native System One API root; the adapter appends `/systemone`. | Exercised API root: `https://api.typesafe.ai/v1` (do not include `/systemone`). |
| `JEV_MODEL` | Required secret | Model identifier sent to the native Jev endpoint. | Exercised alias: `jev-latest`; not a pinned model-version guarantee. |
| `JEV_API_KEY` | Required secret | Credential used by the native Jev adapter. | Operator-managed credential. |

All six values are declared as required reusable-workflow secrets so neither a pull request nor caller inputs can select a destination or model. The endpoint and model values above are exercised aliases, not guarantees of immutable model versions. API key values are user-managed and must be supplied through trusted runner secrets for provider runs. Their values were not disclosed or transferred by this documentation preparation. Only the two `*_API_KEY` values are authentication credentials. Do not place key values in provider JSON, command-line arguments, source control, workflow artifacts, logs, or review inputs. Endpoint and model values must remain controlled by trusted repository configuration.

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

The reusable `pr-analysis.yml` declares all six names as required `workflow_call.secrets`, materializes the two configs in `RUNNER_TEMP`, and passes both files to the existing CLI. It does not fetch a Nous model catalog or use a free-test model config; the historical `review-commits.yml` workflow remains a separate bounded free-model test path. The caller must map each required name from trusted repository secrets. The hosted observations above verify execution of the current reusable workflow path. The natural review was explicitly incomplete; the synthetic cases are protocol and projection observations, not quality evidence.

The publication workflow is disabled and has no write-capable review credential. Provider setup does not enable review publication. Do not add a `pull-requests: write` permission or a writer secret as part of ordinary provider configuration.

## Central SlopSearX pilot caller

The manual `slopsearx-pilot.yml` workflow resolves only a PR number against `magnus919/SlopSearX`, requires an open non-draft PR targeting `main`, then calls the reusable analysis workflow with the six named secrets. The reusable workflow now permits cross-repository invocation only for the exact caller `groktopus/codereview/.github/workflows/slopsearx-pilot.yml@refs/heads/main` targeting `magnus919/SlopSearX`; ordinary same-repository callers retain the equality check. The reusable job re-reads PR state and exact base/head SHAs before fetching source. It fetches PR objects into a bare repository and runs the trusted harness over that source; it does not check out or execute target-repository code. Artifact recovery records caller repository and target repository separately, accepting only same-repository runs or this exact central caller/target pair; authenticated recovery reads Actions data from the caller repository and revalidates the PR through the target repository. Fork-originated PRs remain eligible when the trusted base repository, open/draft state, and exact revisions validate; fork identity is not used to select credentials or a provider endpoint.

The central caller pins both the reusable workflow and `harness_sha` to the same immutable revision in `slopsearx-pilot.yml`. Updating one without the other is invalid. The revised pairing retains central-caller recovery binding and enables one candidate-level Jev assessment within the shared provider-call budget. Jev remains advisory; deterministic code owns disposition.

## Ordinary review budget and recovery

The current ordinary workflow uses `profiles/ordinary-review-limits-v2.json`, a trusted checked-in override that sets a 600,000-byte aggregate context budget and a 96,000-byte maximum input per task. The prior v1 file remains unchanged as historical configuration. Other CLI limits remain unchanged: 12 total provider calls, zero retries, 16,000 output bytes per task, 192,000 total output bytes, and a 300-second deadline. These are finite operational limits, not a pricing or quality guarantee. The direct diagnostic command retains its historical defaults, including a 300,000-byte aggregate and 64,000-byte per-task input cap.

Provider-free installed-CLI preparation against the current runner preserved the full 24,404-byte MCP harness test context alongside existing policy and source context. SlopSearX PR #477 prepared a largest request of 86,834 bytes and 225,950 aggregate bytes; PR #476 prepared a largest request of 86,859 bytes and 226,050 aggregate bytes. These fit the current per-task and aggregate limits as preparation/admission observations. Later hosted execution is recorded above; PR #477 and PR #476 preparation figures do not establish their review outcomes. Actual follow-up, candidate, and summary demand remains subject to the shared limits. Missing checks and context remain explicit. Historical PR #466 preparation under the older runner produced seven primary requests totaling 342,776 bytes, exceeding the old 300,000-byte aggregate limit; it is not evidence about current-runner request sizing.

Resume with the same trusted limits file, `--max-claim-assessments 1`, and decision configuration as the original invocation. The engine binds these settings to the saved review identity and rejects mismatches. Capturing recovery inputs or passing a consistency preview alone does not authorize provider dispatch or publication.

No production credential values were read or tested while preparing this document.
