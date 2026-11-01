# Archived experiment harnesses

This directory is **not** part of the installed `pr-review-harness` package. It
holds the experiment code that CA-2 (issue #248) moved out of
`src/pr_review_harness/` so the wheel exposes exactly one review path.

`experiments/harness/` is an importable package in a source checkout. Every
module imports the production core as `pr_review_harness.*`; no module here
defines a ledger, reserves a provider call, settles a call, or owns a
disposition. Trial runners either invoke the installed CLI as a bounded
subprocess or read the ledger output the core already wrote.

Run an archived harness from the repository root (the repository-level
`tests/conftest.py` does the same for tests):

```sh
PYTHONPATH=src:. python -m pytest -q tests/test_shadow_audit.py
PYTHONPATH=src:. python scripts/run_injection_trials.py --help
```

## Classification

| Module | Classification | Notes |
|---|---|---|
| `selected_model_trial.py` | reusable experiment harness | provider and current-provider trial orchestration (`run_provider_trial`, `run_current_provider_trial`) |
| `injection_trials.py` | reusable experiment harness | prompt-injection suite preparation and `run_trials` |
| `configured_jev_injection_trial.py` | obsolete (superseded) | versioned two-case Jev diagnostic; retained because archived evidence tests and dated experiment records reference it |
| `shadow_audit.py` | reusable experiment harness | model-only shadow audit runner, claim-facing auditor, packet validation; the production source-audit serializer was promoted to `pr_review_harness.source_audit` |
| `actions_canary.py` | reusable experiment harness | read-only GitHub Actions identity canary (`run_actions_canary`); the official artifact-upload bridge stays in `pr_review_harness.actions_runtime` |
| `cross_model.py` | obsolete (superseded) | v1 cross-model comparison contract; superseded by `cross_model_v2` and retained for archived evaluation evidence |
| `cross_model_v2.py` | reusable experiment harness | versioned offline cross-model comparison |
| `cross_model_package.py` | reusable experiment harness | builds evidence packages over frozen artifacts |
| `evaluation.py` | reusable experiment harness | evaluation corpus/prediction validation toolkit |
| `claim_triage.py` | reusable experiment harness | experimental claim-screen boundary |
| `context_selector.py` | reusable experiment harness | context-selection v2 experiment |
| `policy_inventory.py` | reusable experiment harness | profile/policy inventory support for `context_selector` |
| `shadow_preflight.py` | reusable experiment harness | bounded audit dispatch guard |

`actions_runtime.py` did not move: the official Actions artifact-upload bridge is
required by the installed protected-publication runtime. Only its read-only
identity canary moved into `actions_canary.py`.

## Historical evidence

No evidence was deleted. The archived runtime trees that evidence tests rebuild
keep their exact pre-consolidation bytes pinned in
`tests/fixtures/frozen-runtime-7d550b6/`; the relocation changes where a module
lives, not what any historical plan, receipt, or report described.
