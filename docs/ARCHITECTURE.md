# Architecture and package surface

This document records the consolidated production surface of `pr-review-harness`
after CA-2 (issue #248, "Consolidate experiment and production surfaces"). It is
the authoritative statement of what the installed package contains, which code
is experiment-only, and how the consolidation was measured.

The machine-readable companion is [`public-surface.json`](public-surface.json),
validated by `tests/test_surface_consolidation.py` together with the
one-orchestrator, wheel-exclusion, and reduction gates.

## One production review path

`pr_review_harness.engine.run_review` is the only review orchestrator in the
installed package. The CLI entry point (`pr-review review`, `pr-review recent`)
calls it. Everything else in the package is either a stage of that path, a
deterministic support module, or the guarded publication effect surface
described below.

| Entry point | Location | Classification |
|---|---|---|
| `run_review` | `pr_review_harness.engine` | production review orchestrator (only one) |
| `run_followup_stage`, `run_followups` | `pr_review_harness.review_stages` | internal stages of `run_review`, not independent entry points |
| `run_protected_publication` | `pr_review_harness.protected_publication_runtime` | guarded publication effect executor (disabled by default; it never dispatches review or provider calls) |
| `main` | `pr_review_harness.cli` | installed console entry point |

The protected publication executor is deliberately retained in the package: the
distributed, hard-disabled publisher template
(`templates/protected-pr-review-publisher.yml`) and
`scripts/protected-publication-action/main.mjs` invoke
`python -m pr_review_harness.protected_publication_runtime`, and
`tests/test_protected_publication_installed.py` verifies it is present in the
installed wheel. It is an effect surface for an already-admitted publication
decision, not a second review path.

Default effects remain read-only. Nothing in this consolidation enables
publication, network dispatch, or provider calls.

## Package modules

Production modules (`src/pr_review_harness/`, shipped in the wheel):

| Group | Modules |
|---|---|
| Review path | `engine`, `review_stages`, `review_state`, `planner`, `budget`, `snapshot`, `evidence`, `checks`, `reconcile`, `report`, `completeness`, `providers`, `contracts`, `contract_registry`, `claim_assessment`, `claim_reconciliation`, `claim_transport`, `private_capture`, `context_targets`, `dependency_context`, `source_audit`, `current_source_capture`, `recovery_inputs`, `github` |
| CLI | `cli`, `__main__`, `__init__` |
| Reusable instrumentation | `external_effect_observer` (out-of-process effect sampling used by trials and the CI self-check; not a review-path dependency) |
| Guarded publication surface | `publisher`, `publication_receipts`, `protected_publication_runtime`, `actions_publication`, `actions_runtime` (official Actions artifact-upload bridge only), `artifact_intake`, `github_app_credentials`, `github_actions_credentials`, `github_app_canary` |

`pr_review_harness.source_audit` is the only part of the historical shadow-audit
harness that the review path needs: it serializes the prediction-blind
source-audit request that the engine records before dispatch. The rest of that
harness (shadow-audit runner, claim-facing auditor, packet validation) is
experiment tooling and lives in `experiments/harness`.

## Single budget and settlement authority

`pr_review_harness.budget.BudgetLedger` is the only ledger. Reservation and
settlement methods exist only there; `engine` and `review_stages` are its only
callers. No experiment module defines a ledger, reserves a call, or settles a
call: experiment harnesses either invoke the installed CLI as a bounded
subprocess or read the ledger output that the core already recorded.

```sh
rg -n "class BudgetLedger|def reserve\(|def settle\(" src
# src/pr_review_harness/budget.py:202:class BudgetLedger:
# src/pr_review_harness/budget.py:235:    def reserve(
# src/pr_review_harness/budget.py:360:    def settle(
rg -n "class BudgetLedger|def reserve\(|def settle\(" experiments
# (no matches)
```

## Experiment harness archive

Experiment code is not installed. It lives in the repository-only
`experiments/harness/` package (`experiments/harness/__init__.py`), which is
excluded from the wheel by setuptools package discovery (`where = ["src"]`) and
carried in the source distribution through `MANIFEST.in`. The modules import the
production core (`pr_review_harness.*`) and are run with the repository root on
`sys.path`. See [experiments/README.md](../experiments/README.md).

| Archived module | Classification | Why it moved |
|---|---|---|
| `selected_model_trial` | reusable experiment harness | contained `run_provider_trial` / `run_current_provider_trial`, a parallel review orchestrator that re-derived ledger, coverage, and settlement observations |
| `injection_trials` | reusable experiment harness | contained `run_trials`; drives installed-CLI runs and classifies prompt-injection cases |
| `configured_jev_injection_trial` | obsolete (superseded by `selected_model_trial`) | versioned two-case Jev diagnostic; retained for archived evidence only, no production importer |
| `shadow_audit` | reusable experiment harness | contained `run_shadow_audit` and the claim-facing auditor; the production source-audit serializer was promoted to `source_audit` |
| `actions_canary` (split from `actions_runtime`) | reusable experiment harness | contained `run_actions_canary`; the official artifact-upload bridge stays in `actions_runtime` |
| `cross_model` | obsolete (superseded by `cross_model_v2`) | v1 advisory comparison contract; retained because archived evidence tests and the evaluation toolkit still read it |
| `cross_model_v2`, `cross_model_package` | reusable experiment harness | offline evaluation comparison and package builders |
| `evaluation` | reusable experiment harness | evaluation corpus/prediction validation toolkit |
| `claim_triage` | reusable experiment harness | experimental claim-screen boundary |
| `context_selector` | reusable experiment harness | context-selection v2 experiment |
| `policy_inventory` | reusable experiment harness | support for `context_selector` |
| `shadow_preflight` | reusable experiment harness | bounded audit dispatch guard |

No obsolete module was deleted. The CA-2 non-goal forbids deleting historical
evidence, and each superseded module is still referenced by archived evidence
tests or dated experiment records. They were relocated, classified as obsolete,
and left runnable from the archive instead of being silently removed.

## Consolidation measurement

Method: Python source line counts under `src/` (the installable package),
measured with `find src -name '*.py' -exec wc -l {} + | tail -1`.

| Revision | `src` Python files | `src` Python lines |
|---|---|---|
| Base `7d550b6` (before) | 48 | 40,686 |
| Consolidated (after) | 37 | 28,507 |
| Delta | −11 | −12,179 (−29.93%) |

The `def run_` count in `src/` fell from 11 to 4; of those four, one is the review
orchestrator, two are internal stages of it, and one is the guarded publication
executor. The installed wheel contains no module from `experiments/`.

## Historical evidence

Relocating an inventory module must not change the archived runtime trees that
evidence tests reconstruct. `tests/frozen_runtime.py` therefore reads each
relocated inventory module from the exact pre-consolidation bytes pinned in
`tests/fixtures/frozen-runtime-7d550b6/` instead of from `src`. The expected
model-tree and synthesis-tree hashes are unchanged, so the PR-170 historical
runtime, the PR-464 preflight evidence, and the prepared selected-model trial
fixtures keep validating against the same bytes they always described.

## Verification

```sh
PYTHONPATH=src python -m pytest -q                 # full suite, including archive tests
ruff check src scripts tests experiments           # lint
rg -n "def run_" src                               # orchestrator inventory
python -m build --wheel --outdir dist && unzip -l dist/*.whl  # wheel inventory: no experiments/
```
