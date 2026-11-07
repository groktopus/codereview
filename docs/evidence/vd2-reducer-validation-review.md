# VD-2 reducer / validation bounded progress

Source: immutable revision `928ec1733b3c3dc699be6a09fb38501a409cae00`, branch `test/vd2-reducer`. No commit, push, publication, production-source edit, environment installation, or temporary project configuration was made.

## Requirement and named scope

[Issue 252](https://github.com/groktopus/codereview/issues/252) remains open. Its exact mutation scope is “reconcile, reducer/validators, and budget arithmetic”; exit requires mutation score >=70% on named modules, CI properties, and parameterized fault matrix with stable reason codes. This work cannot close that scope.

Minimal nominated mutation scope: [`engine._reduce`](../../src/pr_review_harness/engine.py#L1173-L1194), 22 source lines. It consumes already classified findings, coverage, waiver receipts, budget breaches, policy validity, and freshness. It does **not** validate evidence or model confidence. Accepted blocking findings take precedence over incompleteness. Nonempty findings and waivers prevent empty approval.

Important separate validator/controller surfaces inspected, not mutation-qualified:

- [`reconcile`](../../src/pr_review_harness/reconcile.py): location validation and duplicate finding consolidation; consolidation conflict semantics are separate from disposition reduction.
- [`contracts.validate_adjudication`](../../src/pr_review_harness/contracts.py#L475-L561): structural fields, supported-claim evidence requirement, and causal-role evidence shape. Referential/snapshot validity belongs to a later boundary.
- [`engine._validated_v3_causal_roles`](../../src/pr_review_harness/engine.py#L419-L488): source/normalized v3 versions, rubric identity, exactly delivered evidence, record identity, and snapshot binding.
- [`ClaimAssessmentAdapter._valid_choice`](../../src/pr_review_harness/claim_assessment.py#L1037-L1056): native choice shape, finite confidence/probabilities, range, normalization and chosen maximum. Valid confidence does not confer approval authority.
- [`review_stages`](../../src/pr_review_harness/review_stages.py): finding classification around lines 2561–2655, freshness/coverage around 3619–3638, result assembly and advisory execution around 3669–3941. These are not the 22-line reducer and need their own measurement.

## Tests and limits of evidence

New [`test_vd2_reducer`](../../tests/test_vd2_reducer.py) adds **251 collected deterministic cases**; it does not duplicate provider-spawn test modules. Cases include 80 blocker precedence combinations with misleading advisory/report summaries, 120 empty-disposition/replay combinations, waiver receipt channels, neutral optional receipts, 20 finding classification combinations, budget breach alone, finite confidence rejection/valid endpoints, stable invalid-evidence error codes, and five delivered/snapshot-bound causal evidence scenarios.

Every reducer replay compares input before/after; the reducer must be pure and repeatable. This is not a claim of full persisted-ledger replay coverage. Advisory/report fields here are hostile reducer inputs; these tests do not execute an actual synthesis provider or prove the whole synthesis controller. Confidence rejection and evidence validation are direct boundary assertions, not a synthetic implementation copy or a claimed end-to-end fault matrix. No provider/network/effect function is invoked by these cases. No full-module validator closure is claimed.

Focused command: `PYTHONPATH=src pytest -q tests/test_vd2_reducer.py tests/test_vd2_invariants.py tests/test_reconcile.py tests/test_review_stages.py` → **325 passed in 0.80s**.

`ruff check .` → pass. `ruff format --check .` → **339 files already formatted**. First focused formatting check failed; canonical formatter applied, then rechecked successfully. `git diff --exit-code -- src pyproject.toml` → pass (production/config unchanged).

`python3 scripts/check_complexity.py --json` → PASS; threshold 150 physical lines/function, **331 scanned files, 6302 functions, 105 baseline entries, 0 findings**.

## Real mutation not executed

Authoritative setup/status details are retained in [`vd2-mutation-reducer.json`](vd2-mutation-reducer.json). Existing `/tmp/mutvenv` was inspected but rejected: editable project points elsewhere and mutmut entrypoint cannot import its module. Independent tool setup first failed installed uv version vs project pin, then hit a sandbox cache-file denial. It was not bypassed. Existing `/tmp/vd2b-venv` also had no executable mutmut/module despite directory names suggesting an installation.

Function-scope capability is **unverified** because `mutmut run --help` failed before presenting options. No full-engine mutation was launched. There are no generated mutant IDs, no mutant statuses to triage, and no valid score/denominator; killed/survived/no-tests/timeouts are null, not zero. Threshold 70% is **not evaluated**. Retain this setup failure; it is not a successful mutation artifact.

Next authorized step: obtain a usable isolated tool environment through the parent with applicable filesystem authority, inspect real function-filter capability, freeze exact config/command/selection, run `_reduce` scope, retain all generated statuses, and meaningfully triage survivors. Do not remove difficult survivors or infer whole validators from this small function.

## Immutable production SHA-256 inventory

| Surface | SHA-256 |
| --- | --- |
| [`engine`](../../src/pr_review_harness/engine.py) | `dce6addfd9b280886fb302811902c9feb817708ed9615e981dbe7f12cf761ae6` |
| [`reconcile`](../../src/pr_review_harness/reconcile.py) | `cb4713ad3653db9c73bc7e62ef9c30bc7280906a399bcdbc3f2ee8292e20a5f2` |
| [`contracts`](../../src/pr_review_harness/contracts.py) | `5309e8ac082952afdd4baf6b567894cb9794ea5c426eb7c6671bd9ad189c2706` |
| [`claim_assessment`](../../src/pr_review_harness/claim_assessment.py) | `20c8d01c213e704305c597400097064ff5dc0961e029eedeab9740ed021ffa3b` |
| [`review_stages`](../../src/pr_review_harness/review_stages.py) | `be9600dee799f20a3e0a748388cbde8b0c872de71a460b78ff72a24aa371d1ae` |

Candidate test SHA-256: `e759a8250510b0bb848e169c9a56ca5e2bf920415e05793f7f752bcd5cc96e20`.
