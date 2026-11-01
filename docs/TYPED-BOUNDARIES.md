# Typed boundaries (CA-4)

## Design

`review_state.py` defines the stable internal records used at controller boundaries: snapshot, plan, task, attempt, ledger, finding, coverage, and result. They describe validated records; they do not replace runtime validation of JSON, profile/workflow input, provider output, or persisted resume state. Boundary validators remain authoritative and continue to fail closed.

The module also contains strict-checkable call protocols for planner, task stages, reconciliation, and report rendering. Dynamic dispatch/provider code is intentionally not included in the first checking set.

## Static checking scope

`mypy --strict` allowlists exactly two files: `src/pr_review_harness/typed_contracts.pyi` (the contracts) and `src/pr_review_harness/typed_boundary_probe.pyi` (actual stage/planner/reconcile/report callables assigned to protocols). The checker suppresses import-follow diagnostics (`follow_imports = "silent"`) for dependencies; it does not strict-check `engine.py`, `planner.py`, `reconcile.py`, `report.py`, `review_state.py`, `review_stages.py`, or downstream runtime dependencies. No checker errors are ignored within the two allowlisted files. The separate CI negative fixture `typecheck_probe.pyi` assigns a string to `TaskRecord.unit_ids`; CI requires mypy to reject that exact field with the intended TypedDict mismatch.

## Migration policy

New or changed cross-module internal records should use these TypedDicts after existing ingress validation. Use `object` for bounded unknown JSON values rather than exporting unvalidated `Any`. Add checker coverage only for modules whose strict errors can be resolved without suppressing meaningful issues. Any `dict[str, Any]` at external/provider ingress is allowed only with its adjacent runtime validator; do not expand this pattern across internal stage boundaries.

## Remaining risks

- Stage implementations still pass mutable mapping-shaped state internally and carry dynamically populated `RunState` attributes; schemas are not yet wired through all consumers.
- Profile and provider extension points remain runtime-validated and intentionally dynamic.
- The strict set is deliberately small; gradual expansion must add explicit modules and tests rather than broad `ignore_errors`.

## Contract duplication

Runtime annotations use the declarations in `review_state.py`; `typed_contracts.pyi` mirrors them for the strict gate. The two copies are currently duplicated and must be kept in sync. Mypy checks the stub copy, so adding/removing optional TypedDict keys is not caught automatically; a future single-source generation step is required.
