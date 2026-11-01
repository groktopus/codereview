# Exception audit (SE-3)

Status: implemented on `feat/se-3-exception-audit` (base `7d550b6`), issue
[#257](https://github.com/groktopus/codereview/issues/257).

This audit covers every broad `except Exception` in the seven
security/effect-relevant modules owned by SE-3. It also replaces the
`pickle.dumps` size proxy in `engine.py` with canonical serialization of the
claim assessor's declared identity/configuration.

## Method

1. Enumerate `except Exception` handlers in `engine.py`, `providers.py`,
   `publisher.py`, `actions_publication.py`, `github.py`,
   `claim_transport.py`, and `review_stages.py`.
2. For each handler, decide whether an exception there is an **expected
   boundary failure** (transport, credential, budget, untrusted payload,
   missing receipt/history) or could be a **programming defect** in
   harness-owned code.
3. Narrow the `except` clause to the expected exception family where that is
   possible without changing the fail-closed outcome. Defect types then
   propagate.
4. Where a broad handler must remain (injected capability with provider-specific
   exceptions), record it below with the exact fail-closed guarantee and add an
   in-code comment. Handlers that can see a defect additionally classify it
   explicitly (`HARNESS_DEFECT`, `SHADOW_ASSESSOR_DEFECT`, `defect: true`) so it
   is never reported as a normal miss.
5. Add the taxonomy in `src/pr_review_harness/errors.py` and regression tests in
   `tests/test_exception_audit.py` and `tests/test_claim_engine.py`.

## Typed error taxonomy

`src/pr_review_harness/errors.py` defines:

| Type | Meaning |
| --- | --- |
| `HarnessError` | Base class for deliberately raised harness errors. |
| `ExpectedBoundaryError` | Expected operational boundary failure; callers fail closed. |
| `BoundaryValueError` / `BoundaryRuntimeError` / `BoundaryTimeoutError` | Boundary errors that keep their historical builtin base (`ValueError`/`RuntimeError`/`TimeoutError`) and therefore their messages/codes and existing `except` behavior. |
| `DefectError` | Harness programming defect surfaced deliberately. |
| `is_defect(exc)` / `defect_name(exc)` / `classify_exception(exc)` | Classify direct exceptions and `IsolatedCallError.remote_type` values (`TypeError`, `AttributeError`, `NameError`, `AssertionError`, `ImportError`, `NotImplementedError`, `UnboundLocalError`). |

Existing trusted-error classes now inherit the boundary taxonomy without
changing their public messages or codes:

- `EnginePreflightError`, `ClaimAssessmentError`, `GitHubReadError`,
  `GitHubPublicationError`, `PublicationRejected` → `BoundaryValueError`
- `ProviderError`, `BudgetExhausted`, `IsolatedCallError`,
  `PublicationAdmissionUnavailable` → `BoundaryRuntimeError`

`IsolatedCallError.remote_type` is still inspected separately: a worker-side
`TypeError` is a defect, while a worker-side `ProviderError` or timeout is an
expected boundary failure.

## Count summary

| Module | Broad handlers before | Narrowed / removed | Retained (documented fail-closed) |
| --- | ---: | ---: | ---: |
| `engine.py` | 1 | 1 | 0 |
| `providers.py` | 5 | 1 | 4 |
| `publisher.py` | 17 | 0 | 17 |
| `actions_publication.py` | 8 | 2 | 6 |
| `github.py` | 1 | 1 | 0 |
| `claim_transport.py` | 1 | 1 | 0 |
| `review_stages.py` | 8 | 6 | 2 |
| **Total** | **41** | **12** | **29** |

Sixty-six further broad handlers exist in modules outside this issue's declared
ownership (for example `cli.py`, `budget.py`, `shadow_audit.py`,
`actions_runtime.py`). They were not edited here and remain residual audit work.

## Retained broad handlers and rationale

All paths below fail closed: the recorded outcome is `UNKNOWN`, `STALE`,
`REJECTED`, `UNAVAILABLE`, or `INCOMPLETE`, never a clean approval or a
confirmed effect. Injected capabilities may raise provider-specific exception
types, so narrowing them would change documented behavior; each handler either
records the boundary outcome or re-raises.

| # | Location | Handler purpose | Why broad is intentional |
| ---: | --- | --- | --- |
| 1 | `providers.py:831` `_call` | Attach bounded `UNKNOWN` HTTP-exchange metadata, then `raise` | Exception is re-raised unchanged; no result is fabricated. Only metadata is added. |
| 2 | `providers.py:1369` `review_with_capture.seal` | Capture sink failure | Injected private-artifact sink; defect types are re-raised first; any other failure becomes `capture_sink_failed`. |
| 3 | `providers.py:1460` `review_with_capture` | Unexpected non-provider failure during capture | Defect types are re-raised first; remaining failures become `provider_call_failed` with a bounded receipt. |
| 4 | `providers.py:1956` `assess` | Attach bounded `UNKNOWN` exchange metadata, then `raise` | Same re-raise contract as `_call`. |
| 5 | `publisher.py:159` `SQLiteEffectStore.claim` | Roll back transaction and re-raise | Never swallows; no effect state is reported by this handler. |
| 6 | `publisher.py:811` `publish_review_stateless` admission | Return `UNKNOWN/publication_admission_unavailable` | Admission evidence is untrusted/incomplete; never forward exception text. |
| 7 | `publisher.py:821` `read_history` | Return `publication_history_unavailable` | History provider failure cannot prove no prior POST. |
| 8 | `publisher.py:908` pre-receipt freshness | Return `UNKNOWN/pre_receipt_head_unavailable` | Freshness cannot be observed; no POST is attempted. |
| 9 | `publisher.py:940` receipt writer | Return `UNKNOWN/receipt_persistence_unknown` | No acknowledgement means the POST precondition is unmet. |
| 10 | `publisher.py:956` post-receipt freshness | Return `UNKNOWN/post_receipt_head_unavailable` | Head cannot be re-verified; no POST is attempted. |
| 11 | `publisher.py:968` `submit_review` | Return `UNKNOWN/submit_response_ambiguous` after one history reconciliation | A failed response may follow a successful remote write; never retry blindly. |
| 12 | `publisher.py:1035` first `fresh_head` | Return `UNKNOWN/fresh_head_unavailable` | Visibility failure; no effect attempted. |
| 13 | `publisher.py:1042` `lookup_effect` | Return `UNKNOWN/existing_effect_state_unavailable` | Prior effect state is unknown; no duplicate attempt. |
| 14 | `publisher.py:1053` second `fresh_head` | Return `UNKNOWN/final_fresh_head_unavailable` | Same, after claim release. |
| 15 | `publisher.py:1065` `claim_effect` | Return `UNKNOWN/effect_claim_unavailable` | Cannot acquire the idempotency claim; no POST. |
| 16 | `publisher.py:1074` third `fresh_head` | Release claim, return `UNKNOWN/final_fresh_head_unavailable` | Same; claim is released rather than left held. |
| 17 | `publisher.py:1090` legacy `submit_review` | Return `UNKNOWN/submit_response_ambiguous` | Ambiguous response; reconcile once, never retry. |
| 18 | `publisher.py:1095` `lookup_effect` after ambiguity | Default to `unknown` | Failed reconciliation cannot confirm an effect. |
| 19 | `publisher.py:1101` `confirm_effect` after ambiguity | Ignore recording failure | The effect was already observed as confirmed; recording failure must not change that observation. |
| 20 | `publisher.py:1108` final `confirm_effect` | Return `UNKNOWN/effect_recording_failed` if lookup is not confirmed | Cannot prove the effect was recorded. |
| 21 | `publisher.py:1112` lookup after final confirm | Default to `unknown` | Same as #18. |
| 22 | `actions_publication.py:672` `_credential` | Raise `GitHubPublicationError("publisher_identity_unavailable")` | Injected credential provider; no detail is safe to forward and failure never implies availability. |
| 23 | `actions_publication.py:1608` `admit` | Raise opaque `PublicationAdmissionUnavailable()` | Never forward third-party exception attributes or text. |
| 24 | `actions_publication.py:1701` `_receipt_history` | Mark history incomplete (`complete=False`) | Missing/expired/tampered artifact evidence cannot prove no prior POST. |
| 25 | `actions_publication.py:1767` `scan` | Return `HistoryScan(UNAVAILABLE, github_history_invalid)` | An unparsable scan is unavailable, never evidence of no effect. |
| 26 | `actions_publication.py:1855` `persist` | Return `UNKNOWN/artifact_persistence_unknown` | Any post-upload failure means the receipt is not acknowledged. |
| 27 | `actions_publication.py:1958` `persist_no_effect` | Return `UNKNOWN/no_effect_persistence_unknown` | A no-effect receipt is never confirmed without verified readback. |
| 28 | `review_stages.py:2186` `run_followups` semantic adjudication | Record `UNCERTAIN` + explicit `HARNESS_DEFECT`/defect fields | Broad clause is needed for provider/budget/transport exceptions; defects are classified, not reported as a normal miss, and cannot support a blocker or clean approval. |
| 29 | `review_stages.py:3484` `build_and_persist_result` advisory | Record `FAILED` advisory with `HARNESS_DEFECT` label when applicable | Advisory runs after the deterministic disposition and cannot change it; defects are still labelled explicitly. |

## Narrowed or removed handlers

| # | Location | Old behavior | New behavior | Regression evidence |
| ---: | --- | --- | --- | --- |
| 1 | `engine.py:642` `_claim_assessor_binding` | `pickle.dumps(assessor)` inside `except Exception` | No `pickle`. Canonical `json` serialization of declared identity + optional `configuration` + type/interface descriptor; catches only `(TypeError, ValueError, RecursionError)` and keeps the legacy `ValueError` messages. | `tests/test_exception_audit.py`; `rg "pickle" src/pr_review_harness/engine.py` is empty. |
| 2 | `providers.py:407` `_http_error_response_observation` | `except Exception` → truncated metadata | Catches `(ProviderError, OSError, ValueError)`; a `TypeError`/`AttributeError` in this diagnostic path now propagates. | provider suite. |
| 3 | `actions_publication.py:508` policy preflight | `except Exception` → `publication_credential_provenance_invalid` | Catches `(ValueError, KeyError)` (the receipt validator's documented rejection family). | publication suite. |
| 4 | `actions_publication.py:1382` historical policy hash | `except Exception` → `historical_policy_invalid` | Catches `(ValueError, KeyError, TypeError, AttributeError)` from shape validation of untrusted historical bytes; other exceptions propagate. | publication suite. |
| 5 | `github.py:290` `GitHubFreshnessCheck.__call__` | `except Exception` → `UNKNOWN` freshness | Catches `(GitHubReadError, OSError)`; a `TypeError` adapter bug now propagates. | `tests/test_exception_audit.py::test_github_freshness_propagates_a_harness_defect`. |
| 6 | `claim_transport.py:264` primary-assessment validation | `except Exception` → `invalid_primary_assessment` | Catches `(ClaimAssessmentError, KeyError)`; defect types propagate. | `tests/test_claim_transport.py`. |
| 7 | `review_stages.py:403` `start_attempt_stage` spawn | `except Exception` → `WORKER_START_FAILED` | Catches `(IsolatedCallError, OSError, ValueError)`. | engine/claim suites. |
| 8 | `review_stages.py:576` `finish_attempt_stage` | `except Exception` → task `FAILED` with error text | Catches `(BudgetExhausted, IsolatedCallError, OSError, ValueError, KeyError)`; defect types propagate. | engine suite. |
| 9 | `review_stages.py:975` resume freshness re-check | `except Exception` → rewrite `UNKNOWN` | Catches `(IsolatedCallError, OSError, TimeoutError, ValueError, KeyError)`. | engine suite. |
| 10 | `review_stages.py:1849` retrieval/follow-up | `except Exception` → `UNRESOLVED` + raw `str(exc)` | Catches `(BudgetExhausted, IsolatedCallError, OSError, ValueError, KeyError)`; defect types propagate. | engine suite. |
| 11 | `review_stages.py:2806` claim-assessment dispatch | `except Exception` → normal `FAILED`/type-name reason | Catches `(BudgetExhausted, ClaimAssessmentError, IsolatedCallError, OSError, ValueError, KeyError)`; local defect types propagate, worker defects are classified as `SHADOW_ASSESSOR_DEFECT` with `defect: true`. | `tests/test_claim_engine.py` defect tests. |
| 12 | `review_stages.py:3229` final freshness | `except Exception` → `UNKNOWN` | Catches `(IsolatedCallError, OSError, TimeoutError, ValueError, KeyError)`; defect types propagate. | engine suite. |

## Programming-error regression tests

- `tests/test_exception_audit.py`
  - engine source contains no `pickle`;
  - canonical assessor binding is deterministic, keeps legacy messages, and
    bounds declared configuration;
  - taxonomy distinguishes boundary failures from defects, including
    `IsolatedCallError.remote_type`;
  - a `TypeError` from the GitHub freshness adapter propagates.
- `tests/test_claim_engine.py`
  - `test_assessor_type_error_is_classified_as_defect_not_a_benign_miss`:
    a `TypeError` inside the spawned assessor is recorded as
    `SHADOW_ASSESSOR_DEFECT` with `defect: true`, not a normal miss, and the
    disposition cannot be `APPROVE`;
  - `test_local_assessor_type_error_propagates_instead_of_becoming_unknown`:
    a `TypeError` raised in controller-owned assessor preparation propagates to
    the caller.

## Verification commands

```bash
rg "pickle" src/pr_review_harness/engine.py
for f in engine providers publisher actions_publication github claim_transport review_stages; do
  grep -c "except Exception" "src/pr_review_harness/$f.py"
done
PYTHONPATH=src python3 -m pytest -q tests/test_exception_audit.py tests/test_claim_engine.py
PYTHONPATH=src python3 -m pytest -q tests/test_engine.py tests/test_providers.py \
  tests/test_publication_receipts.py tests/test_actions_publication.py tests/test_publisher.py
python3 -m ruff check src tests
```
