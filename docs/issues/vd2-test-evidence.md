# VD-2 test evidence (development note)

This is a working, generated-by-test note; the authoritative issue remains [VD-2](04-verification-depth.md#vd-2--add-property-mutation-and-fault-injection-testing).

Scope: deterministic generated invariant cases, provider/reducer/budget boundaries, and a synthetic local HTTP fault matrix. Publication/GitHub effect matrices remain owned by SE-4 and are not duplicated here.

## Reproducible property cases

The generated tests in `tests/test_vd2_invariants.py` use fixed `random.Random` seeds (not Hypothesis):

| Property | Seed | Generated examples |
|---|---:|---:|
| No invocation construction after reservation rejection (call cap exhausted) | 25201 | 24 |
| Settlement requires a reserved attempt | 25202 | 100 |
| Successful reservations stay within provider-call/context/output/cost ceilings | 25203 | 800 |
| Reservation and settlement replay idempotence | 25204 | 80 |
| Accepted blocker survives reducer and finding consolidation | 25205 | 100 |
| Stale/unknown/missing/unrecognized freshness or incomplete coverage never approves | 25206 | 20 parameter combinations |

Total generated examples: 1,124 (1,104 explicit generated loops plus 20 parameterized reducer combinations). The families are bounded deterministic exploration, not probabilistic confidence evidence.

## Fault matrix

| Test ID | Injected fault | Expected terminal / reason | Forbidden effects asserted |
|---|---|---|---|
| VD2-PROVIDER-TIMEOUT | Local HTTP timeout | TIMED_OUT / `provider_deadline_exceeded` | No result payload or publication attempt |
| VD2-PROVIDER-4XX | HTTP 429 | FAILED / `http_status_429` | No result payload or publication attempt |
| VD2-PROVIDER-5XX | HTTP 503 | FAILED / `http_status_503` | No result payload or publication attempt |
| VD2-PROVIDER-MALFORMED | Invalid JSON body | FAILED / `malformed_provider_response` | No result payload or publication attempt |
| VD2-PROVIDER-TRUNCATED | Content-Length exceeds transmitted body | FAILED / `malformed_provider_response` | No result payload or publication attempt |
| VD2-PROVIDER-DUPLICATE | Two choices instead of the single accepted response | FAILED / `malformed_provider_response` | No result payload or publication attempt |
| VD2-BUDGET-DUPLICATE-REPLAY | Conflicting replay after failure settlement | Existing FAILED preserved; conflicting replay rejected | No result payload |

Cases are offline local fixtures; they do not qualify any live provider. GitHub and artifact/publication cases are intentionally left to SE-4's matrix.

## Verification

The focused command is `PYTHONPATH=src python3 -m pytest -q tests/test_vd2_invariants.py tests/test_vd2_provider_faults.py tests/test_budget.py tests/test_review_stages.py tests/test_providers.py tests/test_observability.py`. Ruff uses `python3 -m ruff check` over the changed test files. Mutation execution was attempted with `mutmut` via `uvx`. The default run chose Python 3.8 and failed collection because the repository requires `tomllib`. A Python 3.14 run with pytest was then stopped: mutmut generated a 672,331,908-byte whole-project `mutants/` tree (including the large test suite), without reporting selected-source mutants or a mutation score. The tree was removed after confirming no `mutmut`/`uvx` process remained. Mutation score is not established; mutant count, killed count, and survivor triage are unavailable. A bounded source-only mutation configuration or operator-run targeted mutator remains required.
