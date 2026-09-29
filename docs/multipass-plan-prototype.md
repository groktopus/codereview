# Offline multi-pass plan prototype

`scripts/multipass_plan.py` is an offline contract prototype for splitting an already prepared review manifest across bounded passes. It does not dispatch a model, run target code, query GitHub, or produce review findings or approval. It preserves each prepared specialist request and its obligation IDs, freezes target/profile/provider identity into a plan fingerprint, and accounts for reservations across resumes. Validation compares every assigned task row with the frozen task manifest and checks that task obligations cover the required unit/lens obligations exactly. A reservation with no known result is spent and cannot be retried by this contract.

The sanitized fixture `tests/fixtures/pr305_prepare_only_manifest.json` was derived from a provider-free prepare-only replay of `magnus919/SlopSearX` PR 305, base `00accc58a42eaa470e12831498b572cab2483981`, head `90165dd65be3595006171d7abef34a082c90a71d`. Its metadata records the source artifact digest. The fixture retains request byte counts, hashes, lens/unit bindings, required obligation IDs, and identity hashes; it strips source text, prompts, full evidence, credentials, and provider endpoints.

Under the existing per-pass limits of 12 provider calls, 300,000 serialized input bytes, and 64,000 bytes per request, the 38 mandatory specialist requests (1,945,925 bytes total) pack into seven passes. Two deterministic project-check obligations are retained as once-only non-provider tasks, as are the two external check results bound by the manifest. Two required-context obligations are not admitted by the source manifest and remain pending. Consequently the frozen PR305 aggregate remains `INCOMPLETE`, even after synthetic success results for every specialist request and check. Resolving context in a synthetic test demonstrates only the aggregation contract; it does not change the historical run evidence.

The per-pass caps do not bound total spend. The prototype's plan-level global caps equal the exact mandatory primary task count and byte total, and optional stages are excluded. A future live integration would need an explicit cumulative deadline and monetary ceiling or an explicit cost-unknown decision, plus atomic persistence of the reservation ledger before dispatch. This prototype's fingerprint detects post-freeze plan changes but does not authenticate the origin of a caller-supplied prepared manifest or ledger. `ALL_REQUIRED_RESULTS_RECORDED` means only that supplied synthetic records cover the planned tasks; it does not establish an audit or semantic quality. Disposition always remains `NOT_EVALUATED`, even when a supplied check record says failure, and publication is always disabled.

Run the focused provider-free tests with:

```sh
python3 -m pytest -q tests/test_multipass_plan.py
```
