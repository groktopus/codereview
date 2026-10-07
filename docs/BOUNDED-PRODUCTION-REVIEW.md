# Bounded v16 review capacity candidate

The v16 profile is a separately selected capacity candidate for the v3 source-window splitter. It keeps the v14 review criteria, checks, lenses, and trusted-policy paths, and adds one general security rule for `engines/*.py`. Network clients cross credential, upstream-input, and remote-service trust boundaries, so engine adapters receive security, correctness, and tests review from FOCUSED mode. The profile also bounds source capture, permits HEAD retrieval for implementation and test evidence, and caps native Choice assessments at four candidates. The workflow selector must opt into this exact profile and limits pair; v14 and the fixed-budget trial profiles remain unchanged.

## Capacity contract

`profiles/ordinary-review-limits-v3.json` sets 32 provider-call slots, a 2.5 MB aggregate input ceiling, 96 KB per task, 512 KB aggregate output, and 16 KB per task. The aggregate input ceiling covers provider requests, local context-retrieval bytes, and local-check inputs; all three draw from the same cap. Deadline, retry, concurrency, retrieval, follow-up, and output-token defaults remain unchanged. The explicit 600 KB snapshot cap preserves the prior capture ceiling, while the separately bounded snapshot context remains distinct from this aggregate-input ledger.

On the frozen PR305 source pair (`base 00accc58`, `head 90165dd`), a provider-free prepare pass with merged v3 source and the 600 KB snapshot cap produced 42 required obligations, 15 primary request quotes totaling 1,115,718 bytes, and a largest primary request of 89,903 bytes. This includes four required security obligations overall: two for changed engine modules plus the existing capabilities/configuration obligations. No required source gaps or skipped tasks remained. Two deterministic check tasks add roughly 10.8 KB of local invocation input each and consume no provider calls. Their external check evidence was absent, so their check outcomes remain unknown. The snapshot retained 12 optional gap rows: six truncated base/head context records and six paths not bound by the selector.

The required stage plan reserves 26 task outputs: 15 primary tasks, four semantic-adjudication-provider assessments, four native TypeSafe Choice assessments, one System 1 advisory summary assessment, and two local checks. The final task calls `decision_provider.assess` for an advisory risk/context summary; it is not another primary LLM synthesis. At 16 KB per task, these stages reserve 416 KB. Six additional task slots bring the full reservation to 512 KB. The 2,449,283-byte aggregate is a conditional stage ceiling projection, not an exact future quote or complete-workload guarantee: measured primary bytes (1,115,718) + measured local-check invocation bytes (21,565) + four semantic tasks at 96 KB + four native tasks at 64 KB + one advisory summary task at 96 KB + six optional provider tasks at 96 KB each. This projection excludes local context-retrieval bytes, which also consume the 2.5 MB aggregate-input cap; the observed PR305 run reserved 112,000 bytes for seven retrievals. Any retrievals or actual future quotes reduce the nominal 50,717-byte stage-projection headroom and can exhaust the shared cap; runtime quote estimators must admit actual requests before dispatch and preserve explicit incomplete outcomes when capacity is insufficient. The projection uses 30 provider-call slots and leaves two slots unused, while the output reservation cap is full. Local checks do not charge provider calls but do consume aggregate input and output reservations. Final disposition remains with the deterministic reducer; the advisory assessment does not clear findings or decide disposition.

Native Choice is an advisory classification stage separate from the LLM semantic-adjudication provider. Each native request has a 64 KB intrinsic request bound. The native quote estimator applies the 16 KB caller output ceiling even when the transport's configured response ceiling is 64 KB. A quote above the caller ceiling is rejected before dispatch. The focused test exercises this clamp through the real estimator without making an HTTP request. Candidate-specific input sizes still depend on future primary results and must be admitted by the same estimator at runtime.

The four-candidate native cap is finite. Any additional candidate remains `NOT_RUN` at the cap and must not be described as assessed. If a request exceeds its quote or ledger ceiling, do not truncate its evidence, increase the budget, or retry it; preserve the incomplete status and report the bounded reason. Optional context gaps are not completion requirements.

## Evidence limits

The PR305 sizing demonstrates that the prepared obligations fit these ceilings for this source pair. It does not demonstrate provider outcomes, semantic accuracy, blocker truth, model agreement, or production quality. The external check results were unknown, and dynamic semantic and native requests are unknown until primary outputs exist. The profile status therefore remains `bounded_production_capacity_candidate_not_quality_validated`.

HEAD implementation and test retrieval remains repository evidence. Trusted policy continues to come from the base revision; a request that mislabels a policy path as implementation evidence can retrieve the HEAD file only as untrusted repository evidence. No source text is promoted to trusted policy by a model-proposed evidence kind.

## Focused checks

```sh
PYTHONPATH=src python3 -m pytest -q tests/test_bounded_production_review_profile.py
python3 -m ruff check tests/test_bounded_production_review_profile.py
```

The tests check the v14-to-v16 profile delta, preserved default limits, actual native request quote clamping, the base-policy trust boundary, and small/deep source-window splitting with provider-free request preparation.
