# Cross-model v2 package adapter

`cross_model_package.py` turns one private writer case packet and one completed shadow-audit bundle into the existing `review-cross-model-comparison.v2` contract. It is an offline verifier and serializer. It performs no provider calls, repository reads, target execution, GitHub operations, or publication.

Run it with the fixed corpus and private capture roots:

```sh
python3 scripts/package_cross_model_v2.py \
  --corpus examples/evaluation/corpus.json \
  --capture-root /private/path/writer-capture \
  --case-packet /private/path/writer-capture/case-packets/CASE.json \
  --shadow-root /private/path/shadow-audit \
  --output-dir /private/path/new-package \
  --json
```

The output directory must not already exist. It is created with mode `0700`; `comparison-v2.json` and `comparison-report.json` use mode `0600`. The terminal JSON reports safe identifiers, counts, paths, and verifier status only. Keep the source capture, shadow bundle, package, and terminal output private; writer prompts and responses can contain sensitive source material.

The packager verifies that the selected packet is uniquely present in the capture's packet directory, joins the capture manifest and per-call receipts to the writer run ID, task ID, snapshot identity, exact request/response bytes and artifact IDs, recomputes the engine's task-local candidate ID, and requires one matching candidate occurrence. It checks the shadow packet/snapshot copies and hashes, source-audit seal ordering, source-only request projection, Jev request/response question bindings, the exact Jev-derived classification placed in the claim auditor's request, and every shadow request/response artifact hash. An absent, duplicate, stale, or ambiguous binding aborts package creation.

The source-only auditor receives only case identity, task, and source evidence; it is never given the writer candidate or Jev assessment. Checks use structured request fields and exact packet equality, not keyword scans over untrusted excerpts. The Jev response currently has no typed relation object. Consequently the package retains its verified Jev run and records but has zero `writer_jev` assertions; it does not infer or synthesize a Jev judgment. Typed relation objects returned by the claim-facing auditor may be included as byte-verified `jev_claim_auditor` assertions. Those assertions establish only that a structured relation was present in the exact response. The v2 report leaves accuracy, correctness, ground truth, and calibration null; no human labels or model consensus are treated as truth.

The adapter fails closed if its input does not satisfy these joins. A passing package means the recorded identities and bytes verified under this adapter and the v2 verifier. It does not establish whether a claim or relation is semantically correct, nor does it establish runtime behavior outside the captured request/response artifacts.
