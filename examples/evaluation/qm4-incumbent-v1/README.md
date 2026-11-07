# QM-4 incumbent evidence packet v1

This is an offline, bounded evidence inventory and paired-reporting artifact, not
an incumbent performance benchmark. It covers **all 41 frozen cases**, including
`qm1-slopsearx-pr770`. Actual paired output count: **0**. Five retained live
harness outputs are identity-joined from the accepted QM2/QM3 baseline; **all 41
Droid arms are explicitly missing**. Nothing was executed against Droid or any
model/provider. No target code, publication, issue mutation, commit, or push is
part of generation.

## Inputs and reproduction

From the repository root, using Python 3.11+ and the standard library:

```sh
python3 scripts/compare_incumbent.py > /tmp/qm4-report.json
python3 scripts/compare_incumbent.py --format markdown > /tmp/qm4-report.md
python3 -m pytest -q tests/test_incumbent_comparison.py
```

The versioned [manifest](manifest.json) pins exact input bytes and includes each
complete frozen identity (repository, base/head, snapshot, family/split, profile,
and source-manifest identity). Source manifests are verified against their
canonical content hashes, not merely PR numbers. The script verifies the pilot
subset has identical identities before joining its five predictions, and checks
run IDs against the retained live-run evidence. It does not rerun or embellish
those outputs. The evaluator source and companion source hashes are retained.
The JSON [report](report.json) is the detailed machine-readable record; the
[rendered report](REPORT.md) contains every case and paired denominators.

The input inventory is deliberately limited to versioned repository artifacts at
`6d42bfed60691503c58d2ec8ae58514c4afecb8e`. Missing means **no attributable output
retained in those inspected artifacts**, not “Droid never reviewed this PR.”
Droid execution/access was not used; acquiring new remote baseline outputs was
not authorized in this task. Credentials were not inspected. Model identity and
capture time are null when no output exists, not fabricated aliases or dates.
Historical PR457/PR464 comment evidence does exist, but those cases are outside
this 41-case corpus. It is not transplanted to a superficially similar snapshot.
The QM5 authored `droid` fixtures are explicitly excluded: they are not observed
incumbent execution, whatever their arm name.

## Metric contract and limitations

- Each case distinguishes missing output from a retained run with zero findings.
- Human and synthetic recall are separate. Recall is computed through the
  existing evaluator only for complete labels and completed, fully adjudicated
  runs. An empty eligible-label denominator remains undefined/null. Unresolved
  adjudications are unknown, never assumed misses or matches.
- Paired recall differences use the same case/labels for both arms, with a
  per-case denominator and separate count of comparable cases. Summary means
  are macro means over comparable cases, not pooled prevalence estimates.
  Negative harness-minus-incumbent recall explicitly lists incumbent-better
  cases. No such case is observed in this zero-pair evidence packet; that is not
  evidence that the incumbent is never better.
- Dispositions can be compared descriptively only when both completed outputs
  have known dispositions. Equality/disagreement does not imply correctness or
  quality ordering. Labels and comment counts never imply accuracy.
- The current evaluator finding schema lacks **blocking severity** and the
  retained predictions lack **cost accounting**. False-blocker and cost values,
  numerators, and denominators are therefore null, including for the harness.
  This companion refuses those measures rather than mislabeling all rejected
  material findings as false blockers or substituting token counts for cost.
  A future version must introduce attributable severity/cost evidence and a
  compatible metric contract before making these comparisons; v1 cannot claim
  to measure them merely because some outputs become available.
- Available-pair inventory counts are genuinely zero; unavailable estimand
  denominators and values are null. The difference is intentional.
- No confidence interval, pre-specified equivalence margin, equivalence test,
  parity, improvement, or replacement claim is supplied. Missingness is not
  random; the corpus is risk-enriched, not a prevalence sample; five synthetic
  complete packets with no eligible material defects cannot establish recall.
- PR770 remains included, with incomplete frozen source, incomplete/inconclusive
  synthetic labels, and missing live harness and incumbent outputs.

## Retaining real incumbent evidence later

Create a new manifest version rather than silently rewriting this inventory.
For an actually retained arm, use `status: retained`, and an `output` reference
with repository-local `path` and exact-byte `sha256`. Its JSON envelope must have
`evidence_kind: retained_provider_output`, `captured_at`, `source_url`,
`model_identity` (explicit null if unknown), and a `run` conforming to the
existing predictions schema on the exact frozen identity. `captured_at` must be
a parseable timezone-aware ISO timestamp string; `source_url` must be an HTTPS
URL with a syntactically valid DNS hostname (no credentials or whitespace);
`model_identity` must be a nonempty string or explicit null for unknown. Typed
validation precedes paired counting and rejects malformed envelopes even when
their hashes match. These fields describe retained attributed evidence and are
still attribution assertions requiring maintainer review, not authenticated or
cryptographic proof of provider execution. Authored-fixture evidence kinds fail closed. Findings are
claims, never automatically labels/truth. Optional hash-bound `adjudication`
references supply an existing labels-contract packet on this full corpus with
only that case; it replaces the pilot packet for this comparison so both arms
are adjudicated together. Tests use clearly isolated authored envelopes solely
to probe this protocol and never add them to the versioned measured evidence.

## Live issue wording and exit interpretation

[Issue #245](https://github.com/groktopus/codereview/issues/245) was read live on
2026-11-07, OPEN, updated 2026-11-06T18:34:03Z. Its exit explicitly allows **every
case to have a baseline arm record OR explicit missing**, a per-case paired
report with denominators, and no unqualified equivalence claim. This packet can
therefore fulfill the **documentary/reporting exit** with explicit missing even
without Droid access. The underlying goal of actually measuring incumbent
performance remains unachieved: there are zero measured pairs. Lack of access
is not a reason to leave reporting undone, and completed reporting is not a
reason to assert parity or replacement. Maintainer review decides whether to
close the issue under its wording; this change does not auto-close it.

Version history: `2026-11-07.1` adds the all-case explicit-missing inventory and
provider-free deterministic report; original corpus, pilot, failures and QM5
fixtures remain unchanged. Retention follows the frozen public corpus policy;
no new private payloads or raw provider responses were acquired.
