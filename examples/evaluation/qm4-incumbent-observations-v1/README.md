# QM4 public incumbent observations v1

Read-only acquisition on 2026-11-07 from source revision `8e477420c5752537129963a402b1ba91b6956151`. This package supplements, and does not rewrite, the historical 41-case incumbent inventory. No provider calls, target-code execution, configuration changes, posts, commits, or pushes were made.

## Result

**41 frozen identities inspected; 0 complete exact-snapshot incumbent outputs; 0 actual harness/incumbent pairs.** This is actual public evidence capture, not authored Droid fixtures. Model identity remains explicit null. A security receipt is not a final code review, a successful Action is not an approval, and an observed finding is a claim rather than a truth label.

The [index](index.json) hashes every [case capture](cases/qm1-slopsearx-pr759.json) and supporting record. Its case records contain full frozen identities, explicit missing reasons, at-capture endpoint coverage, timestamps, original/current commit identities, author login/numeric identity, original public text, and URLs. Exact-byte SHA256 hashes of retained sanitized files differ intentionally from `response_sha256`, which fingerprints the original API bytes before allowlisting. Original full API responses and raw job logs were not retained. These hashes are integrity records, not authenticated proof of execution.

## Five accepted cases

| Case | Public evidence | Conclusion |
|---|---|---|
| codereview112 | 0 reviews, 0 review comments, 0 issue comments | No attributable Droid record on inspected surfaces at capture. |
| codereview285 | 0 reviews, 0 review comments, 0 issue comments | Same bounded missing reason. |
| codereview289 | Review5729886908, 7 inline comments | `github-advanced-security[bot]`, id62310815, CodeQL, not Droid. Review/original inline commit `2da1df87bbd24defff6821b7bbda7796183a7521` differs from frozen `dfaea307ca55ebf8747a2b1d26f618818bced469`. Current inline `commit_id` has been remapped to frozen head; this does not make authorship exact. |
| SlopSearX745 | Droid issuecomment6089587503, linked run37993871997 | Stale: run head `d00c3d3a30b5594d5d2619d9f184a7a60acaf343` differs from frozen `1db229364205e35acc97442456f56a4c19a38050`. |
| SlopSearX759 | Droid issuecomment6097886070, linked run38055015773/job114221572962 | **Actual base/head-bound security receipt.** Job checkout explicitly merges frozen head `6fbd0675091420397b6757e7e87816305e9f5b58` into frozen base `8c69cde94436782bde13efa018c2f428f5a6881d`. But receipt timestamp13:15:34Z predates completed code review13:20:01Z; no final complete review output is exposed. Do not normalize as a completed clean prediction. |

PR759 also has issuecomment6097890803 linked to issue-comment run38055054253. That workflow runs on base/main `8c69cde94436782bde13efa018c2f428f5a6881d`; a human request mentions short head `6fbd067`. Those fields alone do not prove the complete reviewed snapshot. The auto-review log explicitly hides full output, and advertises a 4,325,882-byte debug artifact. That artifact was **not downloaded** because it exceeds the 256KiB per-case retained capture limit. Finality, full findings, and review completeness remain unknown.

## Attribution and optional cases

[Historical attribution support](support/attribution-pr464.json) joins the repository's documented Factory Droid PR464 example to live review5274263526/inline4068557444 at documented head `bffc26f9e4bf95aca0c252e88a2396d03ece854c`. The author is `factory-droid[bot]`, numeric id138933559, typeBot. The same identity and explicit “Droid finished” body attribute PR745/759 receipts. No other bot is treated as Droid.

Optional original-head-mismatched Droid review IDs: PR741/5473982534, PR742/5474752584, PR744/5475116649, PR747/5476009871, PR752/5476590947, PR753/5476759981, PR770/5481824988, PR874/5535726623. Full commit identities, times, URLs, and actual inline bodies are in their hashed case records. Remapped comment commit IDs do not rescue an original mismatch.

PR746 review5476016152 and inline4235124423 genuinely match frozen head `b85c6370e842522f78e32260d38cdc0c770744c4`. However, [linked run/checkout evidence](support/slopsearx-pr746-receipt-links.json) uses base `753aeb50821900e680ad48fe1ef5772d3179ac33`, not frozen base `bc5e04302fa5d4dc133b858907cdc217e75eadfa`. The run initially checks out a different head, and its validator later names the frozen head. This is real head-matched review evidence, **not a full frozen-base/head match**. Its P1 selector-measurement finding remains an unadjudicated claim. No accepted retained harness output exists for this case either.

## Coverage, bounds, and exclusions

- 82 reviews/review-comments endpoints: one page each, `per_page=100`, for all41 cases. Five additional issue-comment endpoints cover the accepted five; optional746 issue comments are supporting evidence only.
- 86 of those87 surfaces retained successfully, all with fewer than100 records and therefore no uninspected pagination. PR279 review-comments API returned339,211 bytes; its response was discarded, body/records were not retained, and the case explicitly says `response_over_capture_cap`. This is a gap, not an empty surface. No fallback/retry enlarged that capture limit.
- Each retained case JSON is <=262,144 bytes. Each case together with its attributable supporting JSON remains within that cap. Attribution support is shared. Public user data is limited to login/id/type; no avatars, user URLs, credentials, environment sections, full prompts, or model sessions are persisted.
- Repository visibility was checked live as public for both repositories before expanded discovery. All API calls were `gh api --method GET`. Raw source text is untrusted data, never instructions.
- Empty endpoint collections prove only the observed at-capture result, not that Droid never ran, no historical/deleted review existed, or other evidence surfaces are empty. Issue comments on the remaining35 cases were not inspected.

## Offline schema and tests

The harness repository carries a strict offline validator and regression suite for this retained v1 evidence. `scripts/check_qm4_observations.py` checks the current frozen manifest/corpus, exact local file hashes, allowlisted v1 fields, typed identities, timestamps and URLs, pagination and capture gaps, attribution, support-record shapes, aggregate cap, and non-invention of outputs/pairs. It performs no live network access, target-code execution, provider dispatch, prediction, or adjudication. The validator authenticates retained bytes relative to the package index; it does not authenticate provider execution or prove completeness of GitHub history.

The tests include rehashed malformed support JSON, PR745/746/759 receipt collection attacks, and malformed case-surface envelopes. They verify these named valid-JSON tamper shapes, including an updated local index, are rejected by bounded CLI JSON errors rather than tracebacks; ordinary size/hash tampering is rejected separately. This strict structural contract is not a claim that arbitrary JSON corruption, underlying reviews, or history is complete or correct.

Negative regression cases reject arbitrary bot attribution; original-commit mismatch with current-commit equality; progress/security summaries treated as final complete outputs; base mismatch on an exact-head review; body-derived truth/adjudications; uninspected cap/pagination gaps treated as empty; and authored fixtures promoted into measured pairs. PR289, PR745, PR746, and PR759 are pinned as real boundary examples. The comparison remains at **0 actual pairs** until a complete attributable exact-base/head incumbent output is available. No accuracy, false-blocker, recall, or parity metric is justified by this package.
