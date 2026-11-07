# VD-2 whole reconcile module: measured progress, not VD-2 closure

## Scope and threshold, before results

The requirement measured here is **killed / every generated mutant >=70% for the entire
[reconcile module](../../../src/pr_review_harness/reconcile.py)**. No function, line,
no-tests, timeout, equivalent, or survivor exclusions. This does not qualify the other
VD-2 modules or close the broader VD-2 issue.

Source revision `e35bf37c3ae3a37b2ef7fc8bfbe76e48f039bb11` on
`test/vd2-reconcile-module`; source SHA-256
`cb4713ad3653db9c73bc7e62ef9c30bc7280906a399bcdbc3f2ee8292e20a5f2`.
No production-source/config edits, commit, push, review publication, target-code or
provider execution. Only new local tests and this evidence were added.

## Failure evidence retained first

The [historic probe](../vd2-mutation-reconcile.json) remains unchanged: 257 killed,
73 survived, 338 no-tests / 668 generated. Its 77.88% excluded no-tests; the
whole-module score was **38.47%**, not a threshold pass.

A pristine scratch baseline ran **before any candidate tests executed**, using the
existing [reconcile tests](../../../tests/test_reconcile.py) only. It produced
**248 killed, 70 survived, 338 no-tests, 0 timeouts / 656 =37.80%: FAIL**.
The [baseline native metadata](baseline-native-meta.json), [log](baseline-run.log),
[manifest](baseline-manifest.json), and [complete configuration](baseline-pyproject.toml)
retain that failure. Native clean-test and forced-fail checks both passed first.

Current native generation is **656**, not 668 or a preferred number. The source
hash matches the earlier documented inventory, and both reports name mutmut3.8.1;
the historical report does not retain full generated IDs or sufficient environment
provenance to establish why generation differed. **The cause is unestablished**;
this report does not substitute historical mutants or compare ID suffixes across
that old run. All three fresh runs generated the same 656 IDs.

## New focused behavioral tests

[New module tests](../../../tests/test_vd2_reconcile_module.py) add **89 collected
cases**, not a copy of the existing test file. With the existing 30 cases the fixed
selection is **119 cases**. All functions were read: `_norm`, `stable_candidate_id`,
`validate_location`, and `consolidate_findings`.

- Stable snapshot/candidate identity: frozen independent canonical-JSON digest;
  identity-field sensitivity; Unicode casefold/whitespace normalization; legacy
  top-level anchors; ignored nonidentity metadata; pure deterministic replay.
- Location authorization: task membership, ambiguous/unique path inference,
  explicit unit disambiguation, supplied-unit precedence, HEAD/BASE rename paths,
  inclusive range bounds, invalid integer/bool lines, legacy ranges and locations,
  exact inventory-bound file anchors, deleted BASE file metadata preservation.
- Consolidation invariants: all six input permutations, original-input replay,
  no input mutation, supported blockers retained, conflicting evidence unresolved
  even against two supporting candidates, complete sorted provenance/usage records.

Replay here means repeat evaluation of the **original candidate events**. It does
not claim `consolidate(consolidate(x)) == consolidate(x)`; consolidation output is
not an event ledger. No production-contract decision was made to change that.

## Native full-module runs and denominator

Tool: isolated approved `/tmp/vd2-reducer-tools`, **mutmut3.8.1 / Python3.13.15**.
Its only `.pth` files were virtualenv and coverage initialization; no project
editable installation, new installation or global environment change.

Frozen selection for both measured runs:

```text
tests/test_reconcile.py tests/test_vd2_reconcile_module.py
```

Each run has a separate fresh scratch copied from unchanged source plus tests.
Both scratch configs and input hashes are retained in
[expanded manifest](expanded-manifest.json), [repeat manifest](repeat-manifest.json),
[expanded config](expanded-pyproject.toml), [repeat config](repeat-pyproject.toml).
`mutate_only_covered_lines=false`; no `only_mutate`, `do_not_mutate`, function
filter or no-tests exclusion. Native dependency/test selection is not a denominator
filter. Default native timeout multiplier15 +constant1 and unbounded stack-depth
mapping remain unchanged. Maximum children **4**, runs sequential, no retries to
massage statuses. Runtime budget production code is untouched (zero new headroom).

```bash
PYTHONPATH=src /tmp/vd2-reducer-tools/bin/mutmut run --max-children 4
```

| Run | Generated | Killed | Survived | No-tests | Timeout/other | Killed / all |
|---|---:|---:|---:|---:|---:|---:|
| Existing-test baseline | 656 | 248 | 70 | 338 | 0 | 37.80% FAIL |
| Expanded selection | 656 | 573 | 83 | 0 | 0 | **87.35% PASS** |
| Fresh repeat | 656 | 573 | 83 | 0 | 0 | **87.35% PASS** |

All three commands exited0 (tool completion alone is not a threshold verdict).
Both expanded runs passed their clean-test/forced-fail checks. The complete
656-ID status maps are exactly equal, not just their aggregate counts:
[expanded native metadata](expanded-native-meta.json),
[repeat native metadata](repeat-native-meta.json). Status-map SHA-256, canonical
sorted JSON, is `f8cf65bc98a1fa11615373d00549010d6abbb865d51fa64a6a68d2280d31b386`.
[Machine summary](summary.json) retains the denominator and historical correction.

## Hard survivor triage (all remain in denominator)

All **83 native survivor IDs and full diffs** are retained in
[survivor diffs](survivor-diffs.md). The prefix below is
`pr_review_harness.reconcile.x_`; IDs are scoped to the retained source/config/tool.
Survival is not automatically a defect. Classification here is review, not proof
of equivalence; no ID was removed or status rewritten.

| Function / mutant suffixes | Diff behavior and disposition |
|---|---|
| `_norm__mutmut_11` | Empty fallback `"" -> "XXXX"`. **Meaningful oracle gap**: current falsey-input test compares two identically affected IDs, not the independently frozen empty-text ID. |
| `validate_location__mutmut_3,5` | `candidate.get(location,{})` default becomes None/omitted; immediately type-checked then replaced with `{}`. Likely equivalent for ordinary dict input. |
| `validate_location__mutmut_91–102` | Changes added/deleted/modified alias keys/values, never to `rename`. Only rename equality affects this function. Likely equivalent for these aliases. |
| `validate_location__mutmut_130,132,135–139` | Default kind changed among non-`file` values. Non-file branch is subsequently normalized to `line`. Likely equivalent for ordinary dict input. |
| `validate_location__mutmut_178,179` | Rejects line1 (`<1 -> <=1` or `<2`). **Meaningful boundary gap**: positive tested anchors start at10/20. Add HEAD/BASE inventory range starting1 in future. |
| `validate_location__mutmut_193,200–202` | Forces old path or corrupts nonrename BASE expected path. **Meaningful gap**: renamed BASE positives covered, but nonrename BASE positive line anchors absent. |
| `consolidate_findings__mutmut_6,8` | Location fallback default changed after `isinstance(get(location),dict)` guard; guarded key already exists. Likely equivalent for ordinary dict input. |
| `consolidate_findings__mutmut_51,53–57` | Missing-kind positive-line fallback becomes file/corrupted line. **Meaningful legacy grouping gap**: explicit-kind vs omitted-kind positive-line pairs should merge. |
| `consolidate_findings__mutmut_93` | `typing.cast` first argument becomes None; runtime cast returns second argument unchanged. Runtime equivalent; static typing is a separate gate. |
| `consolidate_findings__mutmut_104,106,109,302,304,307` | Missing-finding-ID sorting fallback changes. Boundary/incomplete-record gap; valid upstream findings normally have IDs, but module tests do not specify missing-ID behavior. No exclusion. |
| `consolidate_findings__mutmut_122,123` | Outcome removed from support shape. **Meaningful conflict gap**: SUPPORTED vs UNCERTAIN with otherwise identical support must remain unresolved. |
| `consolidate_findings__mutmut_136,137` | Corrupts unconditional CONTRADICTED check. **Meaningful safety gap**: single contradicted assessment or all-identical contradicted duplicates; current mixed shapes still take another conflict branch. |
| `consolidate_findings__mutmut_146,147` | Second CONTRADICTED check corrupted; first check already unconditionally makes such cases conflict. Likely equivalent by boolean absorption. |
| `consolidate_findings__mutmut_162,166,167` | Candidate-ID truthiness filter consults wrong key with finding-ID fallback. **Meaningful provenance boundary gap** around empty candidate ID/missing finding ID. |
| `consolidate_findings__mutmut_186,188` | Missing evidence list fallback becomes None, breaking iteration. **Meaningful missing-optional-evidence gap**. |
| `consolidate_findings__mutmut_197,199,202–204` | Assessment record loses candidate fallback to finding ID. **Meaningful provenance oracle gap**: existing candidate fallback test checks union, not per-assessment records. |
| `consolidate_findings__mutmut_236–243` | Task sort key erased/corrupted/default changed. **Meaningful ordering gap**: new permutations correlate task IDs and candidate IDs, so candidate sorting alone passes. Missing task defaults also untested. |
| `consolidate_findings__mutmut_244–257` | Candidate sort key erased/corrupted/default changed. **Meaningful ordering gap**: new permutation inputs have unique tasks, so secondary sort is not decisive; test same-task crossed IDs/missing candidate fallback. |
| `consolidate_findings__mutmut_267,273` | Always emits correlation group for singleton. **Meaningful cardinality gap**: isolated supported finding should have None; existing assertions focus on duplicates. |

This triage intentionally reports real residual gaps rather than relabeling them
equivalent to inflate the score. No production changes were needed for the measured
whole-module threshold, and these residual tests are not falsely claimed delivered.

## Gates and retained failed attempt

- Focused selection: **119 passed**, repeated locally and by native clean runs.
- Relevant deterministic regression: **414 passed** in1.04s, selecting the two
  module files plus reducer, VD-2 invariants, review stages;
  [raw regression log](regression.log). No provider/target executions.
- New test own expanded Ruff rules `E4,E7,E9,F,I,B,SIM,UP,C4,RUF,ASYNC`: PASS;
  canonical formatter check PASS, using pinned Ruff0.17.3.
- First exact expanded gate attempt failed closed because mutation environment has
  Ruff0.17.4, not required0.17.3. [Failure retained](expanded-lint-tool-mismatch.log).
  Root identified existing approved pinned environment; no install/config/baseline
  workaround. Re-run with `/tmp/w-vd4-lint-ratchet/.venv-vd4/bin/python`:
  **PASS341 files /548 debt /0 findings**, [raw report](expanded-lint-pinned.json).
- `/tmp/vd4-types-venv/bin/python scripts/check_typing.py`: **PASS42
  implementations /1073 debt /0 violations**, [raw typing log](typing.log).
- Production source, project config, both accepted debt baselines unchanged;
  `git diff --exit-code -- src pyproject.toml` PASS. No baseline inflation.

[Independent read-only test/oracle review](independent-review.md) is **CLEAR**:
119 focused tests independently passed; both complete 656-ID status maps and
function hashes were independently compared. This does not constitute full VD-2
acceptance. Location validity is inventory-level; downstream file-anchor evidence
authentication is outside this module score.
