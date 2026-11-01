# Profile and limits archive

**Status:** immutable evidence index. **Authority:** [`docs/CONTRACT-REGISTRY.md`](../docs/CONTRACT-REGISTRY.md) and
[`src/pr_review_harness/contract_registry.json`](../src/pr_review_harness/contract_registry.json).

Profile and limits files in this directory are trusted, digest-bound inputs. Several are
retained only because experiment manifests, historical reviews, and dated evidence bind
their SHA-256. **Do not edit an archived or deprecated file to add a note.** Any byte
change invalidates retained evidence. Status labels live in the registry and in this
index instead.

| File | Registry status | Replacement | SHA-256 (unchanged) |
|---|---|---|---|
| `codereview-native-v1-candidate.json` | supported | — | `32d4b63ac84c51eb5919d5f467060d80036f2fa535a3dde354963ecaaaa0c712` |
| `ordinary-review-limits-v3.json` | supported | — | `ec191dcde1672b4f86aac24ee6412752cd9a08871d1aba1b332d11341b6fd2a6` |
| `slopsearx-v14-jev-reconciliation-candidate.json` | deprecated | v16 | `5e83bc43c615f717df0d3d29722de08dd5990c84c8e69d1705c94f3918d49692` |
| `slopsearx-v16-bounded-production-candidate.json` | deprecated | v17 | `699f93fd7bc78d310de2455cad7402a1c3c8cf5ad61c3d4cbb77bb38da1189ed` |
| `slopsearx-v17-context-target-manifest-candidate.json` | deprecated (terminal) | owner retires target | `28725e806a87812386ff67f5c6e63320cc9f3f2b9c1a79c6942c7cf1be004dac` |
| `slopsearx.json` (v8 static-review-boundaries) | deprecated | v14 | unchanged since its recorded evidence |
| `ordinary-review-limits-v2.json` | deprecated | v3 | `39abcf19666c9f322364961577f08f8cff8a3c539e68d894693b6cb0fb5a75e9` |
| `slopsearx-v13-static-assessment-candidate.json` | archived | v14 | `f1a566359a7a5a9af317159dcc962e8b0223e90513516cc25a4f785200ee3156` |
| `slopsearx-v12-dependency-context-candidate.json` | archived | v13 | `e2b1d9bbdafd6d054462b9abac48ce88fdc71400abcb7655902fcf3677c4d446` |
| `slopsearx-v11-related-implementation-context-candidate.json` | archived | v12 | `5afcbf3cf5af235a97b59487303c28cb5c5f0942dc51cccc1ff84178617853d3` |
| `slopsearx-v10-bounded-head-context-trial.json` | archived | v11 | `c2fefca40483bed31207f88fc1ae21f8c058098a207aca9ca987a54ff7abb34b` |
| `slopsearx-v9-context-candidate.json` | archived | v10 | `1ca31f71254640fec7cd60c491bcd3b6ea1e00c8d0e5d76e815f763a045ae0c9` |
| `ordinary-review-limits-v1.json` | archived | v2 | `fb1856f9bda4ad04f13b464348c2b0996a24c690e6b142fdebf2b88bba3d23eb` |

`profiles/generic.json` is an operator template (`review-profile-template`,
`generic-production-v2`), not a review-contract profile, and is supported as a template.
`profiles/targets.json` is the digest-pinned target map (`target-profile-bindings.v1`).

## Archived provenance

Archived profiles remain loadable by the historical experiment scripts that produced
their evidence, but they are not selectable by `scripts/resolve_review_contract.py`.
The provenance tests in `tests/test_contract_registry.py` re-hash every archived file and
compare it with the registry and with the retained evidence manifests.
