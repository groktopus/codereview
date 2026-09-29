# Central pilot admission canary runs — 2026-09-29

This entry records two manual admission rehearsals against the retained PR 477 pilot artifact. It is scoped to the workflow revisions and run receipts below; it does not establish behavior for later revisions or for the automatic `workflow_run` trigger.

| Canary run | Workflow revision | Result | Evidence |
|---|---|---|---|
| [36540490439](https://github.com/groktopus/codereview/actions/runs/36540490439) | `82cbcc7857447a8a4c8765857ca6a682f49db148` (#146) | Failed at recovery-input validation with `recovery_inputs_invalid`; the receipt-upload step was skipped. | The entry point ran from a source checkout without the package import path, so `pr_review_harness.recovery_inputs` could not be imported. The recovery validator mapped that import failure to this error. The retained artifact was valid when the package source path was available. PR #147 fixed startup by adding the checkout's `src/` directory to the script import path; recovery validation stayed strict. |
| [36542089961](https://github.com/groktopus/codereview/actions/runs/36542089961) | `783115d956a38e36793c8cd3f9e99f4b10f34ade` (#147) | Workflow and admission job succeeded; status `CONSISTENCY_VALIDATED`. | The seven-day artifact contains the hash-only receipt below. Its local copy is 1,026 bytes with SHA-256 `b47978a206e1ed16b33457e12611bdffc01ec5b707d7cf2d5958a13f4464c791`. |

The successful run's receipt binds source run `36531683964`, attempt `1`, to target `magnus919/SlopSearX` PR `477`. The exact uploaded receipt content is:

```json
{"artifact_id":11017010102,"artifact_sha256":"282de97907096993a26facb018a68236196038ae3f7666a0d2230734a34fac6a","base_sha256":"746e84691e2c8f6178dfc8611fec7d5732ef626b18bbd664877a9320810ddb69","caller_repository":"groktopus/codereview","caller_workflow_sha256":"2a400e8f59209700b2e03e01fc3db5faa7cd47407c4f536090fbf47bf70dd1f6","head_sha256":"6212d34639aae5cddb101d85384df006f7b8609ec182ae25ee6dfd1057548975","manifest_sha256":"0c451c5d86aafbc21dacf5885d871605cf37f245989c844e7ae3b2aec39f18bf","publication_authorized":false,"pull_request_number":477,"recovery_inputs_sha256":"8369131ddeaf40007f506a0967712785f77af06cdb0962db7ad0d6a3d1c4949d","reusable_workflow_sha256":"9c57d34b0ee5080dbb16d11a1406124447799db6228f261ff7b55a17220146de","schema_version":"central-pilot-candidate-receipt.v1","source_run_attempt":"1","source_run_id":"36531683964","status":"CONSISTENCY_VALIDATED","target_repository":"magnus919/SlopSearX","trigger_mode":"manual_rehearsal","workflow_run_trigger_evidence":"NOT_ESTABLISHED_BY_MANUAL_REHEARSAL"}
```

The hashes cover the selected source artifact archive, base/head identity, manifest, recovery inputs, caller workflow, and reusable workflow. The receipt contains no source request or response bodies. `artifact_id` and `artifact_sha256` identify the selected source artifact and its verified archive digest; they are not the ID or digest of the canary receipt artifact itself.

Both observations are read-only. The successful receipt explicitly records `publication_authorized: false`. Neither run executed target code or published a PR review/comment. The successful run used `workflow_dispatch` as a manual rehearsal; its `workflow_run_trigger_evidence` is `NOT_ESTABLISHED_BY_MANUAL_REHEARSAL`. The workflow also declares a natural `workflow_run` trigger, but these runs do not prove that trigger fires or succeeds naturally. That remains unverified by this ledger.
