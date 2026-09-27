# Actions canary cleanup failure provenance

This note records a bounded cleanup defect reproduced locally while investigating the Python 3.14 CI timeout. It does **not** identify the cause of that CI failure.

## Evidence and scope

- The reference checkout was `80c56da50dbdaf25c242a9a301097f89e819901c`.
- Hosted workflow run `36301463207` failed in `tests/test_actions_artifact_uploader.py::test_node_action_passes_runtime_credentials_only_to_bounded_python_child`: the outer test process exceeded its five-second timeout while running `node scripts/actions-artifact-uploader/canary.mjs`. The preserved log is `/private/tmp/codereview-pr22-python314-failure-20260927.log`, SHA-256 `a9e2453e3d27a8dabffe786037ddaa49610058ec1aee527095351d1e3018928c`.
- A local fake-runtime probe used a 500 ms internal deadline and an escaped descendant that kept stdout open. The old wrapper returned fail-closed `UNKNOWN` after 1.738 seconds. Its saved observation is `/private/tmp/canary-cleanup-probe-vj8gjjxm/root-observation.json`; SHA-256 `f16990f76bea8afb2d39ba5d3cc64ecbf8467fb90f85e8b264e4ea9ed46759c1`. The probed old canary and fake runtime hashes are recorded in that JSON.
- The local probe did not contact Actions, GitHub, or a model endpoint. It used a fake `python` executable and no credential values.

The hosted test timeout has no captured child-stage output. The local pipe-close reproduction establishes a cleanup-wait defect, but does not show that the same condition caused the hosted timeout.

## Change and verification

The canary keeps its production deadline at 150,000 ms and its output cap at 64 KiB. After a deadline or output overflow, it sends TERM to its owned process group, waits at most 250 ms, sends KILL to that same group, waits another 250 ms, then destroys only its owned stdout pipe and waits at most 50 ms for close. This avoids an unbounded wait when a descendant outside the owned group retains the pipe. It does not signal an escaped or unrelated process. The test-only callable deadline accepts only positive integers no greater than the production deadline; no environment variable or workflow override was added. The canary still emits `UNKNOWN` on deadline exhaustion, oversized output, and runtime/spawn failure, with publication disabled.

Focused verification on this change:

```text
node --check scripts/actions-artifact-uploader/canary.mjs  PASS
python3 -m pytest -q tests/test_actions_artifact_uploader.py  7 passed
git diff --check  PASS
```

The tests exercise owned-process-group termination, an escaped stdout-holding descendant, oversized output, spawn failure, the bounded test deadline, credential isolation, and missing runtime context. They are local fake-process boundary tests, not evidence about the hosted timeout's root cause or live Actions behavior.
