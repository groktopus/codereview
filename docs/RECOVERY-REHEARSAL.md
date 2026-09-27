# Installed CLI Recovery Rehearsal

This offline rehearsal checks the public `pr-review review` command's persisted failure and resume behavior against a locally installed package. It uses a temporary two-commit Git fixture, a loopback-only fake OpenAI-compatible server, and a local `gh` shim. The reviewed fixture source is read as evidence; no target code, hooks, tests, or build scripts are executed.

Run it from the source checkout with the CLI from a separate wheel-installed virtual environment:

```sh
python3 scripts/run_recovery_rehearsal.py \
  --cli /path/to/runtime-venv/bin/pr-review \
  --output-dir /tmp/pr-review-recovery-run
```

The runner rejects a nonempty output directory, verifies the CLI shebang/interpreter, installed import path, distribution version, and SHA-256 inventory of installed package modules. It removes inherited provider, GitHub, `PYTHONPATH`, and event-file variables from child environments. Its only credential-shaped value is a fixed synthetic test key sent to the loopback fake provider. Event-mode GitHub requests resolve to a temporary `gh` executable placed first in `PATH`; unexpected fake commands fail locally. The source runner and installed CLI are separate artifacts, and the summary records their paths and installed runtime identity.

The rehearsal covers a synthetic provider HTTP failure, an adapter timeout, interruption after one task checkpoint and during a second reserved call, resume without replaying that uncertain call, profile-drift rejection before dispatch, historical-snapshot labeling, and event-mode `STALE` and `UNKNOWN` freshness. It retains bounded JSON/Markdown run artifacts and a summary under the selected output directory. The summary records fake request counts and typed outcomes; it does not keep prompts, request bodies, credentials, raw exception text, or arbitrary provider response text.

If setup or a scenario fails after an empty output directory has been accepted, the runner writes a typed failure summary with completed scenarios, any installed-runtime identity already established, the active scenario marked `UNKNOWN`, and any safely retained known result files. It retains only regular non-symlink files with the rehearsal's fixed result names, within the same 8 MiB aggregate cap. A nonempty output directory is rejected before writing anything.

Bounds are fixed in the script: an 8-second engine deadline, 0.35-second provider timeout, 12-second per-CLI deadline, 60-second total deadline, two provider-call reservations per run, 256 KiB per captured CLI output stream, 8 MiB total retained result artifacts, and 128 KiB summary output. The scenario work deadline is 57 seconds, reserving the final 3 seconds for bounded local server/process teardown. Retries, context retrieval, follow-up tasks, and publication are disabled. Runs stop with a typed failure if any bound or expected state transition is not demonstrated.

The interrupted case must retain one completed task, settle the in-flight reservation as `INTERRUPTED_UNKNOWN`, and prove resume did not replay it. Provider failure and deadline cases must retain their typed outcomes. The historical case is deliberately labeled `HISTORICAL_SNAPSHOT`; it is not a claim about current GitHub state. The stale and unknown cases come from deterministic local `gh` responses, not GitHub. Passing this rehearsal establishes only that these public CLI recovery paths behaved as expected against the tested installed artifact and local fakes. It does not test remote provider behavior, production credentials, process behavior on every platform, review quality, or deployment readiness.
