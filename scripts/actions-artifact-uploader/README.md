# Artifact uploader dependency overrides

The uploader retains the exact `@actions/artifact` 6.2.1 API and Node >=22
requirement (the action runs on Node 24). The following exact overrides repair
the dependency lock without changing upload, retention, or publication behavior:

- `undici` 6.29.1 satisfies the Actions clients' existing `^6.23.0` ranges.
- Only `archiver-utils` receives `glob` 14.0.2, with `minimatch` 11.0.1.
  Its glob integration uses CommonJS `glob.sync(pattern, options)`, which the
  replacement preserves. The uploader archives explicit paths, not patterns.
  `readdir-glob` keeps its separate, unaffected minimatch 5 dependency.

Updating to the registry's `@actions/artifact` 6.3.1 alone does not repair the
pattern dependencies: it still uses archiver 7 and archiver-utils 5, whose
unmodified glob range is `^10.0.0`. Revisit these overrides when the upstream
chain supports patched releases. All replacement transitive engine ranges
accept Node 22 and 24; the lock records exact versions and registry integrity.

Validate with `npm ci --ignore-scripts` and `npm audit --package-lock-only`
from this directory, using an explicitly bounded worktree-local npm cache.
Then run `python3 -m pytest -q tests/test_actions_artifact_uploader.py` from the
repository root. Its installed-dependency smoke checks glob integration, the
real artifact ZIP stream, and fail-closed CLI startup with credentials removed
and outbound sockets denied. That smoke skips when dependencies are absent;
it does not exercise a network upload or establish hosted-service compatibility.
