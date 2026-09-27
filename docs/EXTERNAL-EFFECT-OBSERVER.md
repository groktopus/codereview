# Linux external effect observer v3

The available observer implementation is v3: it runs an installed CLI under
Linux `strace` and retains a bounded, sanitized view of a fixed syscall scope.
Its identity is `linux-strace-syscall-observer.v3`. It is diagnostic
instrumentation, not a sandbox or containment boundary. The result's
`overall_state` remains `UNKNOWN`, including when scoped tracing completes,
because effects outside the traced syscalls and work bypassing tracing cannot be
ruled out. The separately reviewed selected-model workflow remains pinned to
its earlier observer until a later workflow revision explicitly adopts v3; the
workflow's current run evidence must not be attributed to this implementation.

Version 3 prints raw hexadecimal arguments for `newfstatat` and `wait4`. In the
normalized event contract these already belong to `other_scoped_syscall` and
expose only syscall name, outcome, PID, and trace state; their arguments were
not used for path, endpoint, or lifecycle classification. The change reduces
formatting of high-volume metadata/process calls without removing syscall
coverage. `openat` and other path-classified calls retain decoded paths for
hashed path-scope evidence; socket and process-lifecycle calls keep their
existing classifications. The parser preserves numeric success/error returns
and fails closed when a return value cannot be interpreted; supported
hexadecimal return values are normalized as signed 32- or 64-bit values. The
version change does not raise the 1 MiB trace cap or any other observer limit.

The formatting uses strace's documented `-e raw=syscall_set` option, which
prints the selected syscalls' arguments in hexadecimal ([upstream strace manual](https://github.com/strace/strace/blob/master/doc/strace.1.in)).

## Installed-CLI smoke scope

The Linux observer CI job runs two installed-CLI checks: provider-free
prepare-only and a normal review using the existing recovery harness's loopback
fake provider. The normal review requires one changed unit across the four
requested lenses (`correctness`, `tests`, `security`, and `maintainability`),
four successful provider calls, one attempt per task, complete coverage, and a
`SCOPED_COMPLETE` trace that remains within the unchanged 1 MiB trace cap. Its
fixture allows at most eight calls, zero retries, a 20-second engine deadline,
a 30-second observer deadline, a 128 KB cumulative context ceiling, 32 KB per
task input, and 32 KB aggregate output (8 KB per task).

The fixture disables empty approval authority and accepts only the resulting
typed `COMMENT` or `INCOMPLETE` disposition. A source-level marker would create
a temporary file if target code were executed; the smoke verifies that file is
absent. It reports cost as `UNKNOWN`, candidate adjudication as not exercised
because the fake provider returns no candidates, and Jev as not configured.
This proves the installed CLI's bounded request, coverage, and observation
plumbing on a synthetic path; the fake findings response provides no evidence
of review quality, candidate adjudication, Jev behavior, or performance across
real provider workloads.

The trace byte, line, deadline, CLI-output, and observed process-creation limits
are independent of the event sample size. At most 256 sanitized event examples
are retained in `events`; these are the first parsed events, not a complete
event log. `event_count` counts parsed records. The bounded
`event_aggregates` groups records using only operation, syscall, outcome,
result class, destination class, path scope, and trace state. A
`SCOPED_COMPLETE` result with `event_aggregates_complete: true` means all
parsed records fit into the fixed aggregate buckets; it does not mean all
external effects were observed. `event_sample_truncated` separately reports
whether more records were parsed than retained examples. If the trace or bucket
limits prevent complete aggregation, coverage is `INCOMPLETE`, aggregates are
marked incomplete, and the observer withholds the CLI result from the opted-in
caller.

Unfinished syscall correlation retains at most 256 entries keyed by process ID
and syscall name. Each entry contains only already-sanitized operation,
destination class, and path evidence fields. A resumed syscall inherits that
safe classification and its returned outcome; duplicate, unmatched, or
over-limit correlations fail closed as incomplete. No raw trace fragment is
retained for correlation.

For a nonzero CLI exit, the invocation may include a `cli_error_code` selected
from stable public error categories. The observer keeps the CLI result withheld
and never returns raw stdout or stderr.

File observations describe successful syscalls such as `openat` or `rename`;
they do not establish that bytes were written. Endpoint classes describe only
the destination information visible on the selected socket syscalls. Payload
transfer syscalls are intentionally outside the current scope. Raw trace text,
arguments, environment values, and unredacted file paths are not returned.
