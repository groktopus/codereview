# Linux external effect observer v2

The opt-in selected-model trial observer runs the installed CLI under Linux
`strace` and retains a bounded, sanitized view of a fixed syscall scope. Its
identity is `linux-strace-syscall-observer.v2`. It is diagnostic instrumentation,
not a sandbox or containment boundary. The result's `overall_state` remains
`UNKNOWN`, including when scoped tracing completes, because effects outside the
traced syscalls and work bypassing tracing cannot be ruled out.

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

For a nonzero CLI exit, the invocation may include a `cli_error_code` selected
from stable public error categories. The observer keeps the CLI result withheld
and never returns raw stdout or stderr.

File observations describe successful syscalls such as `openat` or `rename`;
they do not establish that bytes were written. Endpoint classes describe only
the destination information visible on the selected socket syscalls. Payload
transfer syscalls are intentionally outside the current scope. Raw trace text,
arguments, environment values, and unredacted file paths are not returned.
