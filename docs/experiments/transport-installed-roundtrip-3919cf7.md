# Installed transport round-trip failure: 36349985500

The secretless installed-CLI round-trip run [36349985500](https://github.com/groktopus/codereview/actions/runs/36349985500), using diagnostic source `3919cf760fe2d3f212e1d8b5c52f2f0a34deb877`, failed strict arm task-row validation. Job `108706721164` reported `arm_task_fields_invalid`. The retained job log was 29,913 bytes with SHA-256 `bae211e82507f919bf69dd21b3b4289e181d3a15e73e25ec41cb53b34c77ab42`.

Source inspection established the producer/validator mismatch: the diagnostic's shared task-status projector emits `task_id`, `lens`, `status`, `chunk_count`, and `completed_chunks`; the transport receipt contract accepts exactly `task_id`, `lens`, and `status`. The transport-only projection is being corrected to retain those three fields while leaving shared chunk accounting intact. A regression exercises the real task projector, transport projection, and strict arm validator, including malformed identity/status cases.

The paired PR workflow run `36349987317`, job `108706722603`, also failed; its exact failure code was not independently inspected. The new failed run did not retain the original pair receipt or comparison counts, so pair state, request counts, and comparison results are `NOT_RETAINED` for this attempt. Earlier run `36347277922` had a separate fallback receipt and did not retain its original rejection predicate; its cause is not inferred from this newer mismatch.

These are secretless loopback diagnostics. They do not establish real-provider calls or billing, HTTP/TLS parity, model quality, or a live failure cause. No cap, syscall scope, observer behavior, or trial limit was changed to fit the result.
