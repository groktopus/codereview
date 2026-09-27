# Preserved installed recovery rehearsal failure

The installed-wheel CI run [36352270722](https://github.com/groktopus/codereview/actions/runs/36352270722), job `108713155051`, failed in scenario `interruption_and_resume` with `profile_drift_not_rejected`. Its local-fakes-only run summary retained the preceding HTTP-failure and timeout cases and the interrupted checkpoint. The workflow uploaded artifact `pr-review-recovery-36352270722-3.11` (artifact ID `10942537369`).

Retained log: `/private/tmp/codereview-pr65-installed-smoke-failure-108713155051.log`, 27,163 bytes, SHA-256 `7a1dc42d86dd03257b935f543f0ee638bb39ec78a2b2a161ff211752446710da`.

The rehearsal source accepted only a `preflight_rejected` prefix for profile drift and recorded that fixed code. The current CLI uses the typed `resume_state_invalid` preflight reason for invalid resume identity. The failed log records the rehearsal's rejection predicate, but does not retain the profile-drift CLI JSON, so the exact error payload from that attempt is not claimed here. The follow-up keeps strict exit-2 and finite error-code checks, captures the actual accepted code, verifies fake-provider call count did not change, and compares the checkpoint bytes before and after drift rejection.

This was a secretless loopback-fake recovery rehearsal, not a live provider or reviewed-code execution. Preserve it as a failed run; the correction requires a fresh installed-wheel run to establish the updated result.
