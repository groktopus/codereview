# Hosted recovery cancellation and resume rehearsal

This was one secretless, synthetic recovery drill at immutable source `88b5b2a6763738ad1fa493a5e7ed6e3c7b1cf1a1` (`refs/heads/main`). Remote `main` was checked before Run A and again before Run B; it matched that SHA both times. The exact workflow was `.github/workflows/hosted-recovery-rehearsal.yml`, event `workflow_dispatch`. No target SlopSearX source, provider credentials, or live model/provider endpoints were used. Run A's two requests went only to the workflow's loopback fake provider.

## Run A and cancellation gate

- Run A: [36944248422](https://github.com/groktopus/codereview/actions/runs/36944248422), attempt 1; started `2026-10-02T00:05:50Z`, final state `completed/cancelled`.
- While Run A was still `in_progress`, the exact run-scoped readiness artifact was listed and downloaded: artifact `11201112741`, `hosted-recovery-ready-36944248422`, 674 bytes, created `2026-10-02T00:06:18Z`, expires `2026-10-09T00:06:18Z`. ZIP SHA-256: `2914bbd0d657724a7d8fc56302c5b72ccc2a5dc859900f1cf8ff6853b98cb146`. Its sole regular entry was `readiness.json` (834 bytes), SHA-256 `e149cff0a5f90fbc9911d955160fd04c510fae36d9ed9e344d08917b030ba624`.
- The receipt bound run/attempt, repository, workflow path/ref, source SHA, source-module aggregate SHA-256 `0e07542ca1c8d4982e508159bdf371eb34309d84e9897fc96426cb6e8e3806e3`, checkpoint SHA-256 `2f34b0f6d11020e7dc7740f30e784d51a685579d5bc3e6ed6d828aada46ac193` and 8,643-byte size, plus snapshot/request identity. It reported one completed reservation, one uncertain reservation, provider ordinal 2 in flight, two historical fake-provider requests, and zero expected resume requests.
- Only after those checks passed, cancellation was submitted for Run A. The Actions API later reported `completed/cancelled`. Its `cancelled_at` field was null in the returned workflow-run metadata, so this record does not assert a cancellation timestamp.

The final Run A artifact was `11200658578`, `hosted-recovery-36944248422`, 360,785 bytes, created `2026-10-02T00:09:34Z`, expires `2026-10-03T00:09:34Z`. Archive SHA-256: `91ecb4c808a4fe6665fb8987b3ac243bf17c4f706e7ebee045b8fcb79ec8c034`. It contained exactly six root-level regular files (359,979 uncompressed bytes); every file matched the manifest's SHA-256 inventory:

| File | Bytes | SHA-256 |
|---|---:|---|
| `checkpoint.json` | 8,643 | `2f34b0f6d11020e7dc7740f30e784d51a685579d5bc3e6ed6d828aada46ac193` |
| `fixture.bundle` | 517 | `c7521d1697cc2c93579f5bffa90e0ea6cd552de23bbad3d3b2da175f354a2277` |
| `manifest.json` | 5,088 | `3bff1d945357f2da277fb6d7d9be0000dd4b54db0e5b78511b6809230748111c` |
| `pr_review_harness-0.1.0-py3-none-any.whl` | 344,488 | `b5a00dcdbe4dd2f802d1c9e983ed8e596b65f82f8b23043112d9fec7f0a02c29` |
| `provider-ledger.json` | 409 | `fb7d45b0bdc7a2b959e0bd0f88b0f3fe10d6d6f34a82de41ee3bbd02b7c9d206` |
| `readiness.json` | 834 | `e149cff0a5f90fbc9911d955160fd04c510fae36d9ed9e344d08917b030ba624` |

The embedded readiness bytes matched the separately retrieved readiness receipt. The manifest's 40-module source inventory digest matched the readiness aggregate. The checkpoint size/hash matched its readiness receipt. The wheel hash matched the manifest.

## Run B and resume result

- Run B: [36945104586](https://github.com/groktopus/codereview/actions/runs/36945104586), attempt 1; same source SHA, workflow path, `main` ref, and `workflow_dispatch` event; terminal state `completed/success`.
- Run B produced exactly one regular `resume-evidence.json` in artifact `11201424329`, `hosted-recovery-resume-36945104586`, 5,122 bytes, created `2026-10-02T00:16:04Z`, expires `2026-10-03T00:16:04Z`. Archive SHA-256: `2a824143a7b02ffe3abda66484f22aa2a8b5e81673b1315d8e0d1c86f3717341`. The evidence file is 4,968 bytes, SHA-256 `df480df4e8401e2a1fd09da3c149bb6f47d61a4cf57a6293e6b65a45d0edcb2c`.
- Run B's evidence cross-bound both source artifact IDs/names/sizes, the readiness receipt SHA/size, source/run identity, wheel, checkpoint, manifest, ledger, snapshot, request, and module hashes. It reports `INCOMPLETE`, outcomes `FAILED` and `SUCCEEDED`, `interrupted_unknown_present=true`, two historical requests, zero new resume requests, and an empty provider-event list.

The observed contract is that one task remained succeeded, the interrupted task remained uncertain, and resume issued no new fake-provider request. This is one orderly hosted cancellation scenario. It does not establish behavior under hard termination or service failure, live-provider recovery, review quality, injection resistance, publication safety, or general production readiness. The evidence relies on matching artifact hashes and GitHub run metadata; these hashes are not signatures against replacement of both payload and manifest.

Sanitized copies of the two small receipts are next to this note as [readiness receipt](hosted-recovery-2026-10-01-readiness.json) and [resume receipt](hosted-recovery-2026-10-01-resume.json). The downloaded archive files are retained separately in this temporary evidence directory for the bounded audit; do not publish the wheel or checkpoint as standalone evidence.
