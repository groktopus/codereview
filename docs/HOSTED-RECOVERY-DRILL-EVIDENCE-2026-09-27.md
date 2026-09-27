# Hosted recovery drill evidence — 2026-09-27

This record supplements [the hosted rehearsal protocol](HOSTED-RECOVERY-REHEARSAL.md) with the observed two-run result. It records a bounded synthetic rehearsal on source commit `d0be88c273c7fff32ed5676d3439b26f2918d680`; it does not establish production readiness, review quality, or adoption.

## Run A: cancellation and retained evidence

[Run A 36313083348](https://github.com/groktopus/codereview/actions/runs/36313083348) (attempt 1) used workflow `368202354`, `.github/workflows/hosted-recovery-rehearsal.yml`, repository `groktopus/codereview`, and `refs/heads/main` at the recorded source SHA. The operator independently retrieved the readiness artifact while the run was active, verified its identity and checkpoint receipt, and then issued the single authorized cancellation. Run A reached terminal `cancelled` at `2026-09-27T10:37:20Z`.

The active readiness artifact was `10928854299`, `hosted-recovery-ready-36313083348`, 674 bytes; its archive SHA-256 is `2aa7ffc903b5d34451910fe5c86fd6e4ccf898d9d16eb572fc4e50ba9a6249c8`. Its 834-byte receipt SHA-256 is `6f3fb11cf2a4c3587167f960fb1b6e8a5a522e4a8ba5bfbcb165af467ae3d1c2`. The final artifact was `10928669510`, `hosted-recovery-36313083348`, 239378 bytes, archive SHA-256 `e0c6677a73eb183096879f4d8899e6d2c6d90cdfb34976ace7fcfbad38eaac19`. It contained six regular files: manifest, checkpoint, fixture bundle, bounded provider ledger, readiness receipt, and the original wheel. The embedded readiness receipt matched the separately retrieved receipt by identity, size, and hash.

The checkpoint SHA-256 is `f04b5df585b30a7323192e558ac3457900e06d7ba73c3ca60b0937ac75dc3d14`; the wheel SHA-256 is `296284e9d662dd83cedc496a023378f3e06e1601c11e9ed3cfd2fa9de13c722b`. The source inventory covered 28 modules; its sorted, compact JSON encoding with one trailing newline has SHA-256 `965f21ed446d010a69d17f99e1e247148e037259fc19bb56f321a441aa1d0ccd`.

## Run B: resume without replay

[Run B 36313501818](https://github.com/groktopus/codereview/actions/runs/36313501818) (attempt 1) completed successfully on the same source SHA and workflow identity. Its sole retrieved resume artifact was `10929692656`, `hosted-recovery-resume-36313501818`, 4028 bytes, archive SHA-256 `ff28169fd37438401696bc3d1b0673865dab081cd9826c812a4496676e80460f`. The archive contained one regular `resume-evidence.json` file (3874 bytes; SHA-256 `52ce28d5d4b0553fc976563530cb25ee440b8aeb3893892488681fd15acab6fb`). The bounded independent verifier matched its source, module inventory, wheel, checkpoint, manifest, prior-ledger and readiness identities to Run A; it also matched the embedded readiness receipt to the separately retrieved Run A readiness artifact.

The typed result was `INCOMPLETE`. It retained the earlier `SUCCEEDED` result and classified the interrupted operation as `INTERRUPTED_UNKNOWN`; the uncertainty flag was true. The retained history contains two requests, while Run B issued zero new resume requests; the artifact records no provider events. These observations demonstrate the tested no-replay behavior for this synthetic case only.

## Limits and preserved history

The two earlier failed attempts remain documented in the protocol above: the first missed its cancellation hold deadline and the second stopped during setup-node resolution. This evidence does not replace or rewrite those outcomes. Run A's successful cancellation demonstrates only the observed orderly cancellation path and retained-artifact chain under this hosted run. It does not guarantee behavior under runner hard kill, service failure, or different environments.

The artifact and receipt hashes provide integrity comparisons for the retrieved bytes; they are not signatures. The rehearsal used synthetic fixtures and a loopback fake provider. It did not access target application code, use provider credentials, publish a review, or measure review quality. No inference about production behavior, calibrated quality, or release approval follows from this drill.
