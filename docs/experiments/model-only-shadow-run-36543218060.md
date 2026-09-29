# Model-only shadow trial run [36543218060](https://github.com/groktopus/codereview/actions/runs/36543218060)

This note records the failed hosted trial at dispatch revision
`69e3e0d0bac675cbc39698f37fa768895bf30353`. It is revision-scoped evidence
for this run, not an assessment of source quality or Jev.

GitHub Actions metadata identifies workflow `Model-only shadow trial
preparation` (`.github/workflows/private-shadow-capture.yml`), run 19, attempt
1, dispatched on `main` at 2026-09-29 08:31:05 UTC. The run completed with
`failure` at 08:32:32 UTC. It was triggered by `workflow_dispatch` and has no
associated pull request in the Actions metadata; “PR-464” identifies the
selected trial case.

The provider-free preparation job completed. The live-writer job made ten
writer calls; all ten returned `zero_findings_returned`, leaving zero
candidates. The provider-free packet selector failed with
`selection_packet_identity_invalid`. The model-only audit, sealed Jev call,
and cross-model packaging were skipped. No publication occurred.

The pinned PR-464 profile has a canonical JSON hash with prefix `4e8f` and a
raw file-byte hash with prefix `66e`. A provider-free reproduction confirms
these are different identity values and that the live packet uses the former;
the packet selector rejected the resulting identity. This bounds the observed
failure to packet identity selection for this run. It does not explain why the
writer calls returned no findings or establish whether their responses were
substantively correct.

GitHub's artifact metadata lists the following three retained artifacts. The
table records metadata only; it does not reproduce artifact contents.

| Sanitized artifact | Size | SHA-256 |
|---|---:|---|
| `private-shadow-preflight-PR-464-36543218060-1` | 1,642 bytes | `85e52f1c97934dfe31274a6b923cafc1546a5fa7d39c40e9bd5adeea273db5ac` |
| `private-shadow-writer-36543218060-1` | 2,819 bytes | `dd48e193e07ed057360a7a5a69c83e3936f800dbc75469b99993a16e7b06e027` |
| `private-shadow-workflow-status-36543218060-1` | 445 bytes | `225913ae0633c0849d8a3573833f9f444f9350920cc30e78e8f3a0663e4fdca0` |

The run establishes that the writer stage returned ten zero-finding outcomes
and that selection stopped before any candidate audit or Jev judgment. Those
outcomes are not independent verification that the source has no issues. The
run provides no source-quality result, Jev accuracy evidence, or calibration
evidence. Raw provider responses and raw workflow logs are not included in
this record.
