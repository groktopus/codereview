# Model-only shadow run [36517763840](https://github.com/groktopus/codereview/actions/runs/36517763840)

The sanitized receipts show that all ten writer calls completed and parsed as valid specialist reports, with zero returned candidates. The workflow projection marked the writer and upload stages successful, while the shadow audit ended `incomplete` with `no_writer_candidate`; Jev, source auditor, and claim auditor each made zero calls. The run therefore records successful transport and report parsing, followed by an incomplete audit. It provides no semantic-quality or review-accuracy result.

The sanitized preflight records runner revision `c05ab8f`, before merged PRs #126 and #127. In particular, the local-only per-task diagnostics introduced by #127 were not present or uploaded in this run.

| Sanitized artifact | Recorded evidence |
|---|---|
| `writer-receipt.json` | 10 writer calls; 893,359 request bytes; 13,075 response bytes; `WRITER_TRANSPORT_CAPTURED`; `audit_or_jev_dispatched=false`. |
| `writer-outcomes.json` | 10 `valid_specialist_report`; 10 `zero_findings_returned`; 0 parse failures; 0 returned candidates; 0 packet candidates. |
| `shadow-audit-receipt.json` | `terminal_state=incomplete`; `reason=no_writer_candidate`; 0 candidate packets; Jev, source auditor, and claim auditor `not_run`, each with 0 calls. |
| `workflow-status.json` | Job status `success`; writer, shadow-audit, sanitization, and artifact-upload stages projected as `success`. |

These counts distinguish an empty specialist report from parsing or candidate-reconciliation loss. The run's sanitized receipts do not preserve prompt or response content, so they do not explain why the specialists returned no candidates.
