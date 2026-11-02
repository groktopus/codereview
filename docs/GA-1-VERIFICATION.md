# GA-1 verification sample (2026-11-02)

Status: **passed with a documented sole-maintainer exception.**

Branch protection on `main` requires `Review receipt` and `Decision record
links`, with `strict: false`, `enforce_admins: false`, and force-push/deletion
disabled. The administrator bypass is the owner-approved exception for a
one-person repository; every non-admin merge requires both checks.

## Merge sample

Each reviewed head below carried a fenced `review-receipt` naming the reviewed
SHA, a CLEAR verdict, reviewer identity/kind, scope, evidence, and independence.
The receipt SHA equals the merged head recorded by GitHub.

| PR | Topic | Receipt verdict |
|---|---|---|
| #293 | GA-1 receipt protocol | CLEAR |
| #295 | GA-2 decision records | CLEAR |
| #297 | GA-3 ownership/second review | CLEAR |
| #298 | QM-1 frozen corpus | CLEAR |
| #300 | GA-2 decision-link enforcement | CLEAR |
| #302 | QM-2/QM-3 scorecard infrastructure | CLEAR |
| #304 | Synthetic adjudication | CLEAR |
| #305 | 0.1.0 release preparation | CLEAR |
| #306 | Release setuptools fix | CLEAR |
| #308 | RS-2 closeout | CLEAR |

## Blocked attempt

PR #307 (RS-2/GA closeout) was left unmerged after `Review receipt` failed with
`RECEIPT_MISSING` and GitHub reported `mergeStateStatus: BLOCKED`. It was closed
rather than merged. The failure demonstrated that a PR without a receipt cannot
pass the required-check path for a non-admin merge.

## Limits

The owner can still use the administrator bypass. This exception is deliberate,
not an unenforced control. The protocol is not a GitHub review record, and it
does not establish that the reviewer examined the right things.
