# Production core contract

The review engine treats a run as a bounded, resumable state machine. It does
not execute code from the reviewed repository. Provider, deterministic-check,
context-retrieval, adjudication, and freshness calls run in isolated child
processes; reservations are persisted before dispatch and settled after a
result or safe failure. On POSIX, worker process groups are terminated on
deadline so adapter subprocesses are stopped with their worker. Unsupported
isolation platforms fail closed.

## Budgets and provider calls

`BudgetLedger` is the single accounting authority. Every provider dispatch
reserves a call, serialized input bytes, output bytes, and any explicit
operator-bound monetary cap before it starts. Retrieval reserves retrieval
count and bytes; follow-up tasks have their own finite count. Defaults for
total output, retrievals, and follow-ups are set by the CLI. A deadline is
shared across stages and persisted as an epoch for restart policy while live
elapsed time uses a monotonic clock.

Token-derived prices are estimates, not spending guarantees. Billing remains
`UNKNOWN` unless the provider reports an authoritative billed amount. If a
configured run money limit is present, each call needs an explicit
operator-bound reservation; estimates cannot satisfy that condition. A
reservation or aggregate billing overrun is recorded and forces an
`INCOMPLETE` outcome. No zero-cost assumption is inferred from missing usage.

## Durable resume

The ledger identity binds repository snapshot, profile and question versions,
provider identity, plan, and the core/provider contract hash. A code or contract
change therefore cannot silently resume an incompatible run. Reservations
have stable attempt keys. If a process stops after a reservation but before a
settlement, resume marks the prior call `INTERRUPTED_UNKNOWN` and uses a new
attempt key or stops at the call cap; it never assumes the call was free or
replays an uncertain key. Settled results and dynamic follow-up state are
replayed from the ledger. Identical retrieval reservation replays are
idempotent, including when the retrieval quota is already full.

## Evidence, gaps, and coverage

Candidates are hypotheses until the engine validates their unit, typed
location, changed-file anchor, and evidence references against the immutable
snapshot. BASE line claims must fall in deleted or replaced ranges. File-level
claims require an explicit matching file anchor; a missing line never becomes
a file claim by inference. Duplicates are consolidated by stable identity.
Contradictory assessments become unresolved rather than being decided by
votes.

Context retrieval is deterministic, limited to profile-allowlisted Git
objects, and bounded by retrieval count, byte reservations, and the shared
deadline. Retrieved content is evidence, not completed review. A required
context obligation remains open until a bounded follow-up completes the
assigned lens with a valid static-review coverage note citing that evidence.
Invalid required findings, context, or coverage items are quarantined by hash
and leave required coverage incomplete. Invalid optional report notes are
retained as diagnostics but do not affect findings, blockers, or coverage.

Only `coverage_basis: STATIC_REVIEW` can complete a source-review obligation;
reading tests does not mean running them. Missing coverage remains visible and
blocks a complete disposition. Jev/System One is a bounded semantic advisory
and cannot replace mandatory scopes or choose the final disposition.

## Reports

The report presents four distinct categories: accepted blockers, accepted
non-blocking improvements, evidence-backed strengths, and future guidance.
Each section item has a stable ID and supplied evidence references; validated
source locations retain their HEAD/BASE side and become clickable source
anchors when repository identity is available. Unresolved or rejected claims
stay in diagnostics and are not recommendations. The human-readable view
summarizes coverage and bounds its missing-scope list; the durable result keeps
the full coverage ledger and invocation history.
