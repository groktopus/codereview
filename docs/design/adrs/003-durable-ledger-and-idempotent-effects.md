# ADR-003: Persist run evidence and make recovery and effects idempotent

- Status: Proposed; acceptance not recorded
- Scope: run identity, ledger, checkpoint/resume, duplicate delivery, and optional publication
- Decision authority: unresolved; architecture and product owners must accept storage/retention scope
- Primary contact: implementation owner to be assigned
- Evidence: architecture scenarios; research memo requirement for a ledger keyed by base/head; CONTRACTS.md

## Context

A review can be interrupted after some parallel tasks finish, receive duplicate delivery, or observe a changed head. A later optional publication can time out after GitHub has accepted the effect. In-memory state or blind retries can lose findings or create duplicate reviews. The pilot is read-only and its storage location/retention are not yet selected.

## Decision

Propose a durable append-only per-run ledger keyed by `run_id`, with immutable snapshot hashes, versioned task IDs, budget reservations, attempt results, coverage, reconciliation, reducer output, and report hashes. Resume uses the same run and idempotency keys only when snapshot, profile, and contract identities still match. Conflicting duplicate outputs are quarantined, not last-write-wins. A future publisher queries by a stable effect key before retrying and verifies the current head.

## Considered options

- Durable ledger plus resumable orchestration: preserves partial work and makes recovery auditable; adds storage and retention decisions.
- Ephemeral process state: simplest pilot implementation; a crash loses completed work and makes duplicate handling unclear.
- Fully transactional distributed database and queue from day one: offers broader multi-worker coordination; premature without workload or ownership evidence and adds operational coupling.

## Consequences

The ledger is authoritative for run state; reports are derived views. No credential is persisted. Corrupt or mismatched state fails closed as INCOMPLETE. Storage durability, retention, deletion, and privacy controls are open product/implementation questions. Publication remains disabled in the initial pilot.

## Confirmation plan

Exercise process restart at each committed state, duplicate event/task delivery, conflicting duplicate result, interrupted artifact write, ambiguous publisher timeout, and changed-head rejection. Verify exactly-once logical effects through idempotency/reconciliation rather than assuming exactly-once delivery. No such runtime evidence exists yet.
