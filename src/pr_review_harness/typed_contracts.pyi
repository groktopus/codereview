"""Type-only contracts for validated internal review records.

These declarations do not validate JSON/provider/workflow input.
"""

from __future__ import annotations

from typing import Any, Protocol, Required, TypedDict

# Stable typed boundary records; validators at external edges remain authoritative.

class SnapshotEvidence(TypedDict, total=False):
    evidence_id: str
    source_kind: str
    trust: str
    content: str
    content_hash: str
    snapshot_id: str
    path: str
    revision: str
    status: str
    conclusion: str
    line_start: int
    line_end: int
    source_revision: str
    content_truncated: bool
    source_side: str
    source_object_id: str | None
    source_object_format: str | None
    source_object_size_bytes: int | None
    source_url: str | None
    manifest_sha256: str
    lock_object_id: str | None
    lock_sha256: str | None
    dependency_binding_id: str
    dependency_lenses: list[str]
    dependency_unit_ids: list[str]
    changed_line_ranges: list[list[int]]
    head_object_id: str | None
    head_relation: str

class SnapshotUnit(TypedDict, total=False):
    unit_id: str
    path: str
    old_path: str | None
    kind: str
    change: str
    diff: str
    change_type: str
    changed_lines: list[list[int]]
    old_line_ranges: list[list[int]]
    evidence_ids: list[str]
    review_context_evidence_ids: list[str]
    diff_hash: str
    file_level_location: dict[str, object]

class SnapshotRecord(TypedDict, total=False):
    snapshot_id: str
    snapshot_hash: str
    repository: str | None
    repository_url: str | None
    pull_request_number: int | None
    head_sha: str
    base_sha: str
    change_base_sha: str
    comparison_mode: str
    freshness_basis: str
    profile_version: str
    project_profile_version: str
    event_id: str
    external_check_evidence_hash: str
    inventory: list[SnapshotUnit]
    evidence: dict[str, SnapshotEvidence]
    trusted_context_refs: list[str | dict[str, str]]
    gaps: list[dict[str, object]]
    external_check_results: dict[str, dict[str, object]]
    profile_hash: str

class TaskRecord(TypedDict, total=False):
    task_id: Required[str]
    scope_id: str
    obligation_id: str
    task_kind: str
    lens: str
    unit_ids: list[str]
    scope_unit_ids: list[str]
    evidence_ids: list[str]
    required: bool
    check_binding_id: str
    check_id: str
    question_version: str
    parent_task_id: str
    parent_obligation_ids: list[str]
    request_input_contract: str
    unit_evidence_bindings: list[dict[str, object]]
    context_followup: dict[str, object]
    context_target_manifest: dict[str, object]
    review_criteria: str
    project_rules: list[str]
    base_context_ids: list[str]
    required_context_ids: list[str]
    obligation_ids: list[str]
    _group: tuple[str, ...]
    _context_group: tuple[str, ...] | None

class CoverageRow(TypedDict, total=False):
    coverage_id: str
    run_id: str
    snapshot_id: str
    obligation_id: str
    obligation_kind: str
    required: bool
    scope_unit_ids: list[str]
    lens: str
    state: str
    reason_code: str
    waived_from_state: str
    waived_from_reason_code: str
    waiver: dict[str, object]
    context_gap_ids: list[str]
    task_ids: list[str]
    evidence_refs: list[str]
    updated_at: str
    closure_diagnostics: dict[str, object]

class PlanRecord(TypedDict, total=False):
    plan_version: str
    snapshot_id: str | None
    profile_version: str | None
    requested_mode: str
    mode: str
    risk_floor: str
    routing_reasons: list[str]
    policy_valid: bool
    risk_by_unit: dict[str, list[str]]
    coverage_obligations: list[dict[str, object]]
    tasks: list[TaskRecord]
    not_applicable: list[dict[str, object]]

class StageOutcome(TypedDict, total=False):
    task_id: str
    task_kind: str
    status: str
    attempts: int
    input_hash: str
    output_hash: str
    error_code: str
    error_summary: str
    lens: str
    unit_ids: list[str]
    input_evidence_ids: list[str]
    quarantined_items: list[dict[str, object]]
    source_contract_version: str
    context_omissions: list[str]
    required_context_omissions: list[str]
    provider_error_meta: dict[str, object]
    request_input_contract: str
    unit_evidence_bindings: list[dict[str, object]]
    context_followup: dict[str, object]
    context_target_manifest: dict[str, object]
    payload: dict[str, object]
    usage: dict[str, object]
    provenance: dict[str, object]
    started_at: str
    finished_at: str

class PreparedAttempt(TypedDict, total=False):
    task: TaskRecord
    task_id: str
    kind: str
    is_check: bool
    target: object
    reservation_key: str
    reservation: dict[str, object]
    invocation: object
    evidence: list[SnapshotEvidence]
    attempt_index: int
    capture_spec: dict[str, object] | None
    started_at: str
    started_monotonic: float
    status: str
    error_code: str
    error_summary: str
    attempts: int
    input_hash: str

class AttemptRecord(TypedDict, total=False):
    attempt_id: str
    task_id: str
    attempt_index: int
    status: str
    started_at: str
    finished_at: str | None
    reservation_key: str
    input_hash: str
    output_hash: str | None
    error_code: str | None

class LedgerEntry(TypedDict, total=False):
    identity: dict[str, object]
    reservations: dict[str, dict[str, object]]
    call_reservations: int
    attempts: list[AttemptRecord]
    outputs: dict[str, dict[str, object]]
    task_results: dict[str, dict[str, object]]
    planned_task_inputs: dict[str, dict[str, object]]
    planned_tasks: list[TaskRecord]
    dynamic_tasks: list[TaskRecord]
    dynamic_obligations: list[dict[str, object]]
    candidate_records: list[dict[str, object]]
    claim_assessments: dict[str, dict[str, object]]
    coverage: list[CoverageRow]
    findings: list[FindingRecord]
    context_gaps: list[dict[str, object]]
    retrieved_context: dict[str, dict[str, object]]
    reconciled_tasks: dict[str, dict[str, object]]
    invocations: list[dict[str, object]]
    events: list[dict[str, object]]
    budget: dict[str, object]
    request_hash: str
    run_started_at_epoch: float
    created_at: str
    deadline_epoch: float
    ledger_version: str
    adjudications: dict[str, dict[str, object]]

class FindingRecord(TypedDict, total=False):
    finding_id: str
    candidate_id: str
    snapshot_id: str
    task_id: str
    unit_id: str
    path: str
    line: int | None
    location: dict[str, object]
    title: str
    observation: str
    consequence: str
    rule_or_contract: str
    severity: str
    introducedness: str
    evidence_refs: list[str]
    semantic_assessment: dict[str, object]
    candidate_ids: list[str]
    task_ids: list[str]
    assessment_records: list[dict[str, object]]
    duplicate_count: int
    correlation_group_id: str | None
    status: str
    blocking_class: str
    blocking_rationale: str
    reconciliation_conflict: bool
    semantic_usage: dict[str, object]
    semantic_provenance: dict[str, object]

class ReviewResult(TypedDict, total=False):
    contract_version: str
    run_id: str
    run_elapsed_ms: float
    snapshot_id: str | None
    snapshot: SnapshotRecord
    plan: PlanRecord
    findings: list[FindingRecord]
    coverage_ledger: list[CoverageRow]
    ledger: LedgerEntry
    claim_assessments: list[dict[str, object]]
    advisory_assessment: dict[str, object]
    run_summary: dict[str, object]
    completeness_summary: dict[str, object]
    waiver_receipt: dict[str, object] | None
    waivers_applied: list[dict[str, object]]
    waivers_not_applied: list[dict[str, object]]
    request_hash: str
    result_hash: str
    disposition: str
    report_sections: dict[str, object]
    repository_url: str | None
    repository: str | None
    pull_request_number: int | None
    base_sha: str | None
    head_sha: str | None
    change_base_sha: str
    comparison_mode: str
    effective_contracts: dict[str, object]
    project_profile_version: str | None
    coverage_state: str
    freshness: str
    freshness_details: dict[str, object]
    merge_eligibility: str
    created_at: str
    completed_at: str
    provider_identity: dict[str, object]
    budget: dict[str, object]
    task_results: dict[str, dict[str, object]]
    policy_valid: bool
    allow_empty_approve: bool
    context_gaps: list[dict[str, object]]
    snapshot_gaps: list[dict[str, object]]
    routing_reasons: list[str]
    not_applicable: list[dict[str, object]]
    evidence_index: dict[str, dict[str, object]]
    context_omissions: list[dict[str, str]]

class PlannerBoundary(Protocol):
    def __call__(self, snapshot: SnapshotRecord, profile: dict[str, Any], mode: str = "AUTO") -> PlanRecord: ...

class StageBoundary(Protocol):
    """A controller stage consumes run state and returns no decision."""

    def __call__(self, state: Any, /) -> None: ...

class TaskStageBoundary(Protocol):
    """Boundary signature for a task-oriented stage after ingress validation."""

    def __call__(self, state: Any, task: TaskRecord, /) -> StageOutcome: ...

class AttemptStartBoundary(Protocol):
    def __call__(self, state: Any, task: TaskRecord, attempt_index: int, /) -> PreparedAttempt: ...

class AttemptFinishBoundary(Protocol):
    def __call__(self, state: Any, prepared: PreparedAttempt, /) -> StageOutcome: ...

class ReconcileBoundary(Protocol):
    def __call__(self, findings: list[FindingRecord], /) -> list[FindingRecord]: ...

class ReportBoundary(Protocol):
    def __call__(self, result: ReviewResult, /) -> str: ...
