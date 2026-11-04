"""Explicit run state for the bounded review controller (CA-1).

``RunState`` replaces the mutable closure state that used to be shared by
the nested functions inside ``engine.run_review``.  It carries run identity,
the snapshot/plan/profile binding, the budget ledger, reservations,
deadlines, coverage, checkpoint callables, and every derived index that
stages exchange.

The class is intentionally a plain annotated container: it has no behavior
of its own, so a stage can be constructed and exercised in isolation.  The
fields are not validated here; each stage validates its own inputs and
fails closed, exactly as the former nested functions did.
"""

from __future__ import annotations

from typing import Any, Protocol, Required, TypedDict

from .budget import BudgetLedger

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


class RunState:
    """Mutable, explicitly named state for one bounded review run."""

    # Run identity and trusted inputs (constructor arguments).
    snapshot: SnapshotRecord
    plan: PlanRecord
    profile: dict[str, Any]
    provider: Any
    decision_provider: Any
    limits: dict[str, Any]
    output_dir: str
    run_id: str
    resume: bool
    freshness_check: Any
    context_retriever: Any
    check_adapter: Any
    claim_assessor: Any
    max_claim_assessments: int
    price_table: Any
    private_capture_dir: str | None
    private_capture_case_id: str | None
    private_capture_request_pins: dict[str, dict] | None
    private_capture_snapshot_pin: dict[str, Any] | None
    private_capture_source_audit_max_bytes: int

    # Fields populated by stages, in execution order.
    _: Any
    accepted_improvements: Any
    active: Any
    active_key: Any
    actual_output: Any
    adjudication_attempt: Any
    adjudication_deadline: Any
    adjudication_dispatch_started: bool
    adjudication_evidence: Any
    adjudication_input_hash: Any
    adjudication_started_monotonic: Any
    advisory_assessment: dict[str, Any]
    advisory_attempt: Any
    advisory_call_started: Any
    advisory_deadline: Any
    advisory_text: Any
    allowed_budget_codes: Any
    anchor: Any
    anchor_hash: Any
    anchor_id: Any
    anchor_record: Any
    anchor_side: Any
    anchor_valid: Any
    approval_authority: Any
    assessment: Any
    assessment_refs: Any
    assessments_valid: Any
    attempt_index: Any
    attempts: Any
    attempts_done: Any
    attempts_used: Any
    audit_limits: dict
    blockers: Any
    blocking: Any
    budget: BudgetLedger
    budget_code: Any
    byte_count: Any
    cached: Any
    cached_assessment: Any
    cached_payload: Any
    cached_provenance: Any
    call_cap: Any
    call_estimate: Any
    call_limits: dict
    call_lock: Any
    candidate: dict[str, Any]
    candidate_hash: Any
    candidate_id: Any
    candidate_ids: Any
    candidate_record: dict[str, Any]
    candidates: Any
    capture_profile_id: Any
    causal_path_supported: Any
    causal_roles: Any
    causal_roles_valid: bool
    check: Any
    check_evidence_refs: Any
    check_result_evidence_invalid: bool
    check_result_unavailable: bool
    checkpoint: Any
    cited_evidence: list
    claim_assessor_code_hash: Any
    claim_assessor_contract: Any
    claim_assessor_identity_hash: Any
    claim_call_started: Any
    claim_candidate: Any
    claim_identity: dict
    claim_not_run: Any
    claim_reconciliation_rows: Any
    contracts: dict
    allow_archived_contracts: bool
    claim_row: Any
    claim_rows: Any
    claim_supported: Any
    closure_state: Any
    code: Any
    complete_assessment: Any
    completed_ids: list
    content: Any
    context_gaps: Any
    counts: Any
    coverage: list
    coverage_note_evidence_invalid: bool
    coverage_note_missing: bool
    coverage_note_result: str
    coverage_row: dict[str, Any]
    coverage_state: Any
    covered: Any
    deadline_cap: Any
    deadline_epoch: Any
    delivered_ids: Any
    dimension: Any
    dispatch_deadline: Any
    dispatched_refs: Any
    dynamic_obligations: Any
    dynamic_tasks: Any
    elapsed_ms: Any
    entry: Any
    error_code: Any
    estimate: Any
    estimated_size: Any
    event: dict[str, Any]
    evidence: Any
    evidence_cache: Any
    evidence_id: Any
    evidence_item: Any
    evidence_map: Any
    existing: Any
    existing_gap_ids: Any
    existing_obligation: Any
    expected_binding: Any
    expected_claim_contract: Any
    expected_provenance: dict
    expected_question_ids: Any
    expected_revision: Any
    expected_source_kind: Any
    failure_reason: Any
    fetched: list
    fid: Any
    finding: dict[str, Any]
    finding_by_candidate: Any
    findings: Any
    finish_attempt: Any
    followup_evidence: Any
    followup_id: Any
    followup_obligation_id: Any
    followup_payload: Any
    followup_result: Any
    followup_task: TaskRecord
    followup_unit_ids: Any
    freshness: str
    freshness_details: dict
    freshness_reserve_seconds: Any
    gap: Any
    gap_id: Any
    gap_obligations: Any
    gap_observation_known: bool
    index: Any
    input_cap: Any
    input_ceiling: Any
    input_evidence_ids: list
    introduced: Any
    introducedness_available: Any
    invalid_binding: bool
    invocation: Any
    ipc_cap: Any
    item: Any
    key: Any
    known_ids: Any
    known_task_ids: Any
    ledger: LedgerEntry
    lens: Any
    line: Any
    linked: Any
    location: Any
    location_valid: Any
    manifest: Any
    manifest_choice: Any
    materiality: Any
    max_context: Any
    max_workers: Any
    meta: Any
    missing_covered_units: Any
    note: Any
    note_count: Any
    note_counts: Any
    note_observation: Any
    note_observed: Any
    notes: Any
    notes_examined_count: Any
    notes_unexamined_after_match_count: Any
    obligation: dict[str, Any]
    obligation_by_id: Any
    obligation_id: Any
    obligations: Any
    observation: Any
    oid: Any
    old: Any
    ordered_candidates: Any
    original: Any
    original_refs: Any
    outcome: Any
    output_bytes: Any
    output_cap: Any
    output_path: Any
    partial_coverage_note: bool
    path: Any
    patterns: Any
    payload: dict[str, Any]
    pending: Any
    pin: Any
    planned: Any
    planned_task: Any
    planned_task_inputs: Any
    prefix: Any
    preflight_skips: Any
    prepared: Any
    prepared_body: Any
    prepared_candidate: Any
    prepared_evidence: Any
    prepared_hash: Any
    prepared_primary: Any
    prepared_question_ids_valid: bool
    prepared_question_map: dict
    prepared_questions: Any
    prepared_request: Any
    prepared_state: Any
    prepared_version: Any
    primary: Any
    primary_finding: Any
    primary_finding_by_candidate: Any
    primary_hash: Any
    primary_task_inputs: Any
    primary_tasks: Any
    prior: Any
    prior_index: Any
    prior_reservation: Any
    prior_task: Any
    private_capture: Any
    profile_id: Any
    proposal: Any
    provenance: Any
    provenance_valid: Any
    provider_identity: Any
    quarantine_observation: Any
    question_id: Any
    question_map: Any
    question_pairs: Any
    queue: Any
    quote: Any
    quoted_input_bytes: Any
    raw: Any
    raw_actual: Any
    raw_bytes: Any
    raw_candidate: Any
    raw_refs: list
    raw_response_cap: Any
    reason_code: str
    reconciliation_by_candidate: Any
    reconciliation_policy: Any
    record: Any
    record_by_candidate: Any
    record_task_outcome: Any
    record_update: dict
    refs: Any
    related: Any
    relation: Any
    remaining: Any
    remaining_call_limits: Any
    remote_meta: Any
    remote_type: Any
    report_notes: Any
    report_sections: dict
    request_basis: dict
    request_bytes: Any
    request_hash: Any
    required_claim_calls_remaining: Any
    required_claim_deadline_floor: Any
    required_context_not_covered: bool
    required_context_note_matches: Any
    required_context_note_observations: Any
    required_cov: Any
    required_dimensions: Any
    required_ids: list
    required_output_quarantined: Any
    reservation: Any
    reservation_key: Any
    reserve_local_check: Any
    reserve_provider_call: Any
    reserved_attempts: Any
    reserved_bytes: Any
    response: Any
    response_assessments: Any
    response_valid: Any
    result: ReviewResult | dict[str, object]
    results: Any
    retrieval_envelope_bytes: Any
    retrieval_key: Any
    retrieval_limits: dict
    retrieval_result_bytes: Any
    retrieved: Any
    retrieved_context: Any
    reused_assessment: Any
    review_input_size: Any
    role: Any
    role_name: Any
    role_records: Any
    run_followup: Any
    safe_error_code: Any
    saved: ReviewResult
    scope_units: list
    selected_path: Any
    semantic_provenance: Any
    semantic_result: Any
    semantic_role_refs: Any
    semantic_usage: Any
    settlement_bytes: Any
    skip_reason: Any
    snapshot_captured_evidence: dict
    snapshot_item: Any
    snapshot_reuse: Any
    source_request: Any
    split_skips: Any
    start_attempt: Any
    started: Any
    state: Any
    state_lock: Any
    status: Any
    structurally_valid: Any
    successful: Any
    supplied_ids: list
    support_keys: Any
    supported: Any
    target: Any
    target_binding: Any
    target_obligations: Any
    target_path: Any
    target_unit: Any
    task: TaskRecord
    task_by_id: dict[str, TaskRecord]
    task_has_required_quarantine: Any
    task_id: Any
    task_result: Any
    task_results: dict
    task_units: list
    tasks: list[TaskRecord]
    uid: Any
    uncertain: Any
    unit: Any
    unit_evidence: Any
    unit_evidence_ids: Any
    unit_id: Any
    unit_map: Any
    unit_notes: Any
    unresolved: Any
    unresolved_followup_count: int
    unresolved_ids: Any
    usage: Any
    used_context: int
    valid: Any
    valid_refs: Any
    valid_target: Any
    validated_check_evidence: Any
    value: Any
    verified: Any

    def __init__(
        self,
        snapshot: SnapshotRecord,
        plan: PlanRecord,
        profile: dict[str, Any],
        provider: Any,
        decision_provider: Any,
        limits: dict[str, Any],
        output_dir: str,
        run_id: str,
        resume: bool,
        freshness_check: Any,
        context_retriever: Any,
        check_adapter: Any,
        claim_assessor: Any,
        max_claim_assessments: int,
        private_capture_dir: str | None,
        private_capture_case_id: str | None,
        private_capture_request_pins: dict[str, dict] | None,
        private_capture_snapshot_pin: dict[str, Any] | None,
        private_capture_source_audit_max_bytes: int,
        allow_archived_contracts: bool = False,
        price_table: Any = None,
    ) -> None:
        self.snapshot = snapshot
        self.plan = plan
        self.profile = profile
        self.provider = provider
        self.decision_provider = decision_provider
        self.limits = limits
        self.output_dir = output_dir
        self.run_id = run_id
        self.resume = resume
        self.freshness_check = freshness_check
        self.context_retriever = context_retriever
        self.check_adapter = check_adapter
        self.claim_assessor = claim_assessor
        self.max_claim_assessments = max_claim_assessments
        self.price_table = price_table
        self.private_capture_dir = private_capture_dir
        self.private_capture_case_id = private_capture_case_id
        self.private_capture_request_pins = private_capture_request_pins
        self.private_capture_snapshot_pin = private_capture_snapshot_pin
        self.private_capture_source_audit_max_bytes = private_capture_source_audit_max_bytes
        self.contracts = {}
        self.allow_archived_contracts = allow_archived_contracts
