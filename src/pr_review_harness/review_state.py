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

from typing import Any

from .budget import BudgetLedger


class RunState:
    """Mutable, explicitly named state for one bounded review run."""

    # Run identity and trusted inputs (constructor arguments).
    snapshot: dict
    plan: dict
    profile: dict
    provider: Any
    decision_provider: Any
    limits: dict
    output_dir: str
    run_id: str
    resume: bool
    freshness_check: Any
    context_retriever: Any
    check_adapter: Any
    claim_assessor: Any
    max_claim_assessments: int
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
    advisory_assessment: dict
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
    candidate: dict
    candidate_hash: Any
    candidate_id: Any
    candidate_ids: Any
    candidate_record: dict
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
    coverage_row: dict
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
    event: dict
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
    finding: dict
    finding_by_candidate: Any
    findings: Any
    finish_attempt: Any
    followup_evidence: Any
    followup_id: Any
    followup_obligation_id: Any
    followup_payload: Any
    followup_result: Any
    followup_task: dict
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
    ledger: dict
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
    obligation: dict
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
    payload: dict
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
    result: Any
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
    saved: Any
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
    task: Any
    task_by_id: dict
    task_has_required_quarantine: Any
    task_id: Any
    task_result: Any
    task_results: dict
    task_units: list
    tasks: Any
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
        snapshot: dict,
        plan: dict,
        profile: dict,
        provider: Any,
        decision_provider: Any,
        limits: dict,
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
        self.private_capture_dir = private_capture_dir
        self.private_capture_case_id = private_capture_case_id
        self.private_capture_request_pins = private_capture_request_pins
        self.private_capture_snapshot_pin = private_capture_snapshot_pin
        self.private_capture_source_audit_max_bytes = private_capture_source_audit_max_bytes
        self.contracts = {}
