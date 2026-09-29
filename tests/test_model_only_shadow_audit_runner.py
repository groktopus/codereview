from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
from pathlib import Path

import pytest

from pr_review_harness import claim_transport, providers
from pr_review_harness.claim_transport import ClaimTransport
from pr_review_harness.providers import OpenAIProvider, ProviderError
from pr_review_harness.shadow_audit import _CapturingNativeCall
from pr_review_harness.shadow_preflight import AuditPreflightError

SPEC = importlib.util.spec_from_file_location(
    "model_only_shadow_runner", Path(__file__).resolve().parents[1] / "scripts/run_model_only_shadow_audit.py"
)
RUNNER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RUNNER)
_PROFILE_BYTES = b'{\n  "profile_id": "profile-v1"\n}\n'
_PROFILE_OBJECT = json.loads(_PROFILE_BYTES)
_PROFILE_FILE_SHA256 = hashlib.sha256(_PROFILE_BYTES).hexdigest()
_PROFILE_SNAPSHOT_SHA256 = hashlib.sha256(
    json.dumps(_PROFILE_OBJECT, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
).hexdigest()
SANITIZER_SPEC = importlib.util.spec_from_file_location(
    "shadow_audit_receipt_sanitizer", Path(__file__).resolve().parents[1] / "scripts/sanitize_model_only_shadow_audit_receipt.py"
)
SANITIZER = importlib.util.module_from_spec(SANITIZER_SPEC)
assert SANITIZER_SPEC.loader is not None
SANITIZER_SPEC.loader.exec_module(SANITIZER)
POLICY_PATH_RESOLVER = RUNNER.case_for_plan_path
POLICY_VALIDATOR = RUNNER.validate_plan_binding
REPO_ROOT = Path(__file__).resolve().parents[1]
CASE_IDENTITY = {
    "snapshot_id": "snap-test", "snapshot_hash": "a" * 64, "base_sha": "b" * 40,
    "head_sha": "c" * 40, "profile_version": "profile-v1", "profile_hash": _PROFILE_SNAPSHOT_SHA256,
}
AUDIT_ROLES = ("source_auditor", "jev", "claim_auditor")


def _receipt_dispatch_fields(accounting):
    return {
        "audit_provider_calls": sum(row["dispatched"] for row in accounting.values()),
        "role_call_counts": {role: row["attempted"] for role, row in accounting.items()},
        "role_dispatched_call_counts": {role: row["dispatched"] for role, row in accounting.items()},
        "role_guard_rejected_counts": {role: row["guard_rejected"] for role, row in accounting.items()},
        "role_post_guard_pretransport_counts": {
            role: row["post_guard_pretransport"] for role, row in accounting.items()
        },
        "role_unknown_dispatch_counts": {role: row["unknown"] for role, row in accounting.items()},
        "role_request_sha256": {role: row["request_sha256"] for role, row in accounting.items()},
    }


def _candidate_free_receipt(*, source_status="completed", jev_status="not_run",
                            source_state="http_attempted", jev_state=None):
    accounting = {}
    states = {"source_auditor": source_state, "jev": jev_state, "claim_auditor": None}
    for role, state in states.items():
        row = {"attempted": int(state is not None), "dispatched": 0, "guard_rejected": 0,
               "post_guard_pretransport": 0, "unknown": 0,
               "request_sha256": hashlib.sha256(role.encode()).hexdigest() if state is not None else None}
        if state is not None:
            key = {
                "http_attempted": "dispatched", "guard_rejected": "guard_rejected",
                "post_guard_pretransport": "post_guard_pretransport", "unknown": "unknown",
            }[state]
            row[key] = 1
        accounting[role] = row
    return {
        "schema": "model-only-shadow-audit-receipt.v1", "case_id": "PR-464",
        "terminal_state": "incomplete", "reason": "no_writer_candidate",
        "candidate_packet_count": 0, "selected_packet_sha256": "a" * 64,
        "capture_manifest_sha256": "b" * 64,
        "roles": {"source_auditor": source_status, "jev": jev_status, "claim_auditor": "not_run"},
        **_receipt_dispatch_fields(accounting),
    }


@pytest.fixture(autouse=True)
def trusted_profile_file(tmp_path, monkeypatch):
    path = tmp_path / RUNNER.PROFILE_RELATIVE_PATH
    path.parent.mkdir(parents=True)
    path.write_bytes(_PROFILE_BYTES)
    monkeypatch.setattr(RUNNER, "ROOT", tmp_path)
    policy = {**RUNNER.CASE_POLICY["PR-464"], "profile_sha256": _PROFILE_FILE_SHA256}
    monkeypatch.setattr(RUNNER, "case_for_plan_path", lambda _path, _root: ("PR-464", policy))
    monkeypatch.setattr(RUNNER, "validate_plan_binding", lambda _plan, _raw: ("PR-464", policy))


def _packet(case_id: str, candidate_id: str | None, task_id: str) -> dict:
    return {"contract_version": "model-only-shadow-case.v1", "case_id": case_id,
            "snapshot": dict(CASE_IDENTITY),
            "source_task": {"task_id": task_id},
            "writer_candidate": None if candidate_id is None else {"candidate_id": candidate_id}}


def _plan(task_ids: list[str], *, budget: dict | None = None) -> dict:
    return {"schema": "model-only-shadow-live-writer-plan.v1",
            "budget": budget or {
                "audit_max_deadline_seconds_per_call": 90,
                "audit_max_input_bytes_per_call": 64000,
                "audit_max_output_tokens_per_llm_call": 1800,
                "audit_max_provider_calls": 3,
                "audit_max_response_bytes_per_call": 64000,
                "audit_max_retries": 0,
                "total_provider_deadline_seconds_max": 870,
                "writer_deadline_seconds": 600,
            },
            "case": {"case_id": "PR-464", "snapshot_id": CASE_IDENTITY["snapshot_id"],
                     "snapshot_sha256": CASE_IDENTITY["snapshot_hash"], "base_sha": CASE_IDENTITY["base_sha"],
                     "head_sha": CASE_IDENTITY["head_sha"], "profile_version": CASE_IDENTITY["profile_version"],
                     "profile_file_sha256": _PROFILE_FILE_SHA256},
            "prepare_contract": {"profile_path": RUNNER.PROFILE_RELATIVE_PATH},
            "writer_requests": [{"task_id": task_id} for task_id in task_ids]}


def _capture(root: Path, packets: list[dict], *, manifest_case_id: str = "writer-live-123-1") -> Path:
    root.mkdir(mode=0o700)
    packet_dir = root / "case-packets"
    packet_dir.mkdir(mode=0o700)
    inventory = []
    for index, packet in enumerate(packets):
        path = packet_dir / f"packet-{index}.json"
        raw = json.dumps(packet).encode()
        path.write_bytes(raw)
        inventory.append({"path": path.name, "sha256": hashlib.sha256(raw).hexdigest()})
    (root / "manifest.json").write_text(json.dumps({
        "contract_version": "model-only-shadow-case.v1", "case_id": manifest_case_id, "private_artifacts": True,
        "snapshot_id": CASE_IDENTITY["snapshot_id"], "snapshot_hash": CASE_IDENTITY["snapshot_hash"],
        "case_packet_inventory": {"schema": "model-only-shadow-packet-inventory.v1", "packets": inventory},
    }))
    return root


def test_default_plan_stays_pr464_and_pr457_plan_selects_its_frozen_profile():
    assert RUNNER.DEFAULT_PLAN == REPO_ROOT / "experiments/model-only-shadow-live-pr464-plan-v2.json"
    plan_path = REPO_ROOT / RUNNER.CASE_POLICY["PR-457"]["plan_relative_path"]
    plan_raw = plan_path.read_bytes()
    plan = json.loads(plan_raw)
    case_id, policy = POLICY_PATH_RESOLVER(plan_path, REPO_ROOT)
    validated_case_id, validated_policy = POLICY_VALIDATOR(plan, plan_raw)
    assert case_id == validated_case_id == "PR-457"
    assert policy == validated_policy
    assert plan["prepare_contract"]["profile_path"] == policy["profile_path"]
    assert hashlib.sha256((REPO_ROOT / policy["profile_path"]).read_bytes()).hexdigest() == policy["profile_sha256"]


def test_current_pr457_plan_accepts_current_audit_limits():
    plan_path = REPO_ROOT / RUNNER.CASE_POLICY["PR-457"]["plan_relative_path"]
    plan, _ = RUNNER._read_json(plan_path, 256_000)
    plan_budget = RUNNER._plan_budget(plan)
    limits = RUNNER._load_limits(RUNNER.DEFAULT_LIMITS)
    RUNNER._validate_plan_budget(plan_budget, limits)


def test_pr457_audit_failure_receipt_keeps_the_selected_case_identity(tmp_path, monkeypatch):
    policy = RUNNER.CASE_POLICY["PR-457"]
    monkeypatch.setattr(RUNNER, "case_for_plan_path", lambda _path, _root: ("PR-457", policy))
    receipt_path = tmp_path / "receipt" / "failure.json"
    with pytest.raises(RUNNER.PreDispatchFailure) as error:
        RUNNER.run(tmp_path / "missing-capture", tmp_path / "provider.json", tmp_path / "jev.json",
                   tmp_path / "raw-audit", receipt_path, tmp_path / "plan.json")
    assert error.value.stage == "capture_validation"
    receipt = json.loads(receipt_path.read_text())
    assert receipt["case_id"] == "PR-457"
    output = tmp_path / "sanitized"
    SANITIZER.sanitize(receipt_path, output)
    assert json.loads((output / "shadow-audit-receipt.json").read_text())["case_id"] == "PR-457"


def test_packet_inventory_detects_missing_packet_from_multi_candidate_task(tmp_path):
    root = _capture(tmp_path / "capture", [_packet("PR-464", "candidate-a", "task-first"),
                                             _packet("PR-464", "candidate-b", "task-first")])
    (root / "case-packets" / "packet-1.json").unlink()
    with pytest.raises(ValueError, match="capture_packet_inventory_mismatch"):
        RUNNER._packet_candidates(root)


def test_packet_inventory_detects_packet_content_change(tmp_path):
    root = _capture(tmp_path / "capture", [_packet("PR-464", "candidate-a", "task-first")])
    (root / "case-packets" / "packet-0.json").write_text(json.dumps(_packet("PR-464", None, "task-first")))
    with pytest.raises(ValueError, match="capture_packet_inventory_mismatch"):
        RUNNER._packet_candidates(root)


def test_writer_run_identity_may_differ_from_packet_corpus_identity(tmp_path):
    root = _capture(tmp_path / "capture", [_packet("PR-464", "candidate-a", "task-first")])
    manifest, _, rows = RUNNER._packet_candidates(root)
    assert manifest["case_id"] == "writer-live-123-1"
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_plan(["task-first"])))
    ordered = RUNNER._task_order(plan, rows, manifest)
    assert ordered[0][2]["case_id"] == "PR-464"


def test_plan_binds_raw_profile_file_pin_to_canonical_snapshot_profile_hash(tmp_path):
    assert _PROFILE_FILE_SHA256 != _PROFILE_SNAPSHOT_SHA256
    root = _capture(tmp_path / "capture", [_packet("PR-464", "candidate-a", "task-first")])
    _, _, rows = RUNNER._packet_candidates(root)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_plan(["task-first"])))

    ordered = RUNNER._task_order(plan, rows)

    assert ordered[0][2]["snapshot"]["profile_hash"] == _PROFILE_SNAPSHOT_SHA256


def test_tampered_packet_corpus_identity_fails_before_provider_setup_and_writes_receipt(tmp_path, monkeypatch):
    root = _capture(tmp_path / "capture", [_packet("untrusted-case", "candidate-a", "task-first")])
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_plan(["task-first"])))
    receipt_path = tmp_path / "receipt" / "failure.json"

    def forbidden_provider(_config):
        raise AssertionError("provider construction must not occur before plan binding")

    monkeypatch.setattr(RUNNER, "OpenAIProvider", forbidden_provider)
    with pytest.raises(RUNNER.PreDispatchFailure) as error:
        RUNNER.run(root, tmp_path / "missing-provider.json", tmp_path / "missing-jev.json",
                   tmp_path / "raw-audit", receipt_path, plan)

    assert error.value.stage == "plan_binding"
    assert not (tmp_path / "raw-audit").exists()
    failure = json.loads(receipt_path.read_text())
    assert failure == {
        "schema": "model-only-shadow-audit-predispatch-failure.v1",
        "case_id": "PR-464", "terminal_state": "failed_before_dispatch",
        "failure_stage": "plan_binding", "failure_code": "plan_binding_invalid",
        "audit_provider_calls": 0,
    }
    sanitized = tmp_path / "sanitized-failure"
    SANITIZER.sanitize(receipt_path, sanitized)
    assert json.loads((sanitized / "shadow-audit-receipt.json").read_text()) == failure


@pytest.mark.parametrize("malformed", ["case_id", "task_id"])
def test_unhashable_packet_identity_fails_closed_with_plan_binding_receipt(tmp_path, monkeypatch, malformed):
    packet = _packet("PR-464", "candidate-a", "task-first")
    if malformed == "case_id":
        packet["case_id"] = []
    else:
        packet["source_task"]["task_id"] = []
    root = _capture(tmp_path / "capture", [packet])
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_plan(["task-first"])))
    receipt_path = tmp_path / "receipt" / "failure.json"

    def forbidden_provider(_config):
        raise AssertionError("provider construction must not occur before plan binding")

    monkeypatch.setattr(RUNNER, "OpenAIProvider", forbidden_provider)
    with pytest.raises(RUNNER.PreDispatchFailure) as error:
        RUNNER.run(root, tmp_path / "missing-provider.json", tmp_path / "missing-jev.json",
                   tmp_path / "raw-audit", receipt_path, plan)

    assert error.value.stage == "plan_binding"
    assert error.value.code == "plan_binding_invalid"
    assert not (tmp_path / "raw-audit").exists()
    failure = json.loads(receipt_path.read_text())
    assert failure["failure_stage"] == "plan_binding"
    assert failure["failure_code"] == "plan_binding_invalid"
    assert failure["audit_provider_calls"] == 0
    sanitized = tmp_path / "sanitized-failure"
    SANITIZER.sanitize(receipt_path, sanitized)


def test_audit_input_rejection_writes_receipt_only_when_dispatch_guard_is_unspent(tmp_path):
    root = _capture(tmp_path / "capture", [_packet("PR-464", "candidate-a", "task-first")])
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_plan(["task-first"])))
    provider_config = tmp_path / "provider.json"
    provider_config.write_text(json.dumps({
        "kind": "openai_compatible", "base_url": RUNNER.EXPECTED_LLM[0],
        "model": RUNNER.EXPECTED_LLM[1], "api_key_env": "LLM_API_KEY",
    }))
    jev_config = tmp_path / "jev.json"
    jev_config.write_text(json.dumps({
        "kind": "typesafe", "endpoint": RUNNER.EXPECTED_JEV[0],
        "model": RUNNER.EXPECTED_JEV[1], "api_key_env": "JEV_API_KEY",
    }))
    receipt_path = tmp_path / "receipt" / "failure.json"

    with pytest.raises(RUNNER.PreDispatchFailure) as error:
        RUNNER.run(root, provider_config, jev_config, tmp_path / "raw-audit", receipt_path, plan)

    assert error.value.stage == "audit_validation"
    assert not (tmp_path / "raw-audit").exists()
    failure = json.loads(receipt_path.read_text())
    assert failure["failure_stage"] == "audit_validation"
    assert failure["failure_code"] == "audit_input_invalid"
    assert failure["audit_provider_calls"] == 0
    sanitized = tmp_path / "sanitized-audit-failure"
    SANITIZER.sanitize(receipt_path, sanitized)


@pytest.mark.parametrize(("actual", "cap", "cap_value", "actual_value"), [
    ("deadline_seconds", "audit_max_deadline_seconds_per_call", 89, 90),
    ("max_input_bytes_per_task", "audit_max_input_bytes_per_call", 63999, 64000),
    ("max_output_bytes_per_task", "audit_max_response_bytes_per_call", 63999, 64000),
    ("max_output_tokens", "audit_max_output_tokens_per_llm_call", 1799, 1800),
    ("max_provider_calls", "audit_max_provider_calls", 2, 3),
    ("max_retries", "audit_max_retries", 0, 1),
    ("total_provider_deadline_seconds", "total_provider_deadline_seconds_max", 869, 270),
])
def test_over_budget_audit_fails_before_provider_config_or_transport(
    tmp_path, monkeypatch, actual, cap, cap_value, actual_value
):
    root = _capture(tmp_path / "capture", [_packet("PR-464", "candidate-a", "task-first")])
    plan = tmp_path / "plan.json"
    budget = {
        "audit_max_deadline_seconds_per_call": 90,
        "audit_max_input_bytes_per_call": 64000,
        "audit_max_output_tokens_per_llm_call": 1800,
        "audit_max_provider_calls": 3,
        "audit_max_response_bytes_per_call": 64000,
        "audit_max_retries": 0,
        "total_provider_deadline_seconds_max": 870,
        "writer_deadline_seconds": 600,
    }
    budget[cap] = cap_value
    plan.write_text(json.dumps(_plan(["task-first"], budget=budget)))
    receipt_path = tmp_path / "receipt" / "failure.json"

    actual_limits = RUNNER._load_limits(RUNNER.DEFAULT_LIMITS)
    actual_limits[actual] = actual_value
    monkeypatch.setattr(RUNNER, "_load_limits", lambda _path: actual_limits)

    def forbidden_provider(_config):
        raise AssertionError("provider construction must not occur for an over-budget plan")

    monkeypatch.setattr(RUNNER, "OpenAIProvider", forbidden_provider)
    monkeypatch.setattr(RUNNER.ClaimTransport, "from_decision_config",
                        lambda _config: (_ for _ in ()).throw(AssertionError("transport setup must not occur")))
    with pytest.raises(RUNNER.PreDispatchFailure) as error:
        RUNNER.run(root, tmp_path / "missing-provider.json", tmp_path / "missing-jev.json",
                   tmp_path / "raw-audit", receipt_path, plan)

    assert error.value.stage == "budget_validation"
    assert error.value.code == "audit_budget_exceeded"
    assert not (tmp_path / "raw-audit").exists()
    assert json.loads(receipt_path.read_text()) == {
        "schema": "model-only-shadow-audit-predispatch-failure.v1",
        "case_id": "PR-464", "terminal_state": "failed_before_dispatch",
        "failure_stage": "budget_validation", "failure_code": "audit_budget_exceeded",
        "audit_provider_calls": 0,
    }


def test_budget_guard_accepts_exact_caps_and_rejects_each_over_limit_dimension():
    limits = {
        "deadline_seconds": 90, "max_input_bytes_per_task": 64000,
        "max_output_bytes_per_task": 64000, "max_output_tokens": 1800,
        "max_provider_calls": 3, "max_retries": 0,
        "total_provider_deadline_seconds": 270,
    }
    plan_budget = {
        "audit_max_deadline_seconds_per_call": 90,
        "audit_max_input_bytes_per_call": 64000,
        "audit_max_output_tokens_per_llm_call": 1800,
        "audit_max_provider_calls": 3,
        "audit_max_response_bytes_per_call": 64000,
        "audit_max_retries": 0,
        "total_provider_deadline_seconds_max": 870,
        "writer_deadline_seconds": 600,
    }
    RUNNER._validate_plan_budget(plan_budget, limits)
    dimensions = [
        ("deadline_seconds", "audit_max_deadline_seconds_per_call"),
        ("max_input_bytes_per_task", "audit_max_input_bytes_per_call"),
        ("max_output_bytes_per_task", "audit_max_response_bytes_per_call"),
        ("max_output_tokens", "audit_max_output_tokens_per_llm_call"),
        ("max_provider_calls", "audit_max_provider_calls"),
        ("max_retries", "audit_max_retries"),
    ]
    for actual, _cap in dimensions:
        candidate = dict(limits)
        candidate[actual] += 1
        with pytest.raises(ValueError, match="audit_limits_exceed_plan_budget"):
            RUNNER._validate_plan_budget(plan_budget, candidate)
    candidate = dict(limits, total_provider_deadline_seconds=271)
    with pytest.raises(ValueError, match="combined_deadline_exceeds_plan_budget"):
        RUNNER._validate_plan_budget(plan_budget, candidate)


def test_selection_uses_pinned_task_order_then_packet_digest(tmp_path):
    root = _capture(tmp_path / "capture", [_packet("PR-464", "candidate-a", "task-late"),
                                             _packet("PR-464", "candidate-z", "task-first")])
    _, _, rows = RUNNER._packet_candidates(root)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_plan(["task-first", "task-late"])))
    ordered = RUNNER._task_order(plan, rows)
    assert RUNNER._select_packet(ordered)[0] == "candidate-z"
    rows.reverse()
    assert RUNNER._select_packet(RUNNER._task_order(plan, rows))[0] == "candidate-z"


def test_packet_task_coverage_must_match_every_pinned_writer_task(tmp_path):
    root = _capture(tmp_path / "capture", [_packet("PR-464", None, "task-first")])
    _, _, rows = RUNNER._packet_candidates(root)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_plan(["task-first", "task-missing"])))
    with pytest.raises(ValueError, match="case_packet_task_coverage_mismatch"):
        RUNNER._task_order(plan, rows)


def test_candidate_free_capture_emits_incomplete_hash_only_receipt_without_provider_config(tmp_path):
    root = _capture(tmp_path / "capture", [_packet("PR-464", None, "task-first")])
    receipt_path = tmp_path / "sanitized" / "shadow-receipt.json"
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_plan(["task-first"])))
    receipt = RUNNER.run(root, tmp_path / "missing-provider.json", tmp_path / "missing-jev.json",
                         tmp_path / "raw-audit", receipt_path, plan)
    assert receipt["terminal_state"] == "incomplete"
    assert receipt["reason"] == "no_writer_candidate"
    assert receipt["audit_provider_calls"] == 0
    assert set(receipt["roles"].values()) == {"not_run"}
    assert not (tmp_path / "raw-audit").exists()
    assert stat.S_IMODE(receipt_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600
    raw = receipt_path.read_text()
    assert '"writer_candidate":' not in raw and "source_evidence" not in raw and "selected_candidate_id" not in raw


def test_opt_in_candidate_free_source_stage_dispatches_one_source_call_and_never_claim(tmp_path, monkeypatch):
    root = _capture(tmp_path / "capture", [_packet("PR-464", None, "task-first")])
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_plan(["task-first"])))
    packet_path = root / "case-packets" / "packet-0.json"
    selection_path = tmp_path / "selection.json"
    selection_path.write_text(json.dumps({
        "schema": "frozen-pr464-no-candidate-selection.v1", "case_id": "PR-464",
        "packet_path": "case-packets/packet-0.json",
        "selected_packet_sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest(),
        "capture_manifest_sha256": hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest(),
        "plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
        "snapshot_sha256": CASE_IDENTITY["snapshot_hash"],
        "selected_task_sha256": hashlib.sha256(b"task-first").hexdigest(),
        "writer_calls": 10, "audit_provider_calls": 0,
        "publication_enabled": False, "target_code_execution": False,
    }))
    provider_config = tmp_path / "provider.json"
    provider_config.write_text(json.dumps({
        "kind": "openai_compatible", "base_url": RUNNER.EXPECTED_LLM[0],
        "model": RUNNER.EXPECTED_LLM[1], "api_key_env": "LLM_API_KEY",
    }))
    jev_config = tmp_path / "jev.json"
    jev_config.write_text(json.dumps({
        "kind": "typesafe", "endpoint": RUNNER.EXPECTED_JEV[0],
        "model": RUNNER.EXPECTED_JEV[1], "api_key_env": "JEV_API_KEY",
    }))
    receipt_path = tmp_path / "receipt" / "source-only.json"
    request = b'{"source_only":"one-call"}'
    request_hash = hashlib.sha256(request).hexdigest()
    observed = []

    class FakeProvider:
        def __init__(self, config):
            self.identity = {"provider_id": "operator_openai_compatible", "model_id": config["model"]}

    class FakeJevTransport:
        def __init__(self):
            self.timeout_seconds = 0
            self.max_request_bytes = 0
            self.max_response_bytes = 0

    class FakeClaimTransport:
        @staticmethod
        def from_decision_config(_config):
            return FakeJevTransport()

    class FakeDispatchGuard:
        def __init__(self, _limits):
            pass

        def check(self, role, raw):
            assert role == "source_auditor"
            assert raw == request

    def source_only_audit(packet, *, source_provider, jev_transport, claim_provider, limits,
                          output_dir, before_dispatch):
        assert packet["writer_candidate"] is None
        assert source_provider is not claim_provider
        assert jev_transport.timeout_seconds == limits["deadline_seconds"]
        output_dir.mkdir(mode=0o700)
        before_dispatch("source_auditor", request)
        observed.append(request_hash)
        manifest = {
            "terminal_state": "incomplete",
            "roles": {
                "source_auditor": {"status": "completed", "calls": [{
                    "dispatch_state": "http_attempted", "request_sha256": request_hash,
                }]},
                "jev": {"status": "not_run", "calls": []},
                "claim_auditor": {"status": "not_run", "calls": []},
            },
        }
        (output_dir / "shadow-audit-manifest.json").write_text(json.dumps(manifest))
        return {"manifest": manifest, "artifact_paths": {}}

    monkeypatch.setattr(RUNNER, "OpenAIProvider", FakeProvider)
    monkeypatch.setattr(RUNNER, "ClaimTransport", FakeClaimTransport)
    monkeypatch.setattr(RUNNER, "AuditDispatchGuard", FakeDispatchGuard)
    monkeypatch.setattr(RUNNER, "run_shadow_audit", source_only_audit)
    receipt = RUNNER.run(
        root, provider_config, jev_config, tmp_path / "raw-audit", receipt_path, plan,
        source_only_no_candidate=True, selection_receipt_path=selection_path,
    )
    assert observed == [request_hash]
    assert receipt["reason"] == "no_writer_candidate"
    assert receipt["candidate_packet_count"] == 0
    assert receipt["audit_provider_calls"] == 1
    assert receipt["role_call_counts"] == {"source_auditor": 1, "jev": 0, "claim_auditor": 0}
    assert receipt["role_dispatched_call_counts"] == {"source_auditor": 1, "jev": 0, "claim_auditor": 0}
    assert set(receipt) == {
        "schema", "case_id", "terminal_state", "reason", "audit_provider_calls", "candidate_packet_count",
        "selected_packet_sha256", "capture_manifest_sha256", "roles", "role_call_counts",
        "role_dispatched_call_counts", "role_guard_rejected_counts", "role_post_guard_pretransport_counts",
        "role_unknown_dispatch_counts", "role_request_sha256",
    }
    sanitized = tmp_path / "sanitized-source-only"
    SANITIZER.sanitize(receipt_path, sanitized)
    assert json.loads((sanitized / "shadow-audit-receipt.json").read_text()) == receipt


def test_source_only_selection_mismatch_fails_before_provider_setup(tmp_path, monkeypatch):
    root = _capture(tmp_path / "capture", [_packet("PR-464", None, "task-first")])
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_plan(["task-first"])))
    selection = tmp_path / "selection.json"
    selection.write_text(json.dumps({"schema": "wrong"}))
    receipt_path = tmp_path / "receipt" / "source-only.json"
    monkeypatch.setattr(RUNNER, "OpenAIProvider", lambda _config: (_ for _ in ()).throw(
        AssertionError("selection mismatch must fail before provider setup")))
    with pytest.raises(RUNNER.PreDispatchFailure) as error:
        RUNNER.run(root, tmp_path / "provider.json", tmp_path / "jev.json", tmp_path / "raw-audit",
                   receipt_path, plan, source_only_no_candidate=True, selection_receipt_path=selection)
    assert error.value.code == "capture_invalid"
    assert json.loads(receipt_path.read_text())["audit_provider_calls"] == 0
    assert not (tmp_path / "raw-audit").exists()


def test_source_only_opt_in_fails_before_provider_setup_when_candidate_exists(tmp_path, monkeypatch):
    root = _capture(tmp_path / "capture", [_packet("PR-464", "candidate-a", "task-first")])
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_plan(["task-first"])))
    receipt_path = tmp_path / "receipt" / "source-only.json"
    monkeypatch.setattr(RUNNER, "OpenAIProvider", lambda _config: (_ for _ in ()).throw(
        AssertionError("candidate presence must fail before provider setup")))
    with pytest.raises(RUNNER.PreDispatchFailure) as error:
        RUNNER.run(root, tmp_path / "provider.json", tmp_path / "jev.json", tmp_path / "raw-audit",
                   receipt_path, plan, source_only_no_candidate=True)
    assert error.value.code == "capture_invalid"
    assert not (tmp_path / "raw-audit").exists()
    failure = json.loads(receipt_path.read_text())
    assert failure["audit_provider_calls"] == 0


def test_plan_order_and_hash_tie_break_do_not_use_candidate_text(tmp_path):
    root = _capture(tmp_path / "capture", [_packet("PR-464", "zzz", "task-first"),
                                             _packet("PR-464", "aaa", "task-first")])
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_plan(["task-first"])))
    _, _, rows = RUNNER._packet_candidates(root)
    rows.reverse()
    selected = RUNNER._select_packet(RUNNER._task_order(plan, rows))
    expected = min(rows, key=lambda row: __import__("hashlib").sha256(row[3]).hexdigest())
    assert selected[1] == expected[1]


def test_provider_identity_is_pinned_before_audit_dispatch():
    provider = {"kind": "openai_compatible", "provider_id": "operator_openai_compatible",
                "base_url": "https://inference-api.nousresearch.com/v1", "model": "openai/gpt-6-luna",
                "api_key_env": "LLM_API_KEY"}
    jev = {"kind": "typesafe", "endpoint": "https://api.typesafe.ai/v1/systemone",
           "model": "jev-latest", "api_key_env": "JEV_API_KEY"}
    RUNNER._validate_provider_identity(provider, jev)
    provider["model"] = "unreviewed-alias"
    try:
        RUNNER._validate_provider_identity(provider, jev)
    except ValueError as exc:
        assert str(exc) == "llm_identity_mismatch"
    else:
        raise AssertionError("unpinned LLM identity was accepted")


def test_sanitizer_rejects_untrusted_case_text_and_accepts_zero_candidate_receipt(tmp_path):
    receipt = {
        "schema": "model-only-shadow-audit-receipt.v1", "case_id": "PR-464",
        "terminal_state": "incomplete", "reason": "no_writer_candidate",
        "audit_provider_calls": 0, "candidate_packet_count": 0,
        "selected_packet_sha256": "a" * 64, "capture_manifest_sha256": "b" * 64,
        "roles": {role: "not_run" for role in AUDIT_ROLES},
        **_receipt_dispatch_fields({role: {
            "attempted": 0, "dispatched": 0, "guard_rejected": 0,
            "post_guard_pretransport": 0, "unknown": 0, "request_sha256": None,
        } for role in AUDIT_ROLES}),
    }
    source = tmp_path / "input.json"
    source.write_text(json.dumps(receipt))
    output = tmp_path / "sanitized"
    SANITIZER.sanitize(source, output)
    assert json.loads((output / "shadow-audit-receipt.json").read_text()) == receipt

    receipt["case_id"] = "untrusted\nvalue"
    source.write_text(json.dumps(receipt))
    try:
        SANITIZER._valid(receipt)
    except SANITIZER.ReceiptError as exc:
        assert str(exc) == "receipt_identity_invalid"
    else:
        raise AssertionError("untrusted case text was accepted")


@pytest.mark.parametrize(("receipt",), [
    (_candidate_free_receipt(),),
    (_candidate_free_receipt(source_status="completed", jev_status="completed", jev_state="http_attempted"),),
    (_candidate_free_receipt(source_status="completed", jev_status="failed", jev_state="post_guard_pretransport"),),
    (_candidate_free_receipt(source_status="abstained", jev_status="not_run", jev_state=None),),
    (_candidate_free_receipt(source_status="failed", jev_status="not_run", source_state="unknown"),),
])
def test_sanitizer_accepts_bounded_source_only_no_candidate_receipt(receipt):
    SANITIZER._valid(receipt)
    assert receipt["candidate_packet_count"] == 0
    assert receipt["terminal_state"] == "incomplete"
    assert receipt["reason"] == "no_writer_candidate"
    assert receipt["audit_provider_calls"] <= 2
    assert receipt["role_call_counts"]["source_auditor"] == 1
    assert receipt["role_call_counts"]["claim_auditor"] == 0
    assert receipt["roles"]["claim_auditor"] == "not_run"


@pytest.mark.parametrize("mutate", [
    lambda receipt: receipt.update(disposition="PASS"),
    lambda receipt: receipt["roles"].update(claim_auditor="completed"),
    lambda receipt: receipt["role_call_counts"].update(claim_auditor=1),
    lambda receipt: receipt["role_call_counts"].update(source_auditor=2),
    lambda receipt: receipt.update(audit_provider_calls=3),
    lambda receipt: receipt.update(audit_provider_calls=1),
    lambda receipt: receipt["role_dispatched_call_counts"].update(source_auditor=0),
])
def test_sanitizer_rejects_false_or_inconsistent_no_candidate_receipts(mutate):
    receipt = _candidate_free_receipt(source_status="completed", jev_status="completed", jev_state="http_attempted")
    mutate(receipt)
    with pytest.raises(SANITIZER.ReceiptError):
        SANITIZER._valid(receipt)


def test_sanitizer_rejects_jev_call_without_completed_source_or_after_abstention():
    for receipt in (
        _candidate_free_receipt(source_status="failed", jev_status="failed", jev_state="http_attempted"),
        _candidate_free_receipt(source_status="abstained", jev_status="completed", jev_state="http_attempted"),
    ):
        with pytest.raises(SANITIZER.ReceiptError):
            SANITIZER._valid(receipt)


def test_sanitizer_rejects_contradictory_terminal_call_and_candidate_accounting():
    receipt = {
        "schema": "model-only-shadow-audit-receipt.v1", "case_id": "PR-464",
        "terminal_state": "completed", "reason": "one_candidate_selected",
        "audit_provider_calls": 3, "candidate_packet_count": 1,
        "selected_candidate_sha256": "c" * 64, "selected_packet_sha256": "a" * 64,
        "capture_manifest_sha256": "b" * 64, "shadow_manifest_sha256": "d" * 64,
        "roles": {role: "completed" for role in AUDIT_ROLES},
        **_receipt_dispatch_fields({role: {
            "attempted": 1, "dispatched": 1, "guard_rejected": 0,
            "post_guard_pretransport": 0, "unknown": 0, "request_sha256": str(index) * 64,
        } for index, role in enumerate(AUDIT_ROLES, 1)}),
    }
    SANITIZER._valid(receipt)
    invalid = dict(receipt, reason="no_writer_candidate")
    with pytest.raises(SANITIZER.ReceiptError, match="candidate_selection_reason_mismatch"):
        SANITIZER._valid(invalid)
    invalid = dict(receipt, audit_provider_calls=2)
    with pytest.raises(SANITIZER.ReceiptError, match="receipt_dispatch_accounting_invalid"):
        SANITIZER._valid(invalid)
    invalid = dict(receipt, terminal_state="source_audit_failed")
    with pytest.raises(SANITIZER.ReceiptError, match="terminal_role_accounting_mismatch"):
        SANITIZER._valid(invalid)


@pytest.mark.parametrize("rejected_role", AUDIT_ROLES)
def test_guard_rejection_is_not_counted_as_http_call_and_survives_sanitization(tmp_path, rejected_role):
    rejected_index = AUDIT_ROLES.index(rejected_role)
    roles = {}
    for index, role in enumerate(AUDIT_ROLES):
        if index < rejected_index:
            dispatch_state, status = "http_attempted", "completed"
        elif index == rejected_index:
            dispatch_state, status = "guard_rejected", "failed"
        else:
            dispatch_state, status = None, "not_run"
        call = [] if dispatch_state is None else [{
            "dispatch_state": dispatch_state, "request_sha256": hashlib.sha256(role.encode()).hexdigest(),
        }]
        roles[role] = {"status": status, "calls": call}

    accounting = RUNNER._dispatch_accounting(roles)
    fields = _receipt_dispatch_fields(accounting)
    receipt = {
        "schema": "model-only-shadow-audit-receipt.v1", "case_id": "PR-464",
        "terminal_state": {
            "source_auditor": "source_audit_failed", "jev": "jev_assessment_failed",
            "claim_auditor": "claim_audit_failed",
        }[rejected_role],
        "reason": "one_candidate_selected", "candidate_packet_count": 1,
        "selected_candidate_sha256": "c" * 64, "selected_packet_sha256": "a" * 64,
        "capture_manifest_sha256": "b" * 64, "shadow_manifest_sha256": "d" * 64,
        "roles": {role: data["status"] for role, data in roles.items()}, **fields,
    }
    sanitized_dir = tmp_path / rejected_role
    input_path = tmp_path / f"{rejected_role}.json"
    input_path.write_text(json.dumps(receipt))
    SANITIZER.sanitize(input_path, sanitized_dir)
    sanitized = json.loads((sanitized_dir / "shadow-audit-receipt.json").read_text())
    assert sanitized["audit_provider_calls"] == rejected_index
    assert sanitized["role_guard_rejected_counts"][rejected_role] == 1
    assert sanitized["role_dispatched_call_counts"][rejected_role] == 0
    assert sanitized["role_request_sha256"][rejected_role] == hashlib.sha256(rejected_role.encode()).hexdigest()


@pytest.mark.parametrize("role", ("source_auditor", "claim_auditor"))
def test_openai_guard_rejection_preserves_request_hash_without_http_attempt(role):
    provider = OpenAIProvider({
        "kind": "openai_compatible", "base_url": "https://example.invalid/v1",
        "model": "fixture", "api_key_env": "AUDIT_TEST_KEY",
    })

    def reject(_raw):
        raise AuditPreflightError("audit_request_exceeds_limit")

    with pytest.raises(ProviderError) as caught:
        provider.audit_json(
            system=f"{role} fixture", user={"role": role}, schema={"type": "object"},
            limits={"max_output_tokens": 8}, contract_version="guard-test.v1", before_dispatch=reject,
        )
    exchange = caught.value.meta["audit_exchange"]
    assert exchange["dispatch_state"] == "guard_rejected"
    assert hashlib.sha256(exchange["request_bytes"]).hexdigest()
    assert exchange["response_bytes"] is None


def test_jev_guard_rejection_preserves_request_hash_without_transport_entry():
    transport_calls = []
    capture = _CapturingNativeCall(lambda *_args: transport_calls.append(True) or b"response", lambda _raw: (
        (_ for _ in ()).throw(AuditPreflightError("audit_request_exceeds_limit"))
    ))
    request = b'{"model":"fixture","questions":{}}'
    with pytest.raises(AuditPreflightError):
        capture(request, 1, 128)
    assert capture.dispatch_state == "guard_rejected"
    assert hashlib.sha256(capture.request_bytes).hexdigest() == hashlib.sha256(request).hexdigest()
    assert transport_calls == []


class _FakeHttpResponse:
    status = 200

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read1(self, size):
        body, self.body = self.body[:size], self.body[size:]
        return body


class _FakeHttpOpener:
    def __init__(self, body):
        self.body = body
        self.calls = 0

    def open(self, *_args, **_kwargs):
        self.calls += 1
        return _FakeHttpResponse(self.body)


def test_openai_success_receipt_confirms_http_attempt_at_opener_boundary(monkeypatch):
    opener = _FakeHttpOpener(json.dumps({
        "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}],
        "usage": {}, "model": "fixture",
    }).encode())
    monkeypatch.setattr(providers, "_HTTP_OPENER", opener)
    monkeypatch.setenv("AUDIT_TEST_KEY", "test-key-only")
    provider = OpenAIProvider({
        "kind": "openai_compatible", "base_url": "https://example.invalid/v1",
        "model": "fixture", "api_key_env": "AUDIT_TEST_KEY",
    })
    result = provider.audit_json(
        system="fixture", user={"role": "source_auditor"}, schema={"type": "object"},
        limits={"max_output_tokens": 8}, contract_version="guard-test.v1",
        before_dispatch=lambda _raw: None,
    )
    assert opener.calls == 1
    assert result["audit_exchange"]["dispatch_state"] == "http_attempted"


def test_openai_missing_credential_is_post_guard_pretransport_not_a_call(monkeypatch):
    monkeypatch.delenv("AUDIT_MISSING_KEY", raising=False)
    provider = OpenAIProvider({
        "kind": "openai_compatible", "base_url": "https://example.invalid/v1",
        "model": "fixture", "api_key_env": "AUDIT_MISSING_KEY",
    })
    with pytest.raises(ProviderError) as caught:
        provider.audit_json(
            system="fixture", user={"role": "source_auditor"}, schema={"type": "object"},
            limits={"max_output_tokens": 8}, contract_version="guard-test.v1",
            before_dispatch=lambda _raw: None,
        )
    exchange = caught.value.meta["audit_exchange"]
    assert exchange["dispatch_state"] == "post_guard_pretransport"
    assert hashlib.sha256(exchange["request_bytes"]).hexdigest()


def test_jev_success_receipt_confirms_http_attempt_at_opener_boundary(monkeypatch):
    opener = _FakeHttpOpener(b"{}")
    monkeypatch.setattr(claim_transport, "_HTTP_OPENER", opener)
    monkeypatch.setattr(claim_transport, "_parse_request", lambda _raw: {"model": "fixture"})
    monkeypatch.setenv("AUDIT_TEST_KEY", "test-key-only")
    transport = ClaimTransport({
        "endpoint": "http://127.0.0.1:12345/v1/systemone", "model": "fixture",
        "api_key_env": "AUDIT_TEST_KEY",
    })
    capture = _CapturingNativeCall(transport)
    assert capture(b'{"model":"fixture"}', 1, 128) == b"{}"
    assert opener.calls == 1
    assert capture.dispatch_state == "http_attempted"


def test_jev_missing_credential_is_post_guard_pretransport_not_a_call(monkeypatch):
    monkeypatch.setattr(claim_transport, "_parse_request", lambda _raw: {"model": "fixture"})
    monkeypatch.delenv("AUDIT_MISSING_KEY", raising=False)
    transport = ClaimTransport({
        "endpoint": "http://127.0.0.1:12345/v1/systemone", "model": "fixture",
        "api_key_env": "AUDIT_MISSING_KEY",
    })
    capture = _CapturingNativeCall(transport)
    with pytest.raises(ProviderError):
        capture(b'{"model":"fixture"}', 1, 128)
    assert capture.dispatch_state == "post_guard_pretransport"
    assert hashlib.sha256(capture.request_bytes).hexdigest()


def test_completed_sanitized_receipt_cannot_include_unconfirmed_role_call():
    receipt = {
        "schema": "model-only-shadow-audit-receipt.v1", "case_id": "PR-464",
        "terminal_state": "completed", "reason": "one_candidate_selected",
        "candidate_packet_count": 1, "selected_candidate_sha256": "c" * 64,
        "selected_packet_sha256": "a" * 64, "capture_manifest_sha256": "b" * 64,
        "shadow_manifest_sha256": "d" * 64,
        "roles": {role: "completed" for role in AUDIT_ROLES},
        **_receipt_dispatch_fields({role: {
            "attempted": 1, "dispatched": 1, "guard_rejected": 0,
            "post_guard_pretransport": 0, "unknown": 0, "request_sha256": str(index) * 64,
        } for index, role in enumerate(AUDIT_ROLES, 1)}),
    }
    receipt["role_dispatched_call_counts"]["jev"] = 0
    receipt["role_guard_rejected_counts"]["jev"] = 1
    receipt["audit_provider_calls"] = 2
    with pytest.raises(SANITIZER.ReceiptError, match="terminal_role_accounting_mismatch"):
        SANITIZER._valid(receipt)
