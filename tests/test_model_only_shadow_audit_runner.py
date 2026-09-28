from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
from pathlib import Path

import pytest

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


def _plan(task_ids: list[str]) -> dict:
    return {"schema": "model-only-shadow-live-writer-plan.v1",
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
    assert RUNNER.DEFAULT_PLAN == REPO_ROOT / "experiments/model-only-shadow-live-pr464-plan-v1.json"
    plan_path = REPO_ROOT / RUNNER.CASE_POLICY["PR-457"]["plan_relative_path"]
    plan_raw = plan_path.read_bytes()
    plan = json.loads(plan_raw)
    case_id, policy = POLICY_PATH_RESOLVER(plan_path, REPO_ROOT)
    validated_case_id, validated_policy = POLICY_VALIDATOR(plan, plan_raw)
    assert case_id == validated_case_id == "PR-457"
    assert policy == validated_policy
    assert plan["prepare_contract"]["profile_path"] == policy["profile_path"]
    assert hashlib.sha256((REPO_ROOT / policy["profile_path"]).read_bytes()).hexdigest() == policy["profile_sha256"]


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
        "roles": {role: "not_run" for role in ("source_auditor", "jev", "claim_auditor")},
        "role_call_counts": {role: 0 for role in ("source_auditor", "jev", "claim_auditor")},
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


def test_sanitizer_rejects_contradictory_terminal_call_and_candidate_accounting():
    receipt = {
        "schema": "model-only-shadow-audit-receipt.v1", "case_id": "PR-464",
        "terminal_state": "completed", "reason": "one_candidate_selected",
        "audit_provider_calls": 3, "candidate_packet_count": 1,
        "selected_candidate_sha256": "c" * 64, "selected_packet_sha256": "a" * 64,
        "capture_manifest_sha256": "b" * 64, "shadow_manifest_sha256": "d" * 64,
        "roles": {role: "completed" for role in ("source_auditor", "jev", "claim_auditor")},
        "role_call_counts": {role: 1 for role in ("source_auditor", "jev", "claim_auditor")},
    }
    SANITIZER._valid(receipt)
    invalid = dict(receipt, reason="no_writer_candidate")
    with pytest.raises(SANITIZER.ReceiptError, match="candidate_selection_reason_mismatch"):
        SANITIZER._valid(invalid)
    invalid = dict(receipt, audit_provider_calls=2)
    with pytest.raises(SANITIZER.ReceiptError, match="receipt_role_call_counts_invalid"):
        SANITIZER._valid(invalid)
    invalid = dict(receipt, terminal_state="source_audit_failed")
    with pytest.raises(SANITIZER.ReceiptError, match="terminal_role_accounting_mismatch"):
        SANITIZER._valid(invalid)
