from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

import pr_review_harness.current_source_capture as capture
from pr_review_harness.current_source_capture import (
    LIMITS,
    TARGET,
    TASK_LENSES,
    CurrentSourceCaptureError,
    _canonical,
    create_plan,
    installed_module_inventory,
    validate_plan,
)


def _request(task_id: str, index: int) -> dict:
    return {
        "admitted": True,
        "context_omissions": [],
        "evidence_bindings": [],
        "evidence_ids": [],
        "input_bytes": (50_000 + index),
        "input_sha256": hashlib.sha256(f"writer:{task_id}".encode()).hexdigest(),
        "lens": TASK_LENSES[task_id],
        "obligation_ids": [],
        "output_bytes_cap": LIMITS["writer_max_response_bytes"],
        "output_tokens_cap": LIMITS["writer_max_output_tokens"],
        "request_input_contract": "specialist-input.v1",
        "required_context_ids": [],
        "required_context_omissions": [],
        "task_id": task_id,
        "unit_evidence_bindings": [],
        "unit_ids": [],
    }


def _prepared() -> dict:
    requests = [_request(task_id, index) for index, task_id in enumerate(TASK_LENSES)]
    source_rows = [
        {"task_id": task_id, "input_bytes": 20_000 + index,
         "input_sha256": hashlib.sha256(f"source:{task_id}".encode()).hexdigest(), "admitted": True}
        for index, task_id in enumerate(TASK_LENSES)
    ]
    return {
        "status": "PREPARED_ONLY", "disposition": None,
        "no_provider_calls": True, "no_target_code_execution": True,
        "snapshot": {
            "base_sha": TARGET["base_sha"], "head_sha": TARGET["head_sha"],
            "snapshot_id": TARGET["snapshot_id"], "snapshot_hash": TARGET["snapshot_sha256"],
            "evidence_index_sha256": TARGET["evidence_index_sha256"],
            "profile_version": TARGET["profile_version"],
            "profile_file_sha256": TARGET["profile_file_sha256"],
            "provider_identity_sha256": "a" * 64,
        },
        "checks": {
            "check_evidence_hash": TARGET["check_evidence_sha256"],
            "historical_check_identity": {"check_document_sha256": TARGET["historical_checks_sha256"]},
        },
        "scope": {"coverage_obligations": [{} for _ in range(TARGET["scope_obligations"])]},
        "primary_requests": requests,
        "capacity": {
            "exact_primary_call_demand": len(requests),
            "exact_primary_serialized_input_bytes": sum(row["input_bytes"] for row in requests),
            "configured_max_provider_calls": LIMITS["writer_max_provider_calls"],
            "configured_max_input_bytes_per_task": LIMITS["writer_max_request_bytes"],
            "source_audit_preflight": {
                "active_input_limit_bytes": LIMITS["audit_max_input_bytes_per_call"],
                "request_count": len(source_rows),
                "request_bytes_max": max(row["input_bytes"] for row in source_rows),
                "requests": source_rows,
                "status": "ADMITTED",
            },
        },
    }


def _plan(prepared: dict | None = None):
    prepared = _prepared() if prepared is None else prepared
    raw = _canonical(prepared)
    return create_plan(prepared, source_sha="1" * 40,
                       module_inventory=installed_module_inventory(), prepared_raw=raw)


def test_current_source_plan_binds_fixed_target_runtime_requests_and_receipt():
    plan, receipt = _plan()
    pins, snapshot = validate_plan(
        plan, receipt, source_sha="1" * 40, module_inventory=installed_module_inventory(),
    )
    assert len(pins) == 6
    assert snapshot == {
        "case_id": "PR-457", "snapshot_id": TARGET["snapshot_id"],
        "snapshot_sha256": TARGET["snapshot_sha256"],
        "audit_max_input_bytes_per_call": LIMITS["audit_max_input_bytes_per_call"],
        "provider_identity_sha256": "a" * 64,
        "source_audit_requests": {row["task_id"]: row for row in plan["source_audit_requests"]},
    }
    assert sum(row["input_bytes"] for row in plan["writer_requests"]) == 300_015


@pytest.mark.parametrize("mutation", [
    "wrong_source", "wrong_head", "wrong_profile", "extra_request", "mutated_request_hash",
    "wrong_module", "receipt_plan_hash", "boolean_provider_calls", "source_request_too_large",
])
def test_current_source_plan_rejects_identity_budget_and_receipt_mutations(mutation: str):
    plan, receipt = _plan()
    plan = copy.deepcopy(plan)
    receipt = copy.deepcopy(receipt)
    source_sha = "1" * 40
    inventory = installed_module_inventory()
    if mutation == "wrong_source":
        source_sha = "2" * 40
    elif mutation == "wrong_head":
        plan["target"] = {**plan["target"], "head_sha": "2" * 40}
    elif mutation == "wrong_profile":
        plan["target"] = {**plan["target"], "profile_file_sha256": "2" * 64}
    elif mutation == "extra_request":
        plan["writer_requests"].append(copy.deepcopy(plan["writer_requests"][0]))
    elif mutation == "mutated_request_hash":
        plan["writer_requests"][0]["input_sha256"] = "2" * 64
    elif mutation == "wrong_module":
        inventory = {**inventory, "pr_review_harness/cli.py": "2" * 64}
    elif mutation == "receipt_plan_hash":
        receipt["plan_sha256"] = "2" * 64
    elif mutation == "boolean_provider_calls":
        receipt["provider_calls"] = False
    elif mutation == "source_request_too_large":
        plan["source_audit_requests"][0]["input_bytes"] = LIMITS["audit_max_input_bytes_per_call"] + 1
        receipt["plan_sha256"] = hashlib.sha256(_canonical(plan)).hexdigest()
    with pytest.raises(CurrentSourceCaptureError):
        validate_plan(plan, receipt, source_sha=source_sha, module_inventory=inventory)


def test_prepare_rejects_duplicate_or_unbound_input_bytes():
    prepared = _prepared()
    with pytest.raises(CurrentSourceCaptureError, match="prepared_input_binding_invalid"):
        create_plan(prepared, source_sha="1" * 40,
                    module_inventory=installed_module_inventory(), prepared_raw=b'{"status":"bad"}')
    duplicate = b'{"status":"PREPARED_ONLY","status":"PREPARED_ONLY"}'
    with pytest.raises(CurrentSourceCaptureError):
        create_plan(prepared, source_sha="1" * 40,
                    module_inventory=installed_module_inventory(), prepared_raw=duplicate)


def test_plan_rejects_writer_request_over_existing_cap_and_source_omission():
    prepared = _prepared()
    prepared["primary_requests"][0]["input_bytes"] = LIMITS["writer_max_request_bytes"] + 1
    prepared["capacity"]["exact_primary_serialized_input_bytes"] = sum(
        row["input_bytes"] for row in prepared["primary_requests"]
    )
    with pytest.raises(CurrentSourceCaptureError):
        _plan(prepared)
    prepared = _prepared()
    prepared["capacity"]["source_audit_preflight"]["requests"].pop()
    with pytest.raises(CurrentSourceCaptureError):
        _plan(prepared)


@pytest.mark.parametrize("obligations", [None, {}, "14", 14])
def test_prepare_rejects_malformed_obligation_collection(obligations):
    prepared = _prepared()
    prepared["scope"]["coverage_obligations"] = obligations
    with pytest.raises(CurrentSourceCaptureError, match="prepared_checks_or_scope_mismatch"):
        _plan(prepared)


def _inventory_root(monkeypatch, tmp_path: Path) -> Path:
    package = tmp_path / "pr_review_harness"
    package.mkdir()
    monkeypatch.setattr(capture, "__file__", str(package / "__init__.py"))
    return package


def test_installed_inventory_rejects_symlink_files(monkeypatch, tmp_path):
    package = _inventory_root(monkeypatch, tmp_path)
    (package / "module.py").write_text("safe", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("outside", encoding="utf-8")
    (package / "linked.py").symlink_to(outside)
    with pytest.raises(CurrentSourceCaptureError, match="runtime_inventory_symlink"):
        installed_module_inventory()


def test_installed_inventory_enforces_file_and_aggregate_byte_caps(monkeypatch, tmp_path):
    package = _inventory_root(monkeypatch, tmp_path)
    monkeypatch.setattr(capture, "MAX_RUNTIME_FILE_BYTES", 4)
    (package / "large.py").write_bytes(b"12345")
    with pytest.raises(CurrentSourceCaptureError, match="runtime_inventory_limit_exceeded"):
        installed_module_inventory()

    (package / "large.py").unlink()
    monkeypatch.setattr(capture, "MAX_RUNTIME_FILE_BYTES", 10)
    monkeypatch.setattr(capture, "MAX_RUNTIME_TOTAL_BYTES", 5)
    (package / "one.py").write_bytes(b"123")
    (package / "two.py").write_bytes(b"456")
    with pytest.raises(CurrentSourceCaptureError, match="runtime_inventory_limit_exceeded"):
        installed_module_inventory()


def test_installed_inventory_enforces_file_count_cap(monkeypatch, tmp_path):
    package = _inventory_root(monkeypatch, tmp_path)
    monkeypatch.setattr(capture, "MAX_RUNTIME_FILES", 2)
    for name in ("a.py", "b.py", "c.py"):
        (package / name).write_text(name, encoding="utf-8")
    with pytest.raises(CurrentSourceCaptureError, match="runtime_inventory_limit_exceeded"):
        installed_module_inventory()


def test_installed_inventory_bounds_directory_entries(monkeypatch, tmp_path):
    package = _inventory_root(monkeypatch, tmp_path)
    monkeypatch.setattr(capture, "MAX_RUNTIME_ENTRIES", 2)
    for name in ("a.py", "b.py", "c.py"):
        (package / name).write_text(name, encoding="utf-8")
    with pytest.raises(CurrentSourceCaptureError, match="runtime_inventory_limit_exceeded"):
        installed_module_inventory()


def test_installed_inventory_rejects_file_growth_during_open(monkeypatch, tmp_path):
    package = _inventory_root(monkeypatch, tmp_path)
    changing = package / "changing.py"
    changing.write_bytes(b"small")
    real_open = capture.os.open
    grew = False

    def grow_before_open(path, flags, *args, **kwargs):
        nonlocal grew
        if Path(path) == changing and not grew:
            grew = True
            changing.write_bytes(b"larger")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(capture.os, "open", grow_before_open)
    with pytest.raises(CurrentSourceCaptureError, match="runtime_inventory_changed"):
        installed_module_inventory()
