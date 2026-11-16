from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FINALIZER_SCRIPT = ROOT / "scripts/finalize_model_only_shadow_live_plans_v3.py"
sys.path.insert(0, str(ROOT / "scripts"))
import finalize_model_only_shadow_live_plans_v3 as finalizer  # noqa: E402


def _prepared(case_id: str) -> dict:
    case = finalizer.CASES[case_id]
    proposal_path = ROOT / (
        "experiments/model-only-shadow-live-pr457-plan-v3-proposal.json"
        if case_id == "PR-457"
        else "experiments/model-only-shadow-live-pr464-plan-v3-proposal.json"
    )
    proposal = json.loads(proposal_path.read_text())
    identity = proposal["case"]
    old_plan = json.loads((ROOT / case["old_plan"]).read_text())
    writer_requests = proposal.get("writer_requests")
    if writer_requests is None:
        writer_requests = old_plan["writer_requests"]
    runtime = proposal.get("runtime", old_plan["runtime"])

    def ident(key):
        return identity.get(key, old_plan["case"].get(key))

    primary = [{**row, "admitted": True} for row in writer_requests]
    source_rows = proposal.get("source_audit_preflight", {}).get("requests")
    if source_rows is None:
        source_rows = [
            {
                "task_id": row["task_id"],
                "input_bytes": 113_860 if case_id == "PR-457" and index < 3 else 70_000 + index,
                "input_sha256": hashlib.sha256(f"{case_id}-{index}".encode()).hexdigest(),
                "admitted": True,
            }
            for index, row in enumerate(primary)
        ]
    else:
        source_rows = [{**row, "admitted": True} for row in source_rows]
    return {
        "command": "review",
        "status": "PREPARED_ONLY",
        "no_provider_calls": True,
        "no_target_code_execution": True,
        "disposition": None,
        "snapshot": {
            "base_sha": identity["base_sha"],
            "head_sha": identity["head_sha"],
            "snapshot_id": identity["snapshot_id"],
            "snapshot_hash": identity["snapshot_sha256"],
            "evidence_index_sha256": ident("evidence_index_sha256"),
            "profile_version": ident("profile_version"),
            "profile_file_sha256": ident("profile_file_sha256"),
            "provider_identity_sha256": runtime["provider_identity_sha256"],
        },
        "checks": {
            "historical_check_identity": {"check_document_sha256": ident("historical_checks_sha256")},
            "check_evidence_hash": ident("check_evidence_sha256"),
        },
        "scope": {"coverage_obligations": [{} for _ in range(case["scope_obligations"])]},
        "capacity": {
            "source_audit_preflight": {
                "active_input_limit_bytes": case["audit_cap"],
                "status": "ADMITTED",
                "request_count": len(source_rows),
                "request_bytes_max": max(row["input_bytes"] for row in source_rows),
                "requests": source_rows,
            },
        },
        "primary_requests": primary,
    }


@pytest.mark.parametrize("case_id", ["PR-457", "PR-464"])
def test_v3_plan_finalizer_binds_provider_free_requests_and_case_budget(case_id: str):
    prepared = _prepared(case_id)
    plan = finalizer._plan(case_id, prepared, "a" * 40, 35, "b" * 64)
    assert plan["schema"] == "model-only-shadow-live-writer-plan.v2"
    assert len(plan["writer_requests"]) == finalizer.CASES[case_id]["calls"]
    assert plan["budget"]["audit_max_input_bytes_per_call"] == finalizer.CASES[case_id]["audit_cap"]
    assert plan["runtime"]["plan_generated_from_revision"] == "a" * 40
    assert plan["runtime"]["module_tree_sha256"] == "b" * 64
    plan_sha = hashlib.sha256(json.dumps(plan, indent=2, ensure_ascii=False).encode() + b"\n").hexdigest()
    corpus_raw, manifest_raw = finalizer._identity_copy(case_id, plan, plan_sha)
    corpus = json.loads(corpus_raw)
    manifest = json.loads(manifest_raw)
    assert corpus["corpus_id"] == f"model-only-shadow-{case_id.replace('-', '').lower()}-v3"
    assert manifest["plan_path"] == finalizer.CASES[case_id]["plan"]
    assert manifest["plan_sha256"] == plan_sha
    assert corpus["cases"][0]["identity"]["source_manifest"]["sha256"] == plan_sha


def test_v3_plan_finalizer_rejects_dispatch_and_over_cap_source_prepares():
    prepared = _prepared("PR-464")
    prepared["no_provider_calls"] = False
    with pytest.raises(finalizer.FinalizeError, match="provider_free_prepare_required"):
        finalizer._plan("PR-464", prepared, "a" * 40, 35, "b" * 64)

    prepared = _prepared("PR-457")
    assert prepared["capacity"]["source_audit_preflight"]["request_bytes_max"] == 113_860
    finalizer._plan("PR-457", prepared, "a" * 40, 35, "b" * 64)
    prepared["capacity"]["source_audit_preflight"]["requests"][0]["input_bytes"] = 120_001
    with pytest.raises(finalizer.FinalizeError, match="source_audit_request_invalid"):
        finalizer._plan("PR-457", prepared, "a" * 40, 35, "b" * 64)


def test_frozen_finalizer_rejects_current_policy_before_writing_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    prepared_paths = {}
    for case_id in ("PR-457", "PR-464"):
        path = tmp_path / f"{case_id}.json"
        path.write_text(json.dumps(_prepared(case_id)), encoding="utf-8")
        prepared_paths[case_id] = path

    isolated_root = tmp_path / "isolated-repository"
    isolated_scripts = isolated_root / "scripts"
    isolated_experiments = isolated_root / "experiments"
    isolated_scripts.mkdir(parents=True)
    isolated_experiments.mkdir()
    policy_path = isolated_scripts / "shadow_case_policy.py"
    verifier_path = isolated_scripts / "verify_model_only_shadow_live_preflight.py"
    limits_path = isolated_experiments / "model-only-shadow-live-writer-limits-v1.json"
    provider_path = isolated_experiments / "model-only-shadow-live-writer-provider-v1.json"
    policy_path.write_bytes(finalizer.POLICY_PATH.read_bytes())
    verifier_path.write_bytes(finalizer.VERIFIER_PATH.read_bytes())
    limits_path.write_bytes(finalizer.LIMITS_PATH.read_bytes())
    provider_path.write_bytes(finalizer.PROVIDER_PATH.read_bytes())

    monkeypatch.setattr(finalizer, "ROOT", isolated_root)
    monkeypatch.setattr(finalizer, "POLICY_PATH", policy_path)
    monkeypatch.setattr(finalizer, "VERIFIER_PATH", verifier_path)
    monkeypatch.setattr(finalizer, "LIMITS_PATH", limits_path)
    monkeypatch.setattr(finalizer, "PROVIDER_PATH", provider_path)
    monkeypatch.setattr(finalizer, "_source_identity", lambda _revision: (35, "b" * 64))

    outputs = [policy_path, verifier_path]
    for case in finalizer.CASES.values():
        outputs.extend(isolated_root / case[key] for key in ("plan", "corpus", "manifest"))
    outputs.extend(
        isolated_root / f"experiments/model-only-shadow-live-pr{case_id[3:]}-plan-v3-evidence.json"
        for case_id in ("PR-457", "PR-464")
    )
    before_exists = {path: path.exists() for path in outputs}
    before = {path: path.read_bytes() for path in outputs if path.exists()}

    with pytest.raises(finalizer.FinalizeError, match="case_policy_pin_placeholder_missing"):
        finalizer.finalize(prepared_paths, revision="a" * 40)

    assert {path: path.read_bytes() for path in outputs if path.exists()} == before
    assert {path: path.exists() for path in outputs} == before_exists


def _isolated_finalizer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, verifier_source: str
) -> tuple[dict[str, Path], list[Path], Path]:
    isolated_root = tmp_path / "isolated-finalizer"
    isolated_scripts = isolated_root / "scripts"
    isolated_experiments = isolated_root / "experiments"
    isolated_scripts.mkdir(parents=True)
    isolated_experiments.mkdir()
    policy_path = isolated_scripts / "shadow_case_policy.py"
    verifier_path = isolated_scripts / "verify_model_only_shadow_live_preflight.py"
    limits_path = isolated_experiments / "model-only-shadow-live-writer-limits-v1.json"
    provider_path = isolated_experiments / "model-only-shadow-live-writer-provider-v1.json"
    policy_path.write_text(
        '"PR-457": {\n  "plan_sha256": "PENDING_FINAL_V3_PLAN_SHA256"\n}\n'
        '"PR-464": {\n  "plan_sha256": "PENDING_FINAL_V3_PLAN_SHA256"\n}\n',
        encoding="utf-8",
    )
    verifier_path.write_text(verifier_source, encoding="utf-8")
    limits_path.write_text("{}", encoding="utf-8")
    provider_path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(finalizer, "ROOT", isolated_root)
    monkeypatch.setattr(finalizer, "POLICY_PATH", policy_path)
    monkeypatch.setattr(finalizer, "VERIFIER_PATH", verifier_path)
    monkeypatch.setattr(finalizer, "LIMITS_PATH", limits_path)
    monkeypatch.setattr(finalizer, "PROVIDER_PATH", provider_path)
    monkeypatch.setattr(finalizer, "_source_identity", lambda _revision: (35, "b" * 64))
    monkeypatch.setattr(finalizer, "_identity_copy", lambda _case, _plan, _sha: (b"{}\n", b"{}\n"))

    prepared_paths: dict[str, Path] = {}
    for case_id in ("PR-457", "PR-464"):
        prepared_path = tmp_path / f"prepared-{case_id}.json"
        prepared_path.write_text(json.dumps(_prepared(case_id)), encoding="utf-8")
        prepared_paths[case_id] = prepared_path
    outputs = [policy_path, verifier_path]
    for case in finalizer.CASES.values():
        outputs.extend(isolated_root / case[key] for key in ("plan", "corpus", "manifest"))
    outputs.extend(
        isolated_root / f"experiments/model-only-shadow-live-pr{case_id[3:]}-plan-v3-evidence.json"
        for case_id in ("PR-457", "PR-464")
    )
    return prepared_paths, outputs, verifier_path


def _verifier_with_old_assignment(assignment: str) -> str:
    return (
        "EXPECTED_MODULE_COUNT = 35\n"
        f"{assignment}\n"
        'if runtime.get("plan_generated_from_revision") != "' + "c" * 40 + '":\n    pass\n'
    )


def test_finalizer_replaces_the_exact_historical_module_tree_assignment_in_isolated_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assignment = finalizer._old_module_tree_assignment()
    prepared_paths, outputs, verifier_path = _isolated_finalizer(
        monkeypatch, tmp_path, _verifier_with_old_assignment(assignment)
    )
    result = finalizer.finalize(prepared_paths, revision="a" * 40)
    assert result["module_tree_sha256"] == "b" * 64
    assert 'EXPECTED_MODULE_TREE_SHA256 = "' + "b" * 64 + '"' in verifier_path.read_text(encoding="utf-8")
    assert all(path.exists() for path in outputs)


@pytest.mark.parametrize("assignment_mode", ["wrong", "duplicate"])
def test_finalizer_rejects_wrong_or_duplicate_historical_assignment_without_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, assignment_mode: str
) -> None:
    exact = finalizer._old_module_tree_assignment()
    assignment = exact if assignment_mode == "duplicate" else exact.replace("3a891f5c", "0a891f5c")
    source = _verifier_with_old_assignment(assignment)
    if assignment_mode == "duplicate":
        source += exact + "\n"
    prepared_paths, outputs, _verifier_path = _isolated_finalizer(monkeypatch, tmp_path, source)
    before_exists = {path: path.exists() for path in outputs}
    before = {path: path.read_bytes() for path in outputs if path.exists()}

    with pytest.raises(finalizer.FinalizeError, match="module_tree_constant_invalid"):
        finalizer.finalize(prepared_paths, revision="a" * 40)

    assert {path: path.exists() for path in outputs} == before_exists
    assert {path: path.read_bytes() for path in outputs if path.exists()} == before


def test_finalizer_pin_resource_failure_precedes_identity_work_and_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exact = finalizer._old_module_tree_assignment()
    prepared_paths, outputs, _verifier_path = _isolated_finalizer(
        monkeypatch, tmp_path, _verifier_with_old_assignment(exact)
    )
    broken_resource = tmp_path / "bad-compatibility-pins.json"
    broken_resource.write_text("not-json", encoding="utf-8")
    original_pin = finalizer.compatibility_pins.pin

    def invalid_resource_pin(name: str) -> str:
        return original_pin(name, path=broken_resource)

    monkeypatch.setattr(finalizer.compatibility_pins, "pin", invalid_resource_pin)
    monkeypatch.setattr(finalizer, "_source_identity", lambda _revision: pytest.fail("identity work ran"))
    before_exists = {path: path.exists() for path in outputs}
    before = {path: path.read_bytes() for path in outputs if path.exists()}

    with pytest.raises(finalizer.FinalizeError, match="module_tree_pin_unavailable"):
        finalizer.finalize(prepared_paths, revision="a" * 40)

    assert {path: path.exists() for path in outputs} == before_exists
    assert {path: path.read_bytes() for path in outputs if path.exists()} == before


def test_finalizer_imports_and_loads_named_pin_from_source_checkout_without_pythonpath(tmp_path: Path) -> None:
    code = (
        "import runpy; namespace = runpy.run_path("
        f"{str(FINALIZER_SCRIPT)!r}, "
        "run_name='standalone_import'); "
        "assert namespace['_old_module_tree_assignment']() == "
        f"{finalizer._old_module_tree_assignment()!r}"
    )
    completed = subprocess.run(
        [sys.executable, "-S", "-c", code],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
