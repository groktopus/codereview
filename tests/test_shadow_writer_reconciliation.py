from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import sanitize_model_only_shadow_reconciliation as reconciliation  # noqa: E402
import test_seeded_writer_synth_001_harness as seeded  # noqa: E402

from pr_review_harness.engine import _evidence_for, prepare_plan_tasks, run_review  # noqa: E402
from pr_review_harness.planner import plan_review  # noqa: E402
from pr_review_harness.snapshot import collect_snapshot  # noqa: E402


def _deterministic_check_fixture():
    snapshot_hash = "a" * 64
    evidence_id = "check-" + "b" * 24
    task_id = "task-check-fixed"
    binding = {
        "task_id": task_id,
        "check_id": "portal-contract",
        "check_binding_id": "external:portal-contract",
        "expected_evidence_id": evidence_id,
        "expected_outcome": "FINDINGS",
        "expected_input_hash": "c" * 64,
        "lens": "project_specific",
        "unit_ids": ["unit-98ecf75f7878cd37c560"],
    }
    payload = {
        "check_id": binding["check_id"], "outcome": binding["expected_outcome"],
        "finding_candidates": [], "evidence_refs": [evidence_id], "diagnostics": [],
    }
    expected_input_hash = binding["expected_input_hash"]
    output = {
        "task_id": task_id, "task_kind": "DETERMINISTIC_CHECK", "lens": binding["lens"],
        "unit_ids": binding["unit_ids"], "status": "SUCCEEDED", "input_evidence_ids": [evidence_id],
        "input_hash": expected_input_hash, "payload": payload,
        "output_hash": reconciliation.digest(reconciliation.canonical(payload)), "attempts": 1,
    }
    return snapshot_hash, {task_id: binding}, {task_id: output}


def test_deterministic_check_projection_binds_exact_snapshot_evidence_and_attempt():
    snapshot_hash, check_tasks, outputs = _deterministic_check_fixture()
    reconciliation.validate_deterministic_check_rows(outputs, outputs, check_tasks, snapshot_hash)

    for field, value in (("input_hash", "d" * 64), ("input_evidence_ids", []), ("attempts", True)):
        mutated = {task_id: {**row, field: value} for task_id, row in outputs.items()}
        with pytest.raises(reconciliation.ReconciliationError, match="check_task_output_invalid"):
            reconciliation.validate_deterministic_check_rows(mutated, mutated, check_tasks, snapshot_hash)

    with pytest.raises(reconciliation.ReconciliationError, match="check_task_binding_invalid"):
        reconciliation.validate_deterministic_check_rows({}, outputs, check_tasks, snapshot_hash)


class _SingleCandidateProvider(seeded._SerializedFixtureProvider):
    def __init__(self, *, missing_title: bool, mixed_candidates: bool = False):
        super().__init__(candidate_enabled=True)
        self.missing_title = missing_title
        self.mixed_candidates = mixed_candidates

    def _fixture_payload(self, task, evidence):
        self.candidate_enabled = task["task_id"].startswith("synth-task-00")
        payload = super()._fixture_payload(task, evidence)
        if self.missing_title and payload["finding_candidates"]:
            payload["finding_candidates"][0].pop("title")
        if self.mixed_candidates and payload["finding_candidates"]:
            invalid = {**payload["finding_candidates"][0]}
            invalid.pop("title")
            valid = {**payload["finding_candidates"][0]}
            payload["finding_candidates"] = [invalid, valid]
        return payload


def _synthetic_run(
    tmp_path: Path, *, missing_title: bool = False, mixed_candidates: bool = False
) -> dict:
    repo, base, head, profile = seeded._synthetic_repo(tmp_path / "repo", seeded_defect=True)
    snapshot = collect_snapshot(str(repo), base, head, profile, seeded.LIMITS)
    provider = _SingleCandidateProvider(
        missing_title=missing_title, mixed_candidates=mixed_candidates
    )
    plan = plan_review(snapshot, profile, "AUTO")
    original_task = plan["tasks"][0]
    original_obligation = plan["coverage_obligations"][0]
    plan["tasks"] = [
        {
            **original_task,
            "task_id": f"synth-task-{index:02d}",
            "scope_id": f"synth-scope-{index:02d}",
            "obligation_id": f"synth-obligation-{index:02d}",
            "obligation_ids": [f"synth-obligation-{index:02d}"],
        }
        for index in range(10)
    ]
    plan["coverage_obligations"] = [
        {**original_obligation, "obligation_id": f"synth-obligation-{index:02d}"}
        for index in range(10)
    ]
    limits = {
        **seeded.LIMITS,
        "max_provider_calls": 10,
        "max_context_bytes": 300_000,
        "max_retries_per_task": 0,
        "max_followup_tasks": 0,
        "max_output_tokens": 1_800,
        "max_output_bytes_per_task": 16_000,
    }
    tasks, _skipped = prepare_plan_tasks(snapshot, plan, profile, limits, provider)
    assert len(tasks) == 10
    request_rows = []
    request_pins = {}
    task_evidence = {}
    for task in tasks:
        evidence = _evidence_for(task, snapshot, limits["max_input_bytes_per_task"])
        request_bytes = provider.serialize_review_request(task, evidence, limits)
        task_evidence[task["task_id"]] = (task, evidence)
        request_rows.append({
            "task_id": task["task_id"],
            "lens": task["lens"],
            "input_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "input_bytes": len(request_bytes),
        })
        request_pins[task["task_id"]] = {
            "task_id": task["task_id"],
            "input_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "input_bytes": len(request_bytes),
            "lens": task["lens"],
            "output_bytes_cap": 16_000,
            "output_tokens_cap": 1_800,
        }
    capture_root = tmp_path / "capture"
    result = run_review(
        snapshot, plan, profile, provider, None, limits, str(tmp_path / "results"),
        "writer-live-synth-001", max_claim_assessments=0,
        private_capture_dir=str(capture_root), private_capture_case_id="SYNTH-001",
        private_capture_request_pins=request_pins,
        private_capture_snapshot_pin={
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_sha256": snapshot["snapshot_hash"],
        },
    )
    # Re-read the exact persisted CLI/engine result bytes used by the reconciler.
    result_path = tmp_path / "results" / "writer-live-synth-001.json"
    result = json.loads(result_path.read_bytes())
    manifest_raw = (capture_root / "manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    outcomes_rows = []
    response_payloads = {}
    packet_pairs = set()
    for call in manifest["calls"]:
        response_raw = (capture_root / "responses" / f"{call['call_id']}.bin").read_bytes()
        response = json.loads(response_raw)
        response_sha = hashlib.sha256(response_raw).hexdigest()
        outcomes_rows.append({
            "task_id_sha256": hashlib.sha256(call["task_id"].encode()).hexdigest(),
            "response_sha256": response_sha,
            "returned_candidate_count": len(response["finding_candidates"]),
        })
        response_payloads[call["task_id"]] = (response_sha, response)
    # Bind the plan to the actual chunk-level calls emitted by run_review.
    # The engine may split a logical planned task into one or more calls.
    plan_wire = {
        "case": {
            "case_id": "SYNTH-001",
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_sha256": snapshot["snapshot_hash"],
        },
        "writer_requests": [
            {
                "task_id": call["task_id"],
                "input_sha256": call["request_sha256"],
            }
            for call in manifest["calls"]
        ],
    }
    plan_sha = hashlib.sha256(
        json.dumps(plan_wire, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    for row in manifest["case_packet_inventory"]["packets"]:
        packet = json.loads((capture_root / "case-packets" / row["path"]).read_bytes())
        candidate = packet.get("writer_candidate")
        if candidate is not None:
            packet_pairs.add((candidate["candidate_id"], packet["source_task"]["task_id"]))
    manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
    outcomes = {
        "capture_manifest_sha256": manifest_sha,
        "tasks": outcomes_rows,
    }
    plan = plan_wire
    manifest["_capture_root"] = str(capture_root)
    writer_receipt = {
        "plan_sha256": plan_sha,
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_sha256": snapshot["snapshot_hash"],
        "writer_call_count": len(tasks),
        "calls": [
            {
                "task_id": call["task_id"],
                "request_sha256": call["request_sha256"],
                "response_sha256": call["response_sha256"],
            }
            for call in manifest["calls"]
        ],
        "target_code_execution": False,
        "publication_enabled": False,
    }
    return {
        "result": result,
        "ledger": result["ledger"],
        "outcomes": outcomes,
        "manifest": manifest,
        "response_payloads": response_payloads,
        "packet_pairs": packet_pairs,
        "plan": plan,
        "writer_receipt": writer_receipt,
        "plan_sha": plan_sha,
        "manifest_sha": manifest_sha,
        "writer_receipt_sha": hashlib.sha256(b"test-sanitized-writer-receipt").hexdigest(),
        "result_path": result_path,
        "capture_root": capture_root,
        "task_evidence": task_evidence,
    }


def _project(
    tmp_path: Path, *, missing_title: bool = False, mixed_candidates: bool = False
) -> tuple[dict, dict]:
    values = _synthetic_run(
        tmp_path, missing_title=missing_title, mixed_candidates=mixed_candidates
    )
    receipt = reconciliation.build_receipt(
        values["result"], values["ledger"], values["outcomes"], values["manifest"],
        values["response_payloads"], values["packet_pairs"], values["plan"],
        values["writer_receipt"], values["result"]["result_hash"],
        values["plan_sha"], values["manifest_sha"], values["writer_receipt_sha"],
    )
    return receipt, values


def test_seeded_valid_candidate_is_bound_to_result_and_private_packet_without_text(tmp_path):
    receipt, values = _project(tmp_path)

    assert receipt["schema"] == "model-only-shadow-writer-reconciliation.v1"
    assert receipt["status"] == "PROJECTION_COMPLETE"
    assert receipt["snapshot_sha256"] == values["plan"]["case"]["snapshot_sha256"]
    assert receipt["result_sha256"] == values["result"]["result_hash"]
    assert receipt["returned_candidate_count_total"] == 1
    assert receipt["packet_candidate_count_total"] == 1
    candidate = next(
        candidate
        for task in receipt["tasks"]
        for candidate in task["candidates"]
    )
    assert candidate["record_provenance"] == "VERIFIED"
    assert candidate["in_reconciled_findings"] is True
    assert candidate["in_case_packet"] is True
    assert candidate["export_disposition"] == "EXPORTED"
    serialized = json.dumps(receipt, sort_keys=True)
    assert "Synthetic authorization bypass" not in serialized
    assert "caller may access another owner's document" not in serialized


def test_seeded_missing_title_is_reported_as_normalization_quarantine(tmp_path):
    receipt, values = _project(tmp_path, missing_title=True)

    assert receipt["returned_candidate_count_total"] == 1
    assert receipt["packet_candidate_count_total"] == 0
    candidate = next(
        candidate
        for task in receipt["tasks"]
        for candidate in task["candidates"]
    )
    assert candidate["record_provenance"] == "VERIFIED"
    assert candidate["in_reconciled_findings"] is False
    assert candidate["in_case_packet"] is False
    assert candidate["export_disposition"] == "NORMALIZATION_QUARANTINED"
    assert candidate["validation_state"] == "NOT_APPLICABLE"
    assert candidate["normalization_reason_code"] == "invalid_candidate_fields"
    assert candidate["missing_required_fields"] == []
    serialized = json.dumps(receipt, sort_keys=True)
    assert "Synthetic authorization bypass" not in serialized
    assert "The seeded change makes the authorization predicate unconditional." not in serialized
    assert "selector" not in serialized.lower()


def test_reconciliation_rejects_candidate_record_raw_mismatch(tmp_path):
    values = _synthetic_run(tmp_path)
    candidate_record = values["result"]["ledger"]["candidate_records"][0]
    candidate_record["raw"]["observation"] = "different content"
    unsigned = {key: value for key, value in values["result"].items() if key != "result_hash"}
    values["result"]["result_hash"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    with pytest.raises(reconciliation.ReconciliationError):
        reconciliation.build_receipt(
            values["result"], values["ledger"], values["outcomes"], values["manifest"],
            values["response_payloads"], values["packet_pairs"], values["plan"],
            values["writer_receipt"], values["result"]["result_hash"],
            values["plan_sha"], values["manifest_sha"], values["writer_receipt_sha"],
        )


def test_mixed_candidates_map_raw_ordinal_to_compact_engine_ordinal(tmp_path):
    receipt, values = _project(tmp_path, mixed_candidates=True)

    candidates = [candidate for task in receipt["tasks"] for candidate in task["candidates"]]
    assert [candidate["candidate_ordinal"] for candidate in candidates] == [0, 1]
    assert candidates[0]["export_disposition"] == "NORMALIZATION_QUARANTINED"
    assert candidates[0]["normalization_reason_code"] == "invalid_candidate_fields"
    assert candidates[0]["candidate_id_sha256"] is None
    assert candidates[0]["raw_candidate_sha256"] == reconciliation.raw_item_hash(
        values["response_payloads"]["synth-task-00:chunk-1"][1]["finding_candidates"][0]
    )

    task_id = "synth-task-00:chunk-1"
    accepted_raw = values["result"]["task_results"][task_id]["payload"]["finding_candidates"][0]
    accepted_id = reconciliation.candidate_id(task_id, 0, accepted_raw)
    assert candidates[1]["candidate_id_sha256"] == hashlib.sha256(accepted_id.encode()).hexdigest()
    assert candidates[1]["record_provenance"] == "VERIFIED"
    assert candidates[1]["in_reconciled_findings"] is True
    assert candidates[1]["in_case_packet"] is True
    assert receipt["packet_candidate_count_total"] == 1


def test_mixed_candidate_projection_rejects_forged_quarantine_hash(tmp_path):
    values = _synthetic_run(tmp_path, mixed_candidates=True)
    task_id = "synth-task-00:chunk-1"
    quarantined = values["result"]["task_results"][task_id]["payload"]["quarantined_items"][0]
    quarantined["item_hash"] = "0" * 64
    ledger_output = values["ledger"]["outputs"][task_id]
    ledger_output["payload"]["quarantined_items"][0]["item_hash"] = "0" * 64
    ledger_output["output_hash"] = reconciliation.digest(
        reconciliation.canonical(ledger_output["payload"])
    )
    values["result"]["task_results"][task_id]["output_hash"] = ledger_output["output_hash"]
    unsigned = {key: value for key, value in values["result"].items() if key != "result_hash"}
    values["result"]["result_hash"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    with pytest.raises(reconciliation.ReconciliationError, match="normalization_quarantine_binding_invalid"):
        reconciliation.build_receipt(
            values["result"], values["ledger"], values["outcomes"], values["manifest"],
            values["response_payloads"], values["packet_pairs"], values["plan"],
            values["writer_receipt"], values["result"]["result_hash"],
            values["plan_sha"], values["manifest_sha"], values["writer_receipt_sha"],
        )


def test_reconciliation_rejects_forged_candidate_id_in_selected_writer_finding(tmp_path):
    values = _synthetic_run(tmp_path)
    finding = values["result"]["findings"][0]
    records = finding.get("assessment_records")
    if isinstance(records, list):
        records[0]["candidate_id"] = "forged-candidate-id"
    else:
        finding["candidate_id"] = "forged-candidate-id"
    unsigned = {key: value for key, value in values["result"].items() if key != "result_hash"}
    values["result"]["result_hash"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()

    with pytest.raises(reconciliation.ReconciliationError, match="finding_candidate_unmatched"):
        reconciliation.build_receipt(
            values["result"], values["ledger"], values["outcomes"], values["manifest"],
            values["response_payloads"], values["packet_pairs"], values["plan"],
            values["writer_receipt"], values["result"]["result_hash"],
            values["plan_sha"], values["manifest_sha"], values["writer_receipt_sha"],
        )


def test_cli_main_binds_saved_engine_result_to_capture_and_projects_private_receipt(tmp_path, monkeypatch):
    values = _synthetic_run(tmp_path)
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(reconciliation.canonical(values["plan"]))
    preflight_path = tmp_path / "preflight.json"
    preflight_path.write_text("{}")
    receipt = values["writer_receipt"]
    outcomes = values["outcomes"]
    receipt_path = tmp_path / "writer-receipt.json"
    outcomes_path = tmp_path / "writer-outcomes.json"
    receipt_path.write_bytes(reconciliation.canonical(receipt))
    outcomes_path.write_bytes(reconciliation.canonical(outcomes))
    result_path = values["result_path"]
    result_path.chmod(0o600)

    def fake_case_for_plan_path(_path, _root):
        return "PR-464", {"writer_calls": 10}

    def fake_sanitize(_capture_root, _plan, _preflight, output_dir):
        output_dir.mkdir(mode=0o700)
        generated_outcomes = output_dir / "writer-outcomes.json"
        generated_outcomes.write_bytes(reconciliation.canonical(outcomes))
        generated_outcomes.chmod(0o600)
        return receipt

    monkeypatch.setattr(reconciliation, "case_for_plan_path", fake_case_for_plan_path)
    monkeypatch.setattr(reconciliation, "sanitize_writer_capture", fake_sanitize)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    output = tmp_path / "projection.json"
    assert reconciliation.main([
        "--result", str(result_path), "--capture-root", str(values["capture_root"]),
        "--plan", str(plan_path), "--preflight", str(preflight_path),
        "--writer-receipt", str(receipt_path), "--writer-outcomes", str(outcomes_path),
        "--output", str(output),
    ]) == 0
    projection = json.loads(output.read_bytes())
    assert projection["status"] == "PROJECTION_COMPLETE"
    assert projection["returned_candidate_count_total"] == 1
    assert output.stat().st_mode & 0o777 == 0o600
