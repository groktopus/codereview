from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import select_frozen_pr464_no_candidate_packet as selector  # noqa: E402


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    task_ids = [f"task-{index}" for index in range(10)]
    requests = [
        {"task_id": task_id, "input_bytes": 100 + index, "input_sha256": f"{index:064x}"}
        for index, task_id in enumerate(task_ids)
    ]
    plan = {
        "case": {"case_id": "PR-464", "snapshot_id": "snapshot-464", "snapshot_sha256": "a" * 64},
        "writer_requests": requests,
    }
    plan_path = tmp_path / "plan.json"
    plan_raw = json.dumps(plan, sort_keys=True).encode()
    plan_path.write_bytes(plan_raw)
    plan_sha = _sha(plan_raw)
    monkeypatch.setattr(selector.shadow_runner, "case_for_plan_path", lambda _path, _root: ("PR-464", {}))
    monkeypatch.setattr(selector.shadow_runner, "validate_plan_binding", lambda _plan, _raw: ("PR-464", {}))

    capture = tmp_path / "capture"
    capture.mkdir(mode=0o700)
    packet_dir = capture / "case-packets"
    packet_dir.mkdir(mode=0o700)
    inventory = []
    packet_rows = []
    for index, task_id in enumerate(task_ids):
        packet = {
            "contract_version": "model-only-shadow-case.v1",
            "case_id": "PR-464",
            "snapshot": {"snapshot_id": "snapshot-464", "snapshot_hash": "a" * 64},
            "source_task": {"task_id": task_id},
            "writer_run": {"status": "completed", "calls": [{
                "request_sha256": requests[index]["input_sha256"],
                "response_sha256": f"{index + 100:064x}",
            }]},
            "writer_candidate": None,
        }
        raw = json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()
        name = f"PR-464-{index:02d}.json"
        path = packet_dir / name
        path.write_bytes(raw)
        inventory.append({"path": name, "sha256": _sha(raw)})
        packet_rows.append(("", path, packet, raw))
    manifest = {
        "contract_version": "model-only-shadow-case.v1",
        "case_id": "writer-live-123-1",
        "private_artifacts": True,
        "snapshot_id": "snapshot-464",
        "snapshot_hash": "a" * 64,
        "case_packet_inventory": {"schema": "model-only-shadow-packet-inventory.v1", "packets": inventory},
    }
    manifest_raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    (capture / "manifest.json").write_bytes(manifest_raw)
    os.chmod(capture / "manifest.json", 0o600)
    for path in packet_dir.iterdir():
        os.chmod(path, 0o600)
    manifest_sha = _sha(manifest_raw)
    monkeypatch.setattr(
        selector.shadow_runner,
        "_task_order",
        lambda _path, packets, **_kwargs: (packets, {}),
    )
    monkeypatch.setattr(selector, "_validate_packet", lambda _packet: None)
    monkeypatch.setattr(selector, "_validate_frozen_pr464", lambda _packet: plan_sha)

    preflight = {
        "schema": "model-only-shadow-live-preflight-receipt.v1",
        "status": "PLAN_MATCHED_PROVIDER_FREE",
        "case_id": "PR-464",
        "plan_sha256": plan_sha,
        "snapshot_sha256": "a" * 64,
        "provider_calls": 0,
        "target_code_execution": False,
        "publication_enabled": False,
    }
    preflight_path = tmp_path / "preflight.json"
    preflight_path.write_text(json.dumps(preflight))
    writer_receipt = {
        "schema": "model-only-shadow-live-writer-receipt.v1",
        "status": "WRITER_TRANSPORT_CAPTURED",
        "case_id": "PR-464",
        "plan_sha256": plan_sha,
        "snapshot_id": "snapshot-464",
        "snapshot_sha256": "a" * 64,
        "writer_call_count": 10,
        "audit_or_jev_dispatched": False,
        "target_code_execution": False,
        "publication_enabled": False,
        "calls": [
            {"task_id": row["task_id"], "request_sha256": row["input_sha256"],
             "request_bytes": row["input_bytes"], "response_sha256": f"{index + 100:064x}"}
            for index, row in enumerate(requests)
        ],
    }
    writer_receipt_path = tmp_path / "writer-receipt.json"
    writer_receipt_path.write_text(json.dumps(writer_receipt))
    outcomes = {
        "schema": "model-only-shadow-live-writer-outcomes.v1",
        "plan_sha256": plan_sha,
        "capture_manifest_sha256": manifest_sha,
        "tasks": [
            {"task_id_sha256": _sha(task_id.encode()), "outcome": "zero_findings_returned",
             "returned_candidate_count": 0, "packet_candidate_count": 0,
             "candidate_packet_count": 1, "response_sha256": f"{index + 100:064x}"}
            for index, task_id in enumerate(task_ids)
        ],
        "returned_candidate_count_total": 0,
        "packet_candidate_count_total": 0,
        "outcome_counts": {
            "zero_findings_returned": 10,
            "parse_failure": 0,
            "candidate_reconciliation_or_filtering": 0,
            "candidates_preserved_in_packets": 0,
        },
    }
    outcomes_path = tmp_path / "writer-outcomes.json"
    outcomes_path.write_text(json.dumps(outcomes))
    return capture, plan_path, preflight_path, writer_receipt_path, outcomes_path, task_ids


def test_selects_manifest_bound_first_pr464_empty_packet_without_dispatch(tmp_path, monkeypatch):
    args = _fixture(tmp_path, monkeypatch)
    capture, plan, preflight, writer_receipt, outcomes, task_ids = args

    result = selector.select(capture, plan, preflight, writer_receipt, outcomes)

    assert result["schema"] == "frozen-pr464-no-candidate-selection.v1"
    assert result["packet_path"] == "case-packets/PR-464-00.json"
    assert result["selected_task_sha256"] == _sha(task_ids[0].encode())
    assert result["writer_calls"] == 10
    assert result["audit_provider_calls"] == 0
    assert result["publication_enabled"] is False
    assert result["target_code_execution"] is False
    assert set(result) == {
        "schema", "case_id", "packet_path", "selected_packet_sha256", "capture_manifest_sha256",
        "plan_sha256", "snapshot_sha256", "selected_task_sha256", "writer_calls",
        "audit_provider_calls", "publication_enabled", "target_code_execution",
    }


def test_rejects_filtered_or_candidate_outcomes_before_selection(tmp_path, monkeypatch):
    args = _fixture(tmp_path, monkeypatch)
    capture, plan, preflight, writer_receipt, outcomes, _task_ids = args
    value = json.loads(outcomes.read_text())
    value["tasks"][0]["outcome"] = "candidate_reconciliation_or_filtering"
    value["outcome_counts"]["zero_findings_returned"] = 9
    value["outcome_counts"]["candidate_reconciliation_or_filtering"] = 1
    outcomes.write_text(json.dumps(value))

    with pytest.raises(selector.SelectionError, match="selection_writer_outcomes_invalid"):
        selector.select(capture, plan, preflight, writer_receipt, outcomes)


def test_rejects_manifest_bound_packet_that_contains_a_candidate(tmp_path, monkeypatch):
    args = _fixture(tmp_path, monkeypatch)
    capture, plan, preflight, writer_receipt, outcomes, _task_ids = args
    packet_path = capture / "case-packets/PR-464-00.json"
    packet = json.loads(packet_path.read_text())
    packet["writer_candidate"] = {"candidate_id": "candidate-should-not-run"}
    raw = json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()
    packet_path.write_bytes(raw)
    manifest_path = capture / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["case_packet_inventory"]["packets"][0]["sha256"] = _sha(raw)
    manifest_raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_path.write_bytes(manifest_raw)
    outcome_data = json.loads(outcomes.read_text())
    outcome_data["capture_manifest_sha256"] = _sha(manifest_raw)
    outcomes.write_text(json.dumps(outcome_data))

    with pytest.raises(selector.SelectionError, match="selection_candidate_present"):
        selector.select(capture, plan, preflight, writer_receipt, outcomes)


def test_exact_frozen_pr464_selector_binds_canonical_profile_hash(tmp_path, monkeypatch):
    """Run the selector against checked-in frozen identity inputs without dispatch.

    The packet body is a focused fixture because the full historical snapshot is
    not checked in. The selector's PR464 plan/corpus/manifest/profile checks and
    its identity validators remain real; only full packet validation and stable
    task ordering are isolated from this identity regression.
    """
    plan_path = selector.ROOT / "experiments/model-only-shadow-live-pr464-plan-v4.json"
    plan_raw = plan_path.read_bytes()
    plan = json.loads(plan_raw)
    plan_sha = _sha(plan_raw)
    case = plan["case"]
    corpus = json.loads(
        (selector.ROOT / "examples/evaluation/model-only-shadow-pr464-v4/corpus.json").read_text()
    )
    identity = corpus["cases"][0]["identity"]
    profile_raw = (selector.ROOT / "docs/real-case-trial-v1/profiles/PR-464.json").read_bytes()
    profile = json.loads(profile_raw)
    raw_profile_sha = _sha(profile_raw)
    canonical_profile_sha = _sha(
        json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    )
    assert raw_profile_sha == case["profile_file_sha256"] == identity["profile"]["sha256"]
    assert canonical_profile_sha != raw_profile_sha

    packets = []
    packet_dir = tmp_path / "capture" / "case-packets"
    packet_dir.mkdir(mode=0o700, parents=True)
    inventory = []
    response_hashes = {}
    for index, request in enumerate(plan["writer_requests"]):
        task_id = request["task_id"]
        response_hash = f"{index + 1:064x}"
        response_hashes[task_id] = response_hash
        packet = {
            "contract_version": "model-only-shadow-case.v1",
            "case_id": "PR-464",
            "snapshot": {
                "snapshot_id": case["snapshot_id"],
                "snapshot_hash": case["snapshot_sha256"],
                "base_sha": case["base_sha"],
                "head_sha": case["head_sha"],
                "profile_version": case["profile_version"],
                "profile_hash": canonical_profile_sha,
            },
            "source_task": {"task_id": task_id},
            "writer_run": {
                "status": "completed",
                "calls": [{"request_sha256": request["input_sha256"], "response_sha256": response_hash}],
            },
            "writer_candidate": None,
            "profile_id": identity["profile"]["profile_id"],
        }
        raw = json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()
        name = f"PR-464-{index:02d}.json"
        (packet_dir / name).write_bytes(raw)
        packets.append(("", packet_dir / name, packet, raw))
        inventory.append({"path": name, "sha256": _sha(raw)})
    monkeypatch.setattr(selector.shadow_runner, "_task_order", lambda *_args, **_kwargs: (packets, {}))
    monkeypatch.setattr(selector, "_validate_packet", lambda _packet: None)

    capture = packet_dir.parent
    os.chmod(capture, 0o700)
    manifest = {
        "contract_version": "model-only-shadow-case.v1",
        "case_id": "writer-live-regression-1",
        "private_artifacts": True,
        "snapshot_id": case["snapshot_id"],
        "snapshot_hash": case["snapshot_sha256"],
        "case_packet_inventory": {"schema": "model-only-shadow-packet-inventory.v1", "packets": inventory},
    }
    manifest_raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    (capture / "manifest.json").write_bytes(manifest_raw)
    preflight_path = tmp_path / "preflight.json"
    preflight_path.write_text(json.dumps({
        "schema": "model-only-shadow-live-preflight-receipt.v1",
        "status": "PLAN_MATCHED_PROVIDER_FREE", "case_id": "PR-464", "plan_sha256": plan_sha,
        "snapshot_sha256": case["snapshot_sha256"], "provider_calls": 0,
        "target_code_execution": False, "publication_enabled": False,
    }))
    writer_receipt_path = tmp_path / "writer-receipt.json"
    writer_receipt_path.write_text(json.dumps({
        "schema": "model-only-shadow-live-writer-receipt.v1", "status": "WRITER_TRANSPORT_CAPTURED",
        "case_id": "PR-464", "plan_sha256": plan_sha, "snapshot_id": case["snapshot_id"],
        "snapshot_sha256": case["snapshot_sha256"], "writer_call_count": 10,
        "audit_or_jev_dispatched": False, "target_code_execution": False, "publication_enabled": False,
        "calls": [{
            "task_id": request["task_id"], "request_sha256": request["input_sha256"],
            "request_bytes": request["input_bytes"], "response_sha256": response_hashes[request["task_id"]],
        } for request in plan["writer_requests"]],
    }))
    outcomes_path = tmp_path / "writer-outcomes.json"

    def write_outcomes(bound_manifest_raw: bytes) -> None:
        outcomes_path.write_text(json.dumps({
            "schema": "model-only-shadow-live-writer-outcomes.v1", "plan_sha256": plan_sha,
            "capture_manifest_sha256": _sha(bound_manifest_raw),
            "tasks": [{
                "task_id_sha256": _sha(request["task_id"].encode()),
                "outcome": "zero_findings_returned", "returned_candidate_count": 0,
                "packet_candidate_count": 0, "candidate_packet_count": 1,
                "response_sha256": response_hashes[request["task_id"]],
            } for request in plan["writer_requests"]],
            "returned_candidate_count_total": 0, "packet_candidate_count_total": 0,
            "outcome_counts": {
                "zero_findings_returned": 10, "parse_failure": 0,
                "candidate_reconciliation_or_filtering": 0, "candidates_preserved_in_packets": 0,
            },
        }))

    write_outcomes(manifest_raw)
    result = selector.select(capture, plan_path, preflight_path, writer_receipt_path, outcomes_path)
    assert result["case_id"] == "PR-464"
    assert result["packet_path"] == "case-packets/PR-464-00.json"
    assert result["writer_calls"] == 10 and result["audit_provider_calls"] == 0

    # Keep the packet otherwise manifest-bound and exercise the exact bad shape
    # from the failed trial: using the raw file digest as the runtime snapshot hash.
    packet_path = packet_dir / "PR-464-00.json"
    bad_packet = json.loads(packet_path.read_text())
    bad_packet["snapshot"]["profile_hash"] = raw_profile_sha
    bad_raw = json.dumps(bad_packet, sort_keys=True, separators=(",", ":")).encode()
    packet_path.write_bytes(bad_raw)
    packets[0] = ("", packet_path, bad_packet, bad_raw)
    manifest["case_packet_inventory"]["packets"][0]["sha256"] = _sha(bad_raw)
    manifest_raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    (capture / "manifest.json").write_bytes(manifest_raw)
    write_outcomes(manifest_raw)
    with pytest.raises(selector.SelectionError, match="selection_packet_identity_invalid"):
        selector.select(capture, plan_path, preflight_path, writer_receipt_path, outcomes_path)
