from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "sanitize_model_only_shadow_package_receipt",
    ROOT / "scripts" / "sanitize_model_only_shadow_package_receipt.py",
)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
SELECT_SPEC = importlib.util.spec_from_file_location(
    "select_model_only_shadow_package_packet",
    ROOT / "scripts" / "select_model_only_shadow_package_packet.py",
)
assert SELECT_SPEC is not None and SELECT_SPEC.loader is not None
selector = importlib.util.module_from_spec(SELECT_SPEC)
SELECT_SPEC.loader.exec_module(selector)


def _summary(**overrides):
    value = {
        "ok": True,
        "comparison_id": "pkg-" + "a" * 64,
        "case_count": 1,
        "verified_artifact_count": 8,
        "verified_structured_relation_count": 6,
        "claims": {"accuracy": None, "ground_truth": None, "calibration": None, "correctness": None},
        "comparison_path": "/runner/private/comparison-v2.json",
        "report_path": "/runner/private/comparison-report.json",
    }
    value.update(overrides)
    return value


def test_projects_only_bounded_counts_and_explicit_non_claims(tmp_path):
    summary = tmp_path / "summary.json"
    summary.write_text(json.dumps(_summary()), encoding="utf-8")
    output_dir = tmp_path / "receipt-dir"
    output_dir.mkdir(mode=0o700)
    output = output_dir / "receipt.json"

    receipt = module.project(summary, output, "PR-464")

    assert set(receipt) == {
        "schema", "case_id", "package_status", "comparison_id", "case_count",
        "verified_artifact_count", "verified_structured_relation_count",
        "semantic_accuracy_claimed", "ground_truth_claimed", "calibration_claimed", "correctness_claimed",
    }
    assert receipt["schema"] == "model-only-shadow-cross-model-package-receipt.v1"
    assert receipt["case_id"] == "PR-464"
    assert receipt["package_status"] == "byte_verified"
    assert receipt["verified_artifact_count"] == 8
    assert all(receipt[key] is False for key in (
        "semantic_accuracy_claimed", "ground_truth_claimed", "calibration_claimed", "correctness_claimed",
    ))
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    text = output.read_text(encoding="utf-8")
    assert "/runner/private" not in text
    assert "comparison_path" not in text and "report_path" not in text


@pytest.mark.parametrize("override", [
    {"case_count": 2},
    {"verified_artifact_count": 7},
    {"comparison_id": "pkg-not-a-hash"},
    {"claims": {"accuracy": 0.9, "ground_truth": None, "calibration": None, "correctness": None}},
    {"verified_structured_relation_count": True},
    {"ok": False},
])
def test_rejects_wrong_package_identity_or_claims(tmp_path, override):
    summary = tmp_path / "summary.json"
    summary.write_text(json.dumps(_summary(**override)), encoding="utf-8")
    output_dir = tmp_path / "receipt-dir"
    output_dir.mkdir(mode=0o700)

    with pytest.raises(module.ReceiptError):
        module.project(summary, output_dir / "receipt.json", "PR-464")


def test_rejects_duplicate_json_keys(tmp_path):
    summary = tmp_path / "summary.json"
    summary.write_text('{"ok":true,"ok":true}', encoding="utf-8")
    output_dir = tmp_path / "receipt-dir"
    output_dir.mkdir(mode=0o700)

    with pytest.raises(module.ReceiptError, match="package_summary_invalid"):
        module.project(summary, output_dir / "receipt.json", "PR-464")


def test_workflow_packages_both_frozen_cases_privately_and_cleans_outputs_without_upload():
    workflow = (ROOT / ".github/workflows/private-shadow-capture.yml").read_text(encoding="utf-8")
    live = workflow.split("  live_writer:", 1)[1]
    package = live.split("- name: Gate cross-model packaging on a completed candidate audit", 1)[1].split(
        "- name: Upload only the hash-only writer accounting artifacts", 1
    )[0]
    assert "steps.case.outputs.corpus_path" in package
    assert "steps.package-selection.outputs.eligible == 'true'" in package
    assert "select_model_only_shadow_package_packet.py" in package
    assert "package_cross_model_v2.py" in package
    assert "--case-id \"${{ steps.case.outputs.case_id }}\"" in package
    selector_source = (ROOT / "scripts/select_model_only_shadow_package_packet.py").read_text(encoding="utf-8")
    assert 'capture_root / "manifest.json"' in selector_source
    assert 'capture_root / "capture-manifest.json"' not in selector_source
    assert "sanitize_model_only_shadow_package_receipt.py" in package
    assert "--case-id \"${{ steps.case.outputs.case_id }}\"" in package
    assert "upload-artifact" not in package
    assert "package-receipt.json" not in live.split("- name: Upload only the hash-only writer accounting artifacts", 1)[1]
    cleanup = live.split("- name: Remove private live-writer workspace", 1)[1]
    assert '"private-cross-model-package"' in cleanup
    case_selection = live.split("- name: Select one fixed live case", 1)[1].split(
        "- name: Set up Python", 1
    )[0]
    assert '"examples/evaluation/model-only-shadow-pr457-v4/corpus.json"' in case_selection
    assert '"examples/evaluation/model-only-shadow-pr464-v4/corpus.json"' in case_selection
    assert '"audit_limits_path": "experiments/model-only-shadow-audit-limits-pr457-v4.json"' in case_selection
    assert '"audit_limits_path": "experiments/model-only-shadow-audit-limits-pr464-v4.json"' in case_selection
    assert '"corpus_path": contracts[case_id]["corpus_path"]' in case_selection
    assert '--limits "${{ steps.case.outputs.audit_limits_path }}"' in live


def _selection_fixture(tmp_path, *, case_id="PR-464", terminal="completed", candidate=True):
    capture = tmp_path / "capture"
    packet_dir = capture / "case-packets"
    packet_dir.mkdir(parents=True, mode=0o700)
    packet = {
        "contract_version": "model-only-shadow-case.v1",
        "case_id": case_id,
        "writer_candidate": {"candidate_id": "candidate-1"} if candidate else None,
    }
    packet_raw = (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (packet_dir / "packet-1.json").write_bytes(packet_raw)
    manifest = {
        "case_packet_inventory": {
            "schema": "model-only-shadow-packet-inventory.v1",
            "packets": [{"path": "packet-1.json", "sha256": hashlib.sha256(packet_raw).hexdigest()}],
        },
    }
    manifest_raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (capture / "manifest.json").write_bytes(manifest_raw)
    audit = {
        "schema": "model-only-shadow-audit-receipt.v1",
        "case_id": case_id,
        "terminal_state": terminal,
        "reason": "one_candidate_selected" if candidate else "no_writer_candidate",
        "candidate_packet_count": 1 if candidate else 0,
        "selected_candidate_sha256": "b" * 64 if candidate else None,
        "selected_packet_sha256": hashlib.sha256(packet_raw).hexdigest(),
        "capture_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "roles": {role: "completed" for role in selector.ROLES},
    }
    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps(audit), encoding="utf-8")
    return capture, audit_path, audit


def test_selects_only_completed_candidate_packet_with_exact_manifest_and_packet_hashes(tmp_path):
    capture, audit_path, _ = _selection_fixture(tmp_path)

    result = selector.select(capture, audit_path, "PR-464")

    assert result == {
        "eligible": True,
        "reason": "completed_candidate_audit",
        "selected_packet": "packet-1.json",
    }


def test_selects_pr457_packet_for_its_matching_case_id(tmp_path):
    capture, audit_path, _ = _selection_fixture(tmp_path, case_id="PR-457")

    result = selector.select(capture, audit_path, "PR-457")

    assert result["eligible"] is True
    with pytest.raises(selector.SelectionError, match="selection_receipt_identity_invalid"):
        selector.select(capture, audit_path, "PR-464")


def test_pr457_receipt_retains_requested_case_identity(tmp_path):
    summary = tmp_path / "summary.json"
    summary.write_text(json.dumps(_summary()), encoding="utf-8")
    output_dir = tmp_path / "receipt-dir"
    output_dir.mkdir(mode=0o700)

    receipt = module.project(summary, output_dir / "receipt.json", "PR-457")

    assert receipt["case_id"] == "PR-457"


@pytest.mark.parametrize("terminal", ["incomplete", "claim_audit_abstained", "source_audit_failed", "jev_assessment_failed", "claim_audit_failed"])
def test_noncompleted_audit_states_are_explicit_package_skips(tmp_path, terminal):
    capture, audit_path, _ = _selection_fixture(tmp_path, terminal=terminal)

    assert selector.select(capture, audit_path, "PR-464") == {
        "eligible": False,
        "reason": "audit_not_completed",
    }


def test_no_candidate_audit_is_an_explicit_package_skip(tmp_path):
    capture, audit_path, _ = _selection_fixture(tmp_path, terminal="incomplete", candidate=False)

    assert selector.select(capture, audit_path, "PR-464") == {
        "eligible": False,
        "reason": "audit_not_completed",
    }


def test_selection_rejects_receipt_hash_not_bound_to_capture_manifest(tmp_path):
    capture, audit_path, audit = _selection_fixture(tmp_path)
    audit["capture_manifest_sha256"] = "c" * 64
    audit_path.write_text(json.dumps(audit), encoding="utf-8")

    with pytest.raises(selector.SelectionError, match="selection_capture_binding_invalid"):
        selector.select(capture, audit_path, "PR-464")


def test_selection_rejects_packet_hash_not_present_in_inventory(tmp_path):
    capture, audit_path, audit = _selection_fixture(tmp_path)
    audit["selected_packet_sha256"] = "d" * 64
    audit_path.write_text(json.dumps(audit), encoding="utf-8")

    with pytest.raises(selector.SelectionError, match="selection_packet_binding_invalid"):
        selector.select(capture, audit_path, "PR-464")


def test_completed_receipt_with_incomplete_roles_is_explicit_package_skip(tmp_path):
    capture, audit_path, audit = _selection_fixture(tmp_path)
    audit["roles"]["jev"] = "abstained"
    audit_path.write_text(json.dumps(audit), encoding="utf-8")

    with pytest.raises(selector.SelectionError, match="completed_receipt_roles_invalid"):
        selector.select(capture, audit_path, "PR-464")


@pytest.mark.parametrize("field,value", [
    ("candidate_packet_count", 0),
    ("selected_candidate_sha256", None),
    ("reason", "no_writer_candidate"),
])
def test_completed_receipt_with_missing_or_invalid_candidate_fails_closed(tmp_path, field, value):
    capture, audit_path, audit = _selection_fixture(tmp_path)
    audit[field] = value
    audit_path.write_text(json.dumps(audit), encoding="utf-8")

    with pytest.raises(selector.SelectionError, match="completed_receipt_candidate_invalid"):
        selector.select(capture, audit_path, "PR-464")


def test_completed_receipt_with_packet_without_candidate_fails_closed(tmp_path):
    capture, audit_path, audit = _selection_fixture(tmp_path)
    packet_path = capture / "case-packets" / "packet-1.json"
    packet = json.loads(packet_path.read_text())
    packet["writer_candidate"] = None
    packet_raw = (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode()
    packet_path.write_bytes(packet_raw)
    manifest_path = capture / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["case_packet_inventory"]["packets"][0]["sha256"] = hashlib.sha256(packet_raw).hexdigest()
    manifest_raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    manifest_path.write_bytes(manifest_raw)
    audit["selected_packet_sha256"] = hashlib.sha256(packet_raw).hexdigest()
    audit["capture_manifest_sha256"] = hashlib.sha256(manifest_raw).hexdigest()
    audit_path.write_text(json.dumps(audit), encoding="utf-8")

    with pytest.raises(selector.SelectionError, match="completed_packet_candidate_invalid"):
        selector.select(capture, audit_path, "PR-464")


def test_bounded_reader_handles_short_reads(tmp_path, monkeypatch):
    capture, audit_path, _ = _selection_fixture(tmp_path)
    real_read = selector.os.read

    def short_read(fd, count):
        return real_read(fd, min(count, 7))

    monkeypatch.setattr(selector.os, "read", short_read)

    assert selector.select(capture, audit_path, "PR-464")["eligible"] is True
