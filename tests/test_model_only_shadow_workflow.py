from __future__ import annotations

import importlib.util
import json
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "private-shadow-capture.yml"
BUDGET = ROOT / "experiments" / "model-only-shadow-trial-v1.json"
_SANITIZER_SPEC = importlib.util.spec_from_file_location(
    "sanitize_model_only_shadow_preflight", ROOT / "scripts" / "sanitize_model_only_shadow_preflight.py"
)
assert _SANITIZER_SPEC is not None and _SANITIZER_SPEC.loader is not None
sanitizer = importlib.util.module_from_spec(_SANITIZER_SPEC)
_SANITIZER_SPEC.loader.exec_module(sanitizer)


def test_shadow_preparation_is_manual_trusted_and_read_only():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "on:\n  workflow_dispatch:\n" in text
    assert text.count("  contents: read\n") == 2
    assert "if: github.event_name == 'workflow_dispatch' && github.repository == 'groktopus/codereview' && github.ref == 'refs/heads/main'" in text
    assert "${{ secrets." not in text
    assert "PUBLISH_REVIEW" not in text
    assert "--run-provider-trial" not in text
    assert "--prepare-only" in text
    assert WORKFLOW.name == "private-shadow-capture.yml"


def test_workflow_pins_the_historical_case_runtime_and_never_uploads_raw_data():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "5873c3f1b297a96c49b78cbcb7be674ab70b3cea" in text
    assert "1c94fabdbd5419a2da5beeed1e6d72030af2af71531f3a58defe1bf0a34ff9c0" in text
    assert "--mode staged-pr464 --prepare-only --input-contract specialist-input-v2" in text
    upload = text.split("- name: Upload only the sanitized preparation receipt", 1)[1]
    assert "${{ runner.temp }}/private-shadow-sanitized/summary.json" in upload
    assert "${{ runner.temp }}/private-shadow-sanitized/manifest.json" in upload
    assert "private-shadow-preparation/summary.json" not in upload
    assert "steps.sanitize.outputs.validated == 'true'" in upload
    assert "private/" not in upload and "capture" not in upload
    assert text.index("Upload only the sanitized preparation receipt") < text.index("Remove private preparation workspace")


def test_budget_manifest_has_finite_shared_limits_and_planned_provider_identity():
    budget = json.loads(BUDGET.read_text(encoding="utf-8"))
    assert budget["schema"] == "model-only-shadow-trial-budget.v1"
    assert budget["status"] == "PREPARE_ONLY_LIVE_DISPATCH_DISABLED"
    case = budget["case"]
    assert case["case_id"] == "PR-464"
    assert case["base_sha"] == "20a743f0434a1843aa00068483f608f1e213b2af"
    assert case["head_sha"] == "bffc26f9e4bf95aca0c252e88a2396d03ece854c"
    assert case["runtime_inventory_sha256"] == "1c94fabdbd5419a2da5beeed1e6d72030af2af71531f3a58defe1bf0a34ff9c0"
    assert case["runtime_module_tree_sha256"] == "d8bdb53517abb7d85fff59805224f457f296832e7e0074b1485c50691dae1ad4"
    limits = budget["budgets"]
    assert limits["writer_calls_max"] + limits["audit_calls_max"] == limits["total_provider_calls_max"] == 13
    assert limits["max_request_bytes_per_call"] == 128_000
    assert limits["max_response_bytes_per_call"] == 32_768
    assert limits["max_output_tokens_per_llm_call"] == 1_800
    assert limits["max_retries_per_task"] == 0
    assert limits["total_provider_deadline_seconds"] == (
        limits["writer_stage_deadline_seconds"] + limits["audit_stage_deadline_seconds_total"]
    )
    assert budget["provider_identity_status"] == "PLANNED_NOT_OBSERVED_SECRET_VALUES_OPAQUE"
    assert budget["planned_provider_identity"] == {
        "llm_base_url": "https://inference-api.nousresearch.com/v1",
        "llm_model": "openai/gpt-6-luna",
        "jev_base_url": "https://api.typesafe.ai/v1",
        "jev_model": "jev-latest",
    }
    assert budget["artifact_policy"]["upload_allowlist"] == ["summary.json", "manifest.json"]


def _receipt_fixture(tmp_path: Path, *, extra_manifest_key: bool = False):
    digest = "a" * 64
    case = {
        "case_id": "PR-464", "checks_sha256": digest, "evidence_index_sha256": digest,
        "immutable_patch_sha256": digest, "primary_calls": 10,
        "primary_descriptor_sha256": digest, "primary_serialized_input_bytes": 893359,
        "profile_sha256": digest, "scope_count": 22, "scope_sha256": digest,
        "snapshot_hash": "3fcb39bbe80bbc10d02fbfef98abc6f73f9f46b829776515a6c9f9df69787663",
        "status": "PREPARED_NOT_RUN",
    }
    summary = {"schema": "historical-real-case-trial-manifest.v2", "status": "PREPARED_NOT_RUN", "cases": [case]}
    manifest = {key: None for key in sanitizer.MANIFEST_KEYS}
    manifest.update({
        "schema": "historical-real-case-trial-manifest.v2", "status": "PREPARED_NOT_RUN",
        "mode": "staged-pr464", "input_contract": "specialist-input-v2", "provider_calls": 0,
        "provider_execution_state": "ZERO_PROVIDER_CALLS_PREPARE_ONLY", "publication_enabled": False,
        "target_code_execution": False, "max_retries_per_task": 0,
        "primary_response_byte_cap_per_call": 16000,
        "runtime_revision": "5873c3f1b297a96c49b78cbcb7be674ab70b3cea",
        "runtime_module_tree_sha256": "d8bdb53517abb7d85fff59805224f457f296832e7e0074b1485c50691dae1ad4", "runner_revision": "b" * 40,
        "runtime_wheel_sha256": digest,
        "cases": [{**case, "primary_request_receipts": []}],
    })
    if extra_manifest_key:
        manifest["source_excerpt"] = "should never be uploaded"
    summary_path, manifest_path = tmp_path / "summary-input.json", tmp_path / "manifest-input.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return summary_path, manifest_path


def test_sanitizer_uploads_only_allowlisted_hash_receipts_and_private_modes(tmp_path: Path):
    summary, manifest = _receipt_fixture(tmp_path)
    output_dir = tmp_path / "sanitized"
    sanitizer.sanitize(summary, manifest, output_dir)
    clean_summary = json.loads((output_dir / "summary.json").read_text())
    clean_manifest = json.loads((output_dir / "manifest.json").read_text())
    assert set(clean_summary) == {"schema", "status", "case"}
    assert "source_summary_sha256" in clean_manifest and "source_manifest_sha256" in clean_manifest
    assert "primary_request_receipts" not in json.dumps(clean_manifest)
    assert stat.S_IMODE(output_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((output_dir / "manifest.json").stat().st_mode) == 0o600


def test_sanitizer_rejects_unreviewed_manifest_fields(tmp_path: Path):
    summary, manifest = _receipt_fixture(tmp_path, extra_manifest_key=True)
    with pytest.raises(sanitizer.ReceiptError, match="manifest_schema_invalid"):
        sanitizer.sanitize(summary, manifest, tmp_path / "sanitized")
