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
    prepare = text.split("  live_writer:", 1)[0]
    assert "on:\n  workflow_dispatch:\n" in text
    assert text.count("  contents: read\n") == 3
    assert "if: inputs.live_case == 'PR-464' && github.event_name == 'workflow_dispatch'" in prepare
    live = text.split("  live_writer:", 1)[1]
    assert "if: inputs.run_live_writer == true && inputs.live_case == 'PR-464' && github.event_name == 'workflow_dispatch' && github.repository == 'groktopus/codereview' && github.ref == 'refs/heads/main'" in live
    assert "${{ secrets." not in prepare
    assert "PUBLISH_REVIEW" not in text
    assert "--run-provider-trial" not in text
    assert "--prepare-only" in text
    assert WORKFLOW.name == "private-shadow-capture.yml"


def test_historical_prepare_is_skipped_for_pr457_and_artifact_names_its_case():
    text = WORKFLOW.read_text(encoding="utf-8")
    prepare = text.split("  prepare:\n", 1)[1].split("  live_writer:", 1)[0]
    assert "name: PR-464 provider-free preparation" in prepare
    assert (
        "if: inputs.live_case == 'PR-464' && github.event_name == 'workflow_dispatch' "
        "&& github.repository == 'groktopus/codereview' && github.ref == 'refs/heads/main'"
    ) in prepare
    assert "private-shadow-preflight-PR-464-${{ github.run_id }}-${{ github.run_attempt }}" in prepare
    assert "${{ secrets." not in prepare
    assert "--prepare-only" in prepare


def test_live_writer_is_opt_in_preflighted_and_uploads_only_sanitized_receipt():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "run_live_writer:" in text and "default: false" in text
    live = text.split("  live_writer:", 1)[1]
    assert "if: inputs.run_live_writer == true && inputs.live_case == 'PR-464' && github.event_name == 'workflow_dispatch'" in live
    assert live.index("Verify the exact plan and write the fresh provider-free receipt") < live.index(
        "Check writer secret names and exact configured identity without printing values"
    ) < live.index("Run only the selected pinned read-only writer calls")
    exact_preflight = live.split("- name: Verify the exact plan and write the fresh provider-free receipt", 1)[1].split(
        "- name: Check writer secret names and exact configured identity without printing values", 1
    )[0]
    provider_identity = live.split(
        "- name: Check writer secret names and exact configured identity without printing values", 1
    )[1].split("- name: Run only the selected pinned read-only writer calls", 1)[0]
    writer = live.split("- name: Run only the selected pinned read-only writer calls", 1)[1].split(
        "- name: Sanitize the completed writer capture", 1
    )[0]
    assert "working-directory: trusted-runner" in exact_preflight
    assert "working-directory: trusted-runner" in provider_identity
    assert "working-directory: trusted-runner" in writer
    assert "writer-live-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}" in live
    assert 'prepare-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}' in text
    assert 'private-shadow-prepare-output' in text and 'private-shadow-live-output' in live
    assert "LLM_BASE_URL: ${{ secrets.LLM_BASE_URL }}" in live
    assert "LLM_MODEL: ${{ secrets.LLM_MODEL }}" in live
    assert "LLM_API_KEY: ${{ secrets.LLM_API_KEY }}" in live
    writer_path = live.split("Build private model-only audit configs", 1)[0]
    assert "JEV_API_KEY" not in writer_path and "JEV_BASE_URL" not in writer_path
    audit_config = live.split("Build private model-only audit configs", 1)[1].split("      - name:", 1)[0]
    audit_dispatch = live.split("Run one bounded model-only audit packet", 1)[1].split("      - name:", 1)[0]
    assert "if: steps.packet-selection.outputs.validated == 'true'" in audit_config
    assert (
        "if: steps.packet-selection.outputs.validated == 'true' && "
        "steps.audit-config.outputs.validated == 'true'"
    ) in audit_dispatch
    assert "JEV_API_KEY: ${{ secrets.JEV_API_KEY }}" in audit_config
    assert "build_model_only_shadow_writer_provider_config.py" in live
    assert 'private-shadow-runtime-config/provider.json' in live
    assert "--private-shadow-plan" in live and "--private-shadow-preflight-receipt" in live
    assert "--max-claim-assessments 0" in live
    assert "--private-shadow-capture" in live
    assert "--source-only-no-candidate" in live
    assert "--selection-receipt \"$RUNNER_TEMP/private-shadow-preparation/packet-selection.json\"" in live
    assert "Sanitize the completed writer capture" in live
    upload = live.split("- name: Upload only the hash-only writer accounting artifacts", 1)[1].split("      - name:", 1)[0]
    assert "private-writer-sanitized/writer-receipt.json" in upload
    assert "private-writer-sanitized/writer-outcomes.json" in upload
    assert "private-writer-capture" not in upload and "private-shadow-preparation" not in upload
    assert "audit_or_jev_dispatched" in (ROOT / "scripts" / "sanitize_model_only_shadow_writer_receipt.py").read_text()


def test_writer_receipt_upload_runs_after_later_audit_failure_only_when_sanitized():
    text = WORKFLOW.read_text(encoding="utf-8")
    sanitize = text.split("id: writer-sanitize", 1)[1].split("# AuditDispatchGuard", 1)[0]
    upload = text.split("- name: Upload only the hash-only writer accounting artifacts", 1)[1].split(
        "- name: Upload only the hash-only model-only audit receipt", 1
    )[0]
    assert "set -euo pipefail" in sanitize
    assert sanitize.index("sanitize_model_only_shadow_writer_receipt.py") < sanitize.index(
        "echo 'validated=true' >> \"$GITHUB_OUTPUT\""
    )
    assert "if: always() && steps.writer-sanitize.outputs.validated == 'true'" in upload
    assert "private-writer-sanitized/writer-receipt.json" in upload
    assert "private-writer-sanitized/writer-outcomes.json" in upload
    assert "private-writer-capture" not in upload
    assert "writer-result.json" not in upload
    assert "writer-stage-diagnostic.json" not in upload


def test_live_activation_keeps_each_provider_boundary_fail_closed_and_private():
    text = WORKFLOW.read_text(encoding="utf-8")
    live = text.split("  live_writer:", 1)[1]
    preflight = live.index("id: exact-preflight")
    identity = live.index("id: provider-identity")
    writer = live.index("id: writer\n")
    writer_receipt = live.index("id: writer-sanitize")
    audit_config = live.index("id: audit-config")
    audit = live.index("id: shadow-audit")
    audit_receipt = live.index("id: audit-sanitize")
    selector = live.index("id: packet-selection")
    source_gate = live.index("id: source-only-gate")
    sealed_jev = live.index("id: sealed-jev\n")
    assert preflight < identity < writer < writer_receipt < selector < audit_config < audit < audit_receipt < source_gate < sealed_jev
    assert "if: steps.exact-preflight.outputs.verified == 'true'" in live[identity:writer]
    assert "steps.provider-identity.outputs.validated == 'true'" in live[writer:writer_receipt]
    assert "if: steps.packet-selection.outputs.validated == 'true'" in live[audit_config:audit]
    assert "steps.audit-config.outputs.validated == 'true'" in live[audit:audit_receipt]
    assert "writer_calls\") != 10" in live[selector:audit_config]
    assert "audit_provider_calls\") != 0" in live[selector:audit_config]
    source_gate_script = live[source_gate:sealed_jev]
    assert '"source_auditor": 1, "jev": 0, "claim_auditor": 0' in source_gate_script
    assert 'receipt["roles"].get("source_auditor") not in {"completed", "abstained"}' in source_gate_script
    assert 'receipt["roles"].get("jev") != "not_run"' in source_gate_script
    assert 'receipt["roles"].get("claim_auditor") != "not_run"' in source_gate_script
    jev_step = live[sealed_jev:live.index("id: package-selection")]
    assert "run_sealed_source_record_jev.py" in jev_step and "--live" in jev_step
    assert "claim_auditor" not in jev_step

    audit_runner = (ROOT / "scripts" / "run_model_only_shadow_audit.py").read_text(encoding="utf-8")
    guard = (ROOT / "src" / "pr_review_harness" / "shadow_preflight.py").read_text(encoding="utf-8")
    assert "AuditDispatchGuard(limits)" in audit_runner
    assert "dispatch_guard.check(role, request_bytes)" in audit_runner
    assert "before_dispatch=before_dispatch" in audit_runner
    assert all(role in guard for role in ("source_auditor", '"jev"', "claim_auditor"))
    assert '"max_packets": 1' in (ROOT / "experiments" / "model-only-shadow-audit-limits-v1.json").read_text()

    uploads = live.split("      - name: Upload only the hash-only writer accounting artifacts", 1)[1].split(
        "      - name: Remove private live-writer workspace", 1
    )[0]
    assert "private-writer-sanitized/writer-receipt.json" in uploads
    assert "private-writer-sanitized/writer-outcomes.json" in uploads
    assert "private-shadow-audit-sanitized/shadow-audit-receipt.json" in uploads
    assert "private-writer-capture" not in uploads
    assert "private-shadow-audit-output" not in uploads
    jev_upload = live.split("- name: Upload only the hash-only sealed Jev receipt", 1)[1].split(
        "- name:", 1
    )[0]
    assert "source-record-jev-receipt.json" in jev_upload and "retention-days: 7" in jev_upload
    assert "private-shadow-jev-sanitized/source-record-jev-receipt.json" in jev_upload
    assert "source-record-jev-advisory-summary.json" not in text
    assert "--write-private-advisory-summary" not in jev_step
    assert "private-writer-sanitized/packet-selection.json" in uploads
    cleanup = live.split("- name: Remove private live-writer workspace", 1)[1]
    assert '"private-shadow-jev-sanitized"' in cleanup
    assert "PUBLISH_REVIEW" not in text and "gh pr review" not in text


def test_live_writer_failure_reports_only_allowlisted_json_and_stage_code():
    text = WORKFLOW.read_text(encoding="utf-8")
    live = text.split("  live_writer:", 1)[1]
    writer = live.split("- name: Run only the selected pinned read-only writer calls", 1)[1].split(
        "- name: Sanitize the completed writer capture", 1
    )[0]
    assert "scripts/run_pr_review_stage_diagnostic.py" in writer
    assert "--stage-output \"$RUNNER_TEMP/private-shadow-preparation/writer-stage-diagnostic.json\"" in writer
    assert "--input \"$RUNNER_TEMP/private-shadow-preparation/writer-result.json\"" in writer
    assert "--stage-input \"$RUNNER_TEMP/private-shadow-preparation/writer-stage-diagnostic.json\"" in writer
    assert "--exit-code \"$cli_exit_code\"" in writer
    assert "--json > \"$RUNNER_TEMP/private-shadow-preparation/writer-result.json\" 2>/dev/null; then" in writer
    assert "python3 scripts/extract_pr_review_failure_code.py" in writer
    assert "exit \"$cli_exit_code\"" in writer
    upload = live.split("- name: Upload only the hash-only writer accounting artifacts", 1)[1].split(
        "- name: Remove private live-writer workspace", 1
    )[0]
    assert "writer-result.json" not in upload
    assert "writer-stage-diagnostic.json" not in upload
    assert '"private-shadow-preparation"' in live.split("- name: Remove private live-writer workspace", 1)[1]


def test_workflow_pins_the_historical_case_runtime_and_never_uploads_raw_data():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "5873c3f1b297a96c49b78cbcb7be674ab70b3cea" in text
    assert "1c94fabdbd5419a2da5beeed1e6d72030af2af71531f3a58defe1bf0a34ff9c0" in text
    assert "--mode staged-pr464 --prepare-only --input-contract specialist-input-v2" in text
    assert 'mkdir -m 700 -p "$RUNNER_TEMP/private-shadow-preparation"' not in text
    upload = text.split("- name: Upload only the sanitized preparation receipt", 1)[1].split("      - name:", 1)[0]
    assert "${{ runner.temp }}/private-shadow-sanitized/summary.json" in upload
    assert "${{ runner.temp }}/private-shadow-sanitized/manifest.json" in upload
    assert "private-shadow-preparation/summary.json" not in upload
    assert "steps.sanitize.outputs.validated == 'true'" in upload
    assert "private/" not in upload and "capture" not in upload
    assert text.index("Upload only the sanitized preparation receipt") < text.index("Remove private preparation workspace")


def test_live_case_selector_is_a_closed_two_case_choice_with_fixed_paths():
    text = WORKFLOW.read_text(encoding="utf-8")
    live = text.split("  live_writer:", 1)[1]
    choice = text.split("      live_case:", 1)[1].split("\n\n", 1)[0]
    assert "type: choice" in choice
    assert "- PR-464" in choice and "- PR-457" in choice and "PR-463" not in choice
    assert "id: case" in live and "case_id not in contracts" in live
    assert '"plan_path": f"experiments/model-only-shadow-live-pr{case_id[3:]}-plan-v2.json"' in live
    assert '--plan "${{ steps.case.outputs.plan_path }}"' in live
    assert "ref: ${{ steps.case.outputs.head_sha }}" in live
    assert '--base "${{ steps.case.outputs.base_sha }}"' in live
    assert '--private-shadow-case-id "${{ steps.case.outputs.case_id }}"' in live
    assert '--private-shadow-preflight-case-id "${{ steps.case.outputs.case_id }}" --max-claim-assessments 0' in live


def test_legacy_prepare_and_live_writer_keep_their_distinct_snapshot_pins():
    legacy = json.loads(BUDGET.read_text(encoding="utf-8"))
    live = json.loads((ROOT / "experiments" / "model-only-shadow-live-pr464-plan-v2.json").read_text())
    historical_hash = "3fcb39bbe80bbc10d02fbfef98abc6f73f9f46b829776515a6c9f9df69787663"
    capture_hash = "e45e9327fcb1ad37d6c37155fb40499f3179fc8dfd73d16a8d261f3a18691868"
    assert legacy["case"]["snapshot_sha256"] == historical_hash
    assert live["case"]["snapshot_sha256"] == capture_hash
    assert historical_hash in (ROOT / "scripts" / "sanitize_model_only_shadow_preflight.py").read_text()
    assert capture_hash in (ROOT / "scripts" / "verify_model_only_shadow_live_preflight.py").read_text()


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
