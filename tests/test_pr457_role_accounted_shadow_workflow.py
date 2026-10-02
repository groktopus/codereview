"""Guard the closed PR-457 workflow's runtime and credential boundaries."""

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from pr_review_harness import cli
from scripts import sanitize_model_only_shadow_writer_receipt as writer_sanitizer

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/pr457-role-accounted-shadow.yml"


def _workflow() -> dict:
    return yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _steps(workflow: dict) -> dict[str, dict]:
    return {step["name"]: step for step in workflow["jobs"]["review"]["steps"]}


def test_manual_workflow_is_disabled_by_default_and_read_only() -> None:
    workflow = _workflow()

    assert workflow["on"]["workflow_dispatch"]["inputs"]["run_live"]["default"] == "false"
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["review"]["permissions"] == {"contents": "read"}
    assert "github.repository == 'groktopus/codereview'" in workflow["jobs"]["review"]["if"]
    assert "github.ref == 'refs/heads/main'" in workflow["jobs"]["review"]["if"]


def test_installed_current_source_paths_and_output_creation_order_are_consistent() -> None:
    steps = _steps(_workflow())
    writer = steps["Run the bounded read-only PR-457 writer"]["run"]
    sanitizer = steps["Sanitize writer capture accounting"]
    count = steps["Check candidate count from sanitized reconciliation"]["run"]
    audit = steps["Run the current-source role-accounted audit"]["run"]

    assert '--private-shadow-plan "$RUNNER_TEMP/pr457-current-source-plan.json"' in writer
    assert '--private-shadow-preflight-receipt "$RUNNER_TEMP/pr457-current-source-receipt.json"' in writer
    assert "--private-shadow-current-source-plan" in writer
    assert sanitizer["env"]["PR457_CURRENT_SOURCE_RUNTIME"] == "1"
    assert "--current-source" in sanitizer["run"]
    assert '"$RUNNER_TEMP/pr457-writer-capture"' in writer
    assert 'mkdir -m 700 "$RUNNER_TEMP/pr457-writer-capture"' not in writer
    assert '"$RUNNER_TEMP/pr457-writer-sanitized"' in sanitizer["run"]
    assert "0 <= count <= 120" in count
    assert "--current-source-plan \"$RUNNER_TEMP/pr457-current-source-plan.json\"" in audit
    assert 'mkdir -m 700 "$RUNNER_TEMP/pr457-private/audit-receipt"' in audit
    assert '"$RUNNER_TEMP/pr457-private/audit-output"' not in audit.split("mkdir", 1)[-1].split("\n", 1)[0]


def test_jev_configuration_and_secret_are_skipped_for_zero_candidates() -> None:
    steps = _steps(_workflow())
    materialize = steps["Materialize bounded audit provider configs"]
    audit = steps["Run the current-source role-accounted audit"]

    assert "steps.candidate-count.outputs.count != '0'" in materialize["if"]
    assert audit["env"]["JEV_API_KEY"] == (
        "${{ steps.candidate-count.outputs.count != '0' && secrets.JEV_API_KEY || '' }}"
    )
    assert 'if [[ "${{ steps.candidate-count.outputs.count }}" != "0" ]]; then' in audit["run"]
    assert '--jev-config "$RUNNER_TEMP/pr457-audit-config/decision.json"' in audit["run"]


def test_workflow_config_builders_accept_private_direct_runner_temp_paths(tmp_path: Path) -> None:
    steps = _steps(_workflow())
    writer_command = steps["Materialize the fixed writer provider config"]["run"]
    audit_command = steps["Materialize bounded audit provider configs"]["run"]
    writer_match = re.search(r'--output-dir "\$RUNNER_TEMP/([^"/]+)"', writer_command)
    audit_match = re.search(r'--output-dir "\$RUNNER_TEMP/([^"/]+)"', audit_command)
    assert writer_match is not None and writer_match.group(1) == "pr457-writer-config"
    assert audit_match is not None and audit_match.group(1) == "pr457-audit-config"
    install = steps["Build and install the exact current harness wheel"]["run"]
    assert '"--force-reinstall"' in install

    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir(mode=0o700)
    os.chmod(runner_temp, 0o700)
    plan = ROOT / "experiments/model-only-shadow-live-pr457-plan-v3.json"
    identity = json.loads(plan.read_text(encoding="utf-8"))["provider_identity"]
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(ROOT / "src"),
        "RUNNER_TEMP": str(runner_temp),
        "LLM_BASE_URL": identity["writer_base_url"],
        "LLM_MODEL": identity["writer_model"],
        "LLM_API_KEY": "local-test-placeholder",
        "JEV_BASE_URL": "https://api.typesafe.ai/v1",
        "JEV_MODEL": "jev-latest",
        "JEV_API_KEY": "local-test-placeholder",
    }
    writer_output = runner_temp / writer_match.group(1)
    writer_result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/build_model_only_shadow_writer_provider_config.py"),
         "--plan", str(plan), "--output-dir", str(writer_output)],
        cwd=ROOT, env=env, capture_output=True, text=True, check=False,
    )
    assert writer_result.returncode == 0, writer_result.stderr
    writer_config = writer_output / "provider.json"
    assert stat.S_IMODE(writer_output.stat().st_mode) == 0o700
    assert stat.S_IMODE(writer_config.stat().st_mode) == 0o600
    assert b"local-test-placeholder" not in writer_config.read_bytes()

    audit_output = runner_temp / audit_match.group(1)
    audit_result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/provider_config_from_env.py"),
         "--output-dir", str(audit_output), "--json"],
        cwd=ROOT, env=env, capture_output=True, text=True, check=False,
    )
    assert audit_result.returncode == 0, audit_result.stderr
    audit_paths = json.loads(audit_result.stdout)
    assert Path(audit_paths["provider_config"]).parent == audit_output
    assert Path(audit_paths["decision_config"]).parent == audit_output
    assert stat.S_IMODE(audit_output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(Path(value).stat().st_mode) == 0o600 for value in audit_paths.values())
    assert all(b"local-test-placeholder" not in Path(value).read_bytes() for value in audit_paths.values())


def test_workflow_capture_and_sanitizer_paths_match_trusted_actions_admission(tmp_path: Path, monkeypatch) -> None:
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir(mode=0o700)
    os.chmod(runner_temp, 0o700)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("PR_REVIEW_TRUSTED_PRIVATE_CAPTURE", "1")
    monkeypatch.setenv("GITHUB_REPOSITORY", "groktopus/codereview")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", cli.TRUSTED_CURRENT_SOURCE_CAPTURE_WORKFLOW_REF)
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("RUNNER_TEMP", str(runner_temp))

    capture = runner_temp / "pr457-writer-capture"
    output = runner_temp / "pr457-private" / "writer-output"
    cli._validate_private_capture_target(str(capture), str(output))

    nested_capture = runner_temp / "pr457-private" / "writer-capture"
    nested_capture.parent.mkdir(mode=0o700)
    nested_capture.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="direct child of RUNNER_TEMP"):
        cli._validate_private_capture_target(str(nested_capture), str(output))

    capture.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="new direct child of RUNNER_TEMP"):
        cli._validate_private_capture_target(str(capture), str(output))
    with pytest.raises(writer_sanitizer.ReceiptError, match="input_unavailable"):
        writer_sanitizer.sanitize(
            capture, runner_temp / "missing-plan.json", runner_temp / "missing-preflight.json",
            runner_temp / "pr457-writer-sanitized", current_source=True,
        )
    sanitizer_script = ROOT / "scripts/sanitize_model_only_shadow_writer_receipt.py"
    sanitizer_env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(ROOT / "src"),
        "PR457_CURRENT_SOURCE_RUNTIME": "1",
        "RUNNER_TEMP": str(runner_temp),
    }
    direct_result = subprocess.run(
        [sys.executable, str(sanitizer_script), "--capture-root", str(capture),
         "--plan", str(runner_temp / "missing-plan.json"),
         "--preflight", str(runner_temp / "missing-preflight.json"), "--current-source",
         "--output-dir", str(runner_temp / "pr457-writer-sanitized")],
        cwd=ROOT, env=sanitizer_env, capture_output=True, text=True, check=False,
    )
    assert direct_result.returncode == 2
    assert json.loads(direct_result.stderr)["error_code"] == "input_unavailable"

    nested_result = subprocess.run(
        [sys.executable, str(sanitizer_script), "--capture-root", str(nested_capture),
         "--plan", str(runner_temp / "missing-plan.json"),
         "--preflight", str(runner_temp / "missing-preflight.json"), "--current-source",
         "--output-dir", str(runner_temp / "pr457-writer-sanitized-nested-check")],
        cwd=ROOT, env=sanitizer_env, capture_output=True, text=True, check=False,
    )
    assert nested_result.returncode == 2
    assert json.loads(nested_result.stderr)["error_code"] == "private_paths_invalid"


def test_preparation_records_only_bounded_runtime_identity() -> None:
    steps = _steps(_workflow())
    temp = steps["Create private provider-free preparation paths"]["run"]
    identity = steps["Record hash-only installed runtime identity"]["run"]
    prepare_upload = steps["Upload only the hash-only provider-free preparation evidence"]["with"]["path"]

    assert "os.chmod(root, 0o700)" in temp
    assert '"wheel_sha256": digest.hexdigest()' in identity
    assert '"python_version": platform.python_version()' in identity
    assert '"source_sha": source_sha' in identity
    assert "runtime-identity.json" in prepare_upload
    assert "LLM_API_KEY" not in identity and "JEV_API_KEY" not in identity
    assert "writer-result.json" not in prepare_upload


def test_review_upload_is_limited_to_sanitized_receipts() -> None:
    steps = _steps(_workflow())
    step = steps["Upload only sanitized writer and role receipts"]
    paths = step["with"]["path"]

    assert "writer-receipt.json" in paths
    assert "writer-outcomes.json" in paths
    assert "writer-task-diagnostics.json" in paths
    assert "writer-reconciliation.json" in paths
    assert "shadow-audit-receipt.json" in paths
    assert step["if"] == "always() && inputs.run_live == true && steps.writer.outcome == 'success'"
    assert step["with"]["if-no-files-found"] == "ignore"
    for private_name in ("writer-cli-output.json", "writer-capture", "audit-output", "audit-config"):
        assert private_name not in paths


def test_reconciliation_reads_hash_bound_durable_writer_result_and_upload_survives_later_failure() -> None:
    steps = _steps(_workflow())
    writer = steps["Run the bounded read-only PR-457 writer"]["run"]
    sanitize = steps["Sanitize writer capture accounting"]["run"]

    run_id = 'writer-live-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}'
    durable = f'--result "$RUNNER_TEMP/pr457-private/writer-output/{run_id}.json"'
    assert f'--run-id "{run_id}"' in writer
    assert durable in sanitize
    assert "--result \"$RUNNER_TEMP/pr457-private/writer-cli-output.json\"" not in sanitize
    assert 'if: always() && inputs.run_live == true && steps.writer.outcome == \'success\'' in WORKFLOW.read_text()
