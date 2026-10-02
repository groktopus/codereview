"""Guard the closed PR-457 workflow's runtime and credential boundaries."""

from pathlib import Path

import yaml

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
    assert '--jev-config "$RUNNER_TEMP/pr457-private/audit-config/decision.json"' in audit["run"]


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
    step = _steps(_workflow())["Upload only sanitized writer and role receipts"]
    paths = step["with"]["path"]

    assert "writer-receipt.json" in paths
    assert "writer-outcomes.json" in paths
    assert "writer-reconciliation.json" in paths
    assert "shadow-audit-receipt.json" in paths
    for private_name in ("writer-result.json", "writer-capture", "audit-output", "audit-config"):
        assert private_name not in paths
