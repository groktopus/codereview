from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from pr_review_harness import external_effect_observer as observer

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/selected-model-provider-trial.yml"
PREPARE_WORKFLOW = ROOT / ".github/workflows/selected-model-claim-trial.yml"
PIN = "dfe8b6c2d8a73f4259a1ec5112c9d34f849350d2"
OBSERVER_ID = "linux-strace-syscall-observer.v3"
OBSERVER_SOURCE_SHA256 = "fce15c42bfbc7fe66f353e8322b11f5fff1ae44a10458bba234366509f75f328"
CHECKOUT_ACTION = "11bd71901bbe5b1630ceea73d27597364c9af683"
SETUP_PYTHON_ACTION = "a26af69be951a213d495a4c3e4e4022e16d87065"
UPLOAD_ARTIFACT_ACTION = "ea165f8d65b6e75b540449e92b4886f43607fa02"
SECRET_NAMES = (
    "LLM_BASE_URL",
    "LLM_MODEL",
    "LLM_API_KEY",
    "JEV_BASE_URL",
    "JEV_MODEL",
    "JEV_API_KEY",
)


def _source(path: Path = WORKFLOW) -> str:
    return path.read_text(encoding="utf-8")


def _step(source: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"workflow_step_missing:{name}")
    end = source.find("\n      - name:", start + len(marker))
    return source[start:] if end < 0 else source[start:end]


def _python_block(step: str) -> str:
    marker = "python3 - <<'PY'\n"
    if marker not in step:
        raise AssertionError("workflow_python_run_missing")
    body = step.split(marker, 1)[1]
    lines = []
    for line in body.splitlines():
        if line.strip() == "PY":
            break
        if not line.strip():
            lines.append("")
            continue
        if not line.startswith("          "):
            break
        lines.append(line[10:])
    return "\n".join(lines) + "\n"


def test_workflow_is_manual_main_only_read_only_and_bounded():
    source = _source()
    trigger = source.split("on:\n", 1)[1].split("\npermissions:\n", 1)[0]
    assert trigger.strip() == "workflow_dispatch:"
    assert "inputs:" not in trigger
    assert "permissions:\n  contents: read\n\nconcurrency:" in source
    assert "contents: write" not in source
    assert "checks: write" not in source
    assert "pull-requests: write" not in source
    assert "actions: write" not in source
    assert "if: github.event_name == 'workflow_dispatch' && github.repository == 'groktopus/codereview' && github.ref == 'refs/heads/main'" in source
    assert "group: selected-model-provider-trial" in source
    assert "cancel-in-progress: false" in source
    assert "timeout-minutes: 20" in source


def test_trusted_runner_is_checked_out_and_verified_at_the_same_full_sha():
    source = _source()
    checkout = _step(source, "Check out the trusted runner at a full immutable revision")
    verify = _step(source, "Verify the exact trusted source revision before build or import")
    build = _step(source, "Build the wheel from the verified trusted source")
    install = _step(source, "Install the verified wheel")
    preflight = _step(source, "Preflight the bounded effect observer before provider configuration")
    trial = _step(source, "Run the fixed provider trial with private temporary configs")
    assert f"uses: actions/checkout@{CHECKOUT_ACTION}" in checkout
    assert "repository: groktopus/codereview" in checkout
    assert f"ref: {PIN}" in checkout
    assert "persist-credentials: false" in checkout
    assert f"EXPECTED_RUNNER_SHA: {PIN}" in verify
    assert '["git", "-C", source, "rev-parse", "HEAD"]' in verify
    assert "result.stdout.strip() != expected" in verify
    assert source.index("Verify the exact trusted source revision") < source.index("Build the wheel from the verified trusted source")
    assert source.index("Build the wheel from the verified trusted source") < source.index("Install the verified wheel")
    assert source.index("Install the verified wheel") < source.index("Run the fixed provider trial")
    assert source.index("Install the verified wheel") < source.index("Preflight the bounded effect observer")
    assert source.index("Preflight the bounded effect observer") < source.index("Run the fixed provider trial")
    assert f"EXPECTED_OBSERVER_SOURCE_SHA256: {OBSERVER_SOURCE_SHA256}" in preflight
    assert '[sys.executable, "-m", "pr_review_harness.external_effect_observer"]' in preflight
    assert 'identity.get("status") != "AVAILABLE"' in preflight
    assert "from pr_review_harness.external_effect_observer import OBSERVER_ID" in preflight
    assert f'OBSERVER_ID != "{OBSERVER_ID}"' in preflight
    assert 'identity.get("source_sha256") != os.environ.get("EXPECTED_OBSERVER_SOURCE_SHA256")' in preflight
    assert 'identity.get("kill_on_exit_supported") is not True' in preflight
    assert "secrets." not in preflight
    compile(_python_block(preflight), "<effect-observer-preflight>", "exec")
    assert "pip wheel --no-deps" in build
    assert '"pip", "install", "--no-deps"' in install
    assert "--cli-executable \"$(command -v pr-review)\"" in trial
    assert "--observe-effects" in trial


@pytest.mark.parametrize(
    ("mutation", "expected_returncode"),
    [("valid", 0), ("observer_id", 1), ("source_hash", 1), ("capability", 1), ("status", 1)],
)
def test_embedded_preflight_accepts_actual_cli_shape_and_rejects_identity_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, expected_returncode: int
):
    """Run the workflow's actual guard against the observer CLI's JSON contract.

    The observer CLI reports preflight status/source/capability; observer ID is
    an exported module constant rather than a field in its JSON response.
    """
    monkeypatch.setattr(observer.platform, "system", lambda: "Linux")
    monkeypatch.setattr(observer.shutil, "which", lambda name: "/usr/bin/strace")
    monkeypatch.setattr(observer, "_source_sha256", lambda *, deadline=None: "a" * 64)
    monkeypatch.setattr(observer, "_hash_file", lambda path, *, deadline=None: "b" * 64)
    probes = iter(
        [
            (0, b"strace -- version 6.8\n", b""),
            (0, b"  --kill-on-exit       kill tracees when strace exits\n", b""),
        ]
    )

    def bounded_probe(argv, *, timeout, env):
        return next(probes)

    monkeypatch.setattr(observer, "_bounded_process", bounded_probe)
    cli_identity = observer.preflight()
    assert cli_identity["status"] == "AVAILABLE"

    package = tmp_path / "pr_review_harness"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "external_effect_observer.py").write_text(
        "import json, os\n"
        "OBSERVER_ID = os.environ.get('FAKE_OBSERVER_ID', 'linux-strace-syscall-observer.v3')\n"
        "if __name__ == '__main__':\n"
        " print(os.environ['FAKE_PREFLIGHT_JSON'])\n",
        encoding="utf-8",
    )
    expected_identity = dict(cli_identity)
    observer_id = OBSERVER_ID
    if mutation == "observer_id":
        observer_id = "linux-strace-syscall-observer.v1"
    elif mutation == "source_hash":
        expected_identity["source_sha256"] = "c" * 64
    elif mutation == "capability":
        expected_identity["kill_on_exit_supported"] = False
    elif mutation == "status":
        expected_identity["status"] = "UNKNOWN"
    source_hash = cli_identity["source_sha256"]
    env = {
        **os.environ,
        "PYTHONPATH": str(tmp_path),
        "EXPECTED_OBSERVER_SOURCE_SHA256": source_hash,
        "FAKE_PREFLIGHT_JSON": json.dumps(expected_identity, sort_keys=True, separators=(",", ":")),
        "FAKE_OBSERVER_ID": observer_id,
    }

    step = _step(_source(), "Preflight the bounded effect observer before provider configuration")
    completed = subprocess.run(
        [sys.executable, "-c", _python_block(step)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == expected_returncode
    report = json.loads(completed.stdout.splitlines()[-1])
    assert report["observer_id"] == observer_id
    assert report["source_sha256"] == expected_identity["source_sha256"]


def test_only_one_bounded_step_receives_six_secrets_and_runs_helper_then_fixed_trial():
    source = _source()
    trial = _step(source, "Run the fixed provider trial with private temporary configs")
    found = re.findall(r"(?m)^\s+([A-Z0-9_]+): \$\{\{ secrets\.([A-Z0-9_]+) \}\}$", source)
    assert tuple(name for name, binding in found) == SECRET_NAMES
    assert tuple(binding for name, binding in found) == SECRET_NAMES
    for name in SECRET_NAMES:
        assert f"{name}: ${{{{ secrets.{name} }}}}" in trial
    assert source.count("secrets.") == len(SECRET_NAMES)
    assert "GITHUB_TOKEN" not in source
    assert "github.token" not in source
    assert "private_config_dir=\"$RUNNER_TEMP/selected-model-provider-config\"" in trial
    assert "--output-dir \"$private_config_dir\" --json >/dev/null" in trial
    assert "scripts/provider_config_from_env.py" in trial
    assert "--run-provider-trial" in trial
    assert "scripts/run_selected_model_trial.py" in trial
    assert "--output \"$trial_output_dir\"" in trial
    assert "--provider-config \"$private_config_dir/provider.json\"" in trial
    assert "--decision-config \"$private_config_dir/decision.json\"" in trial
    assert trial.index("scripts/provider_config_from_env.py") < trial.index("scripts/run_selected_model_trial.py")
    for selector in ("--model", "--case", "--max-provider-calls", "--max-retries", "--timeout-seconds"):
        assert selector not in trial


def test_always_cleanup_is_confined_to_the_private_config_files():
    source = _source()
    cleanup = _step(source, "Remove only the private configs created for this run")
    assert "if: always()" in cleanup
    assert "RUNNER_TEMP: ${{ runner.temp }}" in cleanup
    assert 'config_dir = runner_temp / "selected-model-provider-config"' in cleanup
    assert 'for name in ("provider.json", "decision.json"):' in cleanup
    assert "stat.S_ISLNK" in cleanup
    assert "path.unlink()" in cleanup
    assert "config_dir.rmdir()" in cleanup
    assert "rmtree" not in cleanup and "rm -rf" not in cleanup
    assert source.index("Remove only the private configs") < source.index("Upload only the sanitized summary and manifest")


def test_cleanup_script_removes_created_configs_without_touching_neighbor_paths(tmp_path):
    source = _source()
    cleanup = _step(source, "Remove only the private configs created for this run")
    script = _python_block(cleanup)
    private_dir = tmp_path / "selected-model-provider-config"
    private_dir.mkdir(mode=0o700)
    (private_dir / "provider.json").write_text('{"key_env":"LLM_API_KEY"}', encoding="utf-8")
    (private_dir / "decision.json").write_text('{"key_env":"JEV_API_KEY"}', encoding="utf-8")
    neighbor = tmp_path / "selected-model-provider-config-neighbor"
    neighbor.mkdir()
    sentinel = neighbor / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    result = subprocess.run([sys.executable, "-c", script], env={"RUNNER_TEMP": str(tmp_path)}, capture_output=True, text=True)
    assert result.returncode == 0
    assert not private_dir.exists()
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_uploaded_artifact_is_limited_to_sanitized_summary_and_manifest():
    source = _source()
    upload = _step(source, "Upload only the sanitized summary and manifest")
    assert f"uses: actions/upload-artifact@{UPLOAD_ARTIFACT_ACTION}" in upload
    assert "if: always()" in upload
    assert "name: selected-model-provider-trial-${{ github.run_id }}" in upload
    assert "${{ runner.temp }}/selected-model-provider-trial/summary.json" in upload
    assert "${{ runner.temp }}/selected-model-provider-trial/manifest.json" in upload
    assert "provider-config" not in upload
    assert "raw" not in upload.lower()
    assert "retention-days: 7" in upload
    assert "if-no-files-found: warn" in upload


def test_action_pins_are_full_sha_and_prepare_only_workflow_remains_secretless():
    source = _source()
    assert f"actions/checkout@{CHECKOUT_ACTION}" in source
    assert f"actions/setup-python@{SETUP_PYTHON_ACTION}" in source
    assert f"actions/upload-artifact@{UPLOAD_ARTIFACT_ACTION}" in source
    for match in re.finditer(r"(?m)^\s+uses: ([^\s]+)$", source):
        action = match.group(1).split("@", 1)
        assert len(action) == 2 and re.fullmatch(r"[0-9a-f]{40}", action[1]), match.group(1)
    prepare = _source(PREPARE_WORKFLOW)
    assert "--prepare-only" in prepare
    assert "--run-provider-trial" not in prepare
    assert "secrets." not in prepare
    assert "contents: read" in prepare


def test_workflow_does_not_fetch_pr_data_execute_target_code_or_publish_reviews():
    source = _source()
    for forbidden in (
        "SlopSearX", "pull_request_number", "gh api", "git clone", "target_repository",
        "pr-analysis.yml", "pr-publish.yml", "PUBLISH_REVIEW", "secrets: inherit",
    ):
        assert forbidden not in source
