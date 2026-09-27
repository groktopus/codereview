from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

NODE = shutil.which("node")
ACTION_SCRIPT = Path(__file__).parents[1] / "scripts/actions-artifact-uploader/hosted-recovery.mjs"
REHEARSAL_SCRIPTS = Path(__file__).parents[1] / "scripts"


def _run_action(tmp_path: Path, child_body: str, *, deadline_ms: int = 2_000):
    if NODE is None:
        pytest.skip("Node.js is not available")
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "scripts").mkdir()
    (workspace / "scripts" / "hosted_recovery_rehearsal.py").write_text("# fake child target\n")
    wheel = runner_temp / "recovery.whl"
    wheel.write_bytes(b"fake wheel")
    root, stage = runner_temp / "root", runner_temp / "stage"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    capture = tmp_path / "captured.json"
    fake_python = bin_dir / "python"
    fake_python.write_text(
        f"#!{sys.executable}\nimport json, os, sys\n"
        f"open({str(capture)!r}, 'w', encoding='utf-8').write(json.dumps({{'env':dict(os.environ),'argv':sys.argv[1:]}}))\n"
        f"{child_body}\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o700)
    env = {
        "PATH": str(bin_dir), "HOME": str(tmp_path), "TMPDIR": str(tmp_path),
        "RUNNER_TEMP": str(runner_temp), "GITHUB_WORKSPACE": str(workspace),
        "GITHUB_REPOSITORY": "groktopus/codereview", "GITHUB_RUN_ID": "42",
        "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_WORKFLOW_REF": "groktopus/codereview/.github/workflows/hosted-recovery-rehearsal.yml@refs/heads/main",
        "GITHUB_EVENT_PATH": str(tmp_path / "enclosing-workflow-event.json"),
        "ACTIONS_RUNTIME_TOKEN": "synthetic-runtime-token-canary",
        "ACTIONS_RESULTS_URL": "https://results.actions.githubusercontent.com/",
        "ACTIONS_RUNTIME_URL": "https://actions.githubusercontent.com/",
        "GITHUB_TOKEN": "synthetic-github-token-canary",
        "HOSTED_RECOVERY_FAKE_KEY": "synthetic-provider-key-canary",
        "OPENAI_API_KEY": "synthetic-openai-key-canary",
        "INPUT_MODE": "hosted-recovery-run-a", "INPUT_ROOT": str(root),
        "INPUT_STAGE": str(stage), "INPUT_SOURCE_ROOT": str(workspace), "INPUT_WHEEL": str(wheel),
    }
    runner = (
        "import {runHostedRecovery} from " + json.dumps(ACTION_SCRIPT.as_uri()) + "; "
        f"try {{ await runHostedRecovery({{deadlineMs:{deadline_ms}}}); process.exitCode=0; }} "
        "catch (error) { process.stderr.write(String(error.message)+'\\n'); process.exitCode=1; }"
    )
    completed = subprocess.run(
        [NODE, "--input-type=module", "-e", runner],
        cwd=workspace, env=env, capture_output=True, text=True, timeout=5, check=False,
    )
    return completed, capture


def test_hosted_action_passes_runtime_allowlist_but_not_github_or_provider_secrets(tmp_path):
    completed, captured = _run_action(tmp_path, "print('helper_started')")
    assert completed.returncode == 0
    assert completed.stdout == "helper_started\n"
    assert all(secret not in completed.stdout + completed.stderr for secret in (
        "synthetic-runtime-token-canary", "synthetic-github-token-canary",
        "synthetic-provider-key-canary", "synthetic-openai-key-canary",
    ))
    data = json.loads(captured.read_text(encoding="utf-8"))
    forwarded = data["env"]
    expected_environment = {
        "PATH", "HOME", "TMPDIR", "GITHUB_WORKSPACE", "GITHUB_REPOSITORY", "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT", "GITHUB_REF", "GITHUB_SHA", "GITHUB_WORKFLOW_REF",
        "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RESULTS_URL", "ACTIONS_RUNTIME_URL",
    }
    # CPython on macOS may add these process-local locale/encoding values at startup.
    assert set(forwarded) - expected_environment <= {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
    assert expected_environment <= set(forwarded)
    assert forwarded["ACTIONS_RUNTIME_TOKEN"] == "synthetic-runtime-token-canary"
    assert "GITHUB_TOKEN" not in forwarded and "HOSTED_RECOVERY_FAKE_KEY" not in forwarded
    assert "OPENAI_API_KEY" not in forwarded
    assert "GITHUB_EVENT_PATH" not in forwarded
    assert data["argv"] == [
        str(tmp_path / "workspace" / "scripts" / "hosted_recovery_rehearsal.py"), "run-a",
        "--root", str(tmp_path / "runner-temp" / "root"),
        "--stage", str(tmp_path / "runner-temp" / "stage"),
        "--source-root", str(tmp_path / "workspace"),
        "--wheel", str(tmp_path / "runner-temp" / "recovery.whl"),
    ]


def test_hosted_action_caps_child_output_and_stops_owned_process(tmp_path):
    completed, _captured = _run_action(tmp_path, "print('x' * 70000)", deadline_ms=2_000)
    assert completed.returncode != 0
    assert "hosted_recovery_action_output_exceeded" in completed.stderr
    assert len(completed.stdout.encode()) <= 64 * 1024


def _nested_cli_helper_body(tmp_path: Path, *, emit_overflow: bool) -> str:
    marker = tmp_path / "detached-cli-survived"
    started_marker = tmp_path / "detached-cli-started"
    pid_file = tmp_path / "detached-cli.pid"
    child_source = (
        f"import pathlib,time; pathlib.Path({str(started_marker)!r}).write_text('started'); "
        f"time.sleep(2.5); pathlib.Path({str(marker)!r}).write_text('survived')"
    )
    parts = [
        "import signal, subprocess, time\n"
        f"sys.path.insert(0, {str(REHEARSAL_SCRIPTS)!r})\n"
        "import hosted_recovery_rehearsal as recovery\n"
        f"child_code={child_source!r}\n"
        "child=subprocess.Popen([sys.executable,'-c',child_code],start_new_session=True,"
        "env={'PATH':os.environ.get('PATH','')})\n"
        f"open({str(pid_file)!r},'w',encoding='ascii').write(str(child.pid))\n"
        "signal.signal(signal.SIGTERM,recovery._sigterm_as_keyboard_interrupt)\n",
    ]
    parts.extend([
        "try:\n"
        " startup_deadline=time.monotonic()+1.0\n"
        f" started_marker={str(started_marker)!r}\n"
        " while not os.path.exists(started_marker) and time.monotonic()<startup_deadline: time.sleep(0.01)\n"
        " if not os.path.exists(started_marker): raise RuntimeError('nested_cli_did_not_start')\n",
    ])
    if emit_overflow:
        parts.append(" print('x' * 70000, flush=True)\n")
    parts.extend([
        " while True: time.sleep(0.05)\n"
        "except KeyboardInterrupt:\n"
        " pass\n"
        "finally:\n"
        " recovery._terminate(child)\n",
    ])
    return "".join(parts)


@pytest.mark.parametrize(("emit_overflow", "deadline_ms", "expected_error"), [
    (True, 3_000, "hosted_recovery_action_output_exceeded"),
    (False, 1_500, "hosted_recovery_action_deadline_exhausted"),
])
def test_abnormal_stop_cleans_nested_detached_fake_cli(
    tmp_path, emit_overflow, deadline_ms, expected_error,
):
    completed, _capture = _run_action(
        tmp_path, _nested_cli_helper_body(tmp_path, emit_overflow=emit_overflow),
        deadline_ms=deadline_ms,
    )
    assert completed.returncode != 0
    assert expected_error in completed.stderr
    assert (tmp_path / "detached-cli.pid").exists()
    assert (tmp_path / "detached-cli-started").read_text(encoding="ascii") == "started"
    marker = tmp_path / "detached-cli-survived"
    import time
    time.sleep(2.7)
    assert not marker.exists()


def test_detached_cli_survival_sentinel_positive_control(tmp_path):
    started_marker = tmp_path / "control-cli-started"
    marker = tmp_path / "control-cli-survived"
    child_source = (
        f"import pathlib,time; pathlib.Path({str(started_marker)!r}).write_text('started'); "
        f"time.sleep(0.1); pathlib.Path({str(marker)!r}).write_text('survived')"
    )
    subprocess.run([sys.executable, "-c", child_source], check=True, timeout=2)
    assert started_marker.read_text(encoding="ascii") == "started"
    assert marker.read_text(encoding="ascii") == "survived"
