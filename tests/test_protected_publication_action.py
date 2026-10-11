import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
ACTION = ROOT / "scripts/protected-publication-action"
NODE = shutil.which("node")


def _run_launcher(tmp_path, python_body, *, env_overrides=None, deadline_ms=1000):
    if NODE is None:
        pytest.skip("Node.js is not available")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    marker = tmp_path / "child-ran"
    python = bin_dir / "python"
    python.write_text(
        "#!/bin/sh\n"
        f"touch {json.dumps(str(marker))}\n"
        + python_body,
        encoding="utf-8",
    )
    python.chmod(0o700)
    env = {
        "PATH": f"{bin_dir}:/bin:/usr/bin",
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
        "GITHUB_WORKSPACE": str(ROOT),
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_TOKEN": "read-only-token",
        "GITHUB_EVENT_PATH": str(tmp_path / "event.json"),
        "ACTIONS_RUNTIME_TOKEN": "runtime-token-secret",
        "ACTIONS_RESULTS_URL": "https://results.actions.githubusercontent.com/",
        "PR_REVIEW_ANALYSIS_WORKFLOW_NAME": "PR Review Analysis",
        "PYTHONPATH": str(ROOT / "src"),
        "UNTRUSTED_SENTINEL": "must-not-reach-python",
        "LLM_API_KEY": "must-not-reach-python",
    }
    env.update(env_overrides or {})
    runner = (
        "import {runProtectedPublication} from "
        + json.dumps((ACTION / "main.mjs").as_uri())
        + f"; process.exitCode = await runProtectedPublication({{deadlineMs: {deadline_ms}}});"
    )
    started = time.monotonic()
    completed = subprocess.run(
        [NODE, "--input-type=module", "-e", runner],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return completed, marker, time.monotonic() - started


def test_launcher_uses_fixed_module_and_only_forwards_explicit_runtime_context(tmp_path):
    args_file = tmp_path / "args"
    token_file = tmp_path / "token"
    results_file = tmp_path / "results-url"
    body = (
        f"printf '%s\\n' \"$@\" > {json.dumps(str(args_file))}\n"
        f"printf '%s' \"$ACTIONS_RUNTIME_TOKEN\" > {json.dumps(str(token_file))}\n"
        f"printf '%s' \"$ACTIONS_RESULTS_URL\" > {json.dumps(str(results_file))}\n"
        'test "$GITHUB_TOKEN" = "read-only-token" || exit 11\n'
        'test "$PR_REVIEW_ANALYSIS_WORKFLOW_NAME" = "PR Review Analysis" || exit 12\n'
        'test -z "${UNTRUSTED_SENTINEL+x}" || exit 13\n'
        'test -z "${LLM_API_KEY+x}" || exit 14\n'
        'printf \'{"schema":"pr-review-protected-publication.v1","status":"UNKNOWN","reason":"publication_history_incomplete","no_effect_receipt":{"status":"ACKNOWLEDGED","reason":"readback_verified"}}\\n\'\n'
        'printf "credential-must-not-be-logged" >&2\n'
        "exit 0\n"
    )
    completed, marker, _elapsed = _run_launcher(tmp_path, body)

    assert completed.returncode == 0
    assert marker.exists()
    assert args_file.read_text(encoding="utf-8").splitlines() == [
        "-P",
        "-m",
        "pr_review_harness.protected_publication_runtime",
    ]
    assert token_file.read_text(encoding="utf-8") == "runtime-token-secret"
    assert results_file.read_text(encoding="utf-8") == "https://results.actions.githubusercontent.com/"
    assert json.loads(completed.stdout) == {
        "schema": "pr-review-protected-publication.v1",
        "status": "UNKNOWN",
        "reason": "publication_history_incomplete",
        "no_effect_receipt": {"status": "ACKNOWLEDGED", "reason": "readback_verified"},
    }
    assert "credential-must-not-be-logged" not in completed.stdout + completed.stderr
    assert "runtime-token-secret" not in completed.stdout + completed.stderr


def test_launcher_propagates_child_failure_without_forwarding_child_output(tmp_path):
    completed, marker, _elapsed = _run_launcher(
        tmp_path,
        'printf "private-child-output"; printf "private-child-error" >&2; exit 23\n',
    )

    assert marker.exists()
    assert completed.returncode == 23
    assert completed.stdout == ""
    assert completed.stderr == ""


def test_launcher_rejects_child_output_containing_runtime_credential(tmp_path):
    completed, marker, _elapsed = _run_launcher(
        tmp_path,
        'printf \'{"schema":"pr-review-protected-publication.v1","status":"UNKNOWN","reason":"runtime-token-secret"}\\n\'\n'
        'printf "%s\\n" "$ACTIONS_RUNTIME_TOKEN"\n',
    )

    assert marker.exists()
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "protected_publication_launcher_failed\n"


def test_launcher_rejects_unrecognized_outcome_fields_without_echoing_them(tmp_path):
    completed, marker, _elapsed = _run_launcher(
        tmp_path,
        'printf \'{"schema":"pr-review-protected-publication.v1","status":"UNKNOWN","reason":null,"debug":"private"}\\n\'\n',
    )

    assert marker.exists()
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "protected_publication_launcher_failed\n"


def test_launcher_accepts_the_configured_github_actions_bot_actor(tmp_path):
    payload = json.dumps(
        {
            "schema": "pr-review-protected-publication.v1",
            "status": "CONFIRMED",
            "reason": None,
            "effect_observation": {
                "actor_login": "github-actions[bot]",
                "review_state": "COMMENTED",
                "review_id": 123,
                "write_capability": "OBSERVED_SUCCESS",
            },
        }
    )
    completed, marker, _elapsed = _run_launcher(
        tmp_path,
        f"printf '%s\\n' {shlex.quote(payload)}\n",
    )

    assert marker.exists()
    assert completed.returncode == 0
    assert json.loads(completed.stdout)["effect_observation"]["actor_login"] == "github-actions[bot]"


def test_launcher_rejects_oversized_child_outcome(tmp_path):
    completed, marker, _elapsed = _run_launcher(tmp_path, "head -c 9000 /dev/zero\n")

    assert marker.exists()
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "protected_publication_launcher_failed\n"


def test_launcher_python_safe_path_prevents_target_workspace_module_shadowing(tmp_path):
    if NODE is None:
        pytest.skip("Node.js is not available")
    workspace = tmp_path / "target-workspace"
    poison = workspace / "pr_review_harness"
    poison.mkdir(parents=True)
    marker = tmp_path / "poison-imported"
    (poison / "protected_publication_runtime.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('imported')\n"
        "print('{\\\"schema\\\":\\\"pr-review-protected-publication.v1\\\",\\\"status\\\":\\\"CONFIRMED\\\",\\\"reason\\\":null}')\n",
        encoding="utf-8",
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python_shim = bin_dir / "python"
    python_shim.write_text(f"#!/bin/sh\nexec {sys.executable!r} \"$@\"\n", encoding="utf-8")
    python_shim.chmod(0o700)
    env = {
        "PATH": f"{bin_dir}:/bin:/usr/bin",
        "GITHUB_WORKSPACE": str(workspace),
        "PYTHONPATH": str(ROOT / "src"),
        "ACTIONS_RUNTIME_TOKEN": "runtime-token-secret",
        "ACTIONS_RESULTS_URL": "https://results.actions.githubusercontent.com/",
    }
    runner = (
        "import {runProtectedPublication} from "
        + json.dumps((ACTION / "main.mjs").as_uri())
        + "; process.exitCode = await runProtectedPublication();"
    )
    completed = subprocess.run(
        [NODE, "--input-type=module", "-e", runner],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )
    assert not marker.exists()
    assert completed.returncode == 0
    outcome = json.loads(completed.stdout)
    assert outcome["schema"] == "pr-review-protected-publication.v1"
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] != "target_workspace_module_imported"


def test_launcher_fails_before_child_when_runtime_credentials_are_unavailable(tmp_path):
    completed, marker, _elapsed = _run_launcher(
        tmp_path,
        "exit 0\n",
        env_overrides={"ACTIONS_RUNTIME_TOKEN": ""},
    )

    assert not marker.exists()
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "protected_publication_launcher_failed\n"


def test_launcher_deadline_stops_the_owned_python_process(tmp_path):
    completed, marker, elapsed = _run_launcher(tmp_path, "exec sleep 5\n", deadline_ms=250)

    assert marker.exists()
    assert completed.returncode == 1
    assert elapsed < 2
    assert completed.stderr == "protected_publication_launcher_failed\n"


def test_launcher_forwards_cancellation_to_owned_child_group(tmp_path):
    if NODE is None:
        pytest.skip("Node.js is not available")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "child-started"
    pid_file = tmp_path / "child-pid"
    python = bin_dir / "python"
    python.write_text(
        "#!/bin/sh\n"
        f"touch {json.dumps(str(marker))}\n"
        f"echo $$ > {json.dumps(str(pid_file))}\n"
        "exec sleep 15\n",
        encoding="utf-8",
    )
    python.chmod(0o700)
    env = {
        "PATH": f"{bin_dir}:/bin:/usr/bin",
        "GITHUB_WORKSPACE": str(ROOT),
        "PYTHONPATH": str(ROOT / "src"),
        "ACTIONS_RUNTIME_TOKEN": "runtime-token-secret",
        "ACTIONS_RESULTS_URL": "https://results.actions.githubusercontent.com/",
    }
    runner = (
        "import {runProtectedPublication} from "
        + json.dumps((ACTION / "main.mjs").as_uri())
        + "; process.exitCode = await runProtectedPublication({deadlineMs: 10000});"
    )
    launched = subprocess.Popen(
        [NODE, "--input-type=module", "-e", runner],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    end = time.monotonic() + 3
    while not marker.exists() and time.monotonic() < end:
        time.sleep(0.02)
    assert marker.exists()
    child_pid = int(pid_file.read_text(encoding="utf-8"))
    launched.terminate()
    stdout, stderr = launched.communicate(timeout=2)
    assert launched.returncode == 143
    assert stdout == ""
    assert stderr == ""
    end = time.monotonic() + 1
    while time.monotonic() < end:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        pytest.fail("launcher cancellation left the child process running")
