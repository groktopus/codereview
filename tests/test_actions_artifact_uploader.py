import json
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ACTION = Path(__file__).parents[1] / "scripts/actions-artifact-uploader"
NODE = shutil.which("node")


def _run_canary_with_fake_python(tmp_path, child_source, *, deadline_ms=500, path=None):
    if NODE is None:
        pytest.skip("Node.js is not available")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    child_script = tmp_path / "fake-runtime.mjs"
    child_script.write_text(child_source)
    fake_python = bin_dir / "python"
    fake_python.write_text(f"#!/bin/sh\nexec {shlex.quote(NODE)} {shlex.quote(str(child_script))}\n")
    fake_python.chmod(0o700)
    env = {
        "PATH": path if path is not None else str(bin_dir),
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
        "GITHUB_WORKSPACE": str(Path(__file__).parents[1]),
        "ACTIONS_RUNTIME_TOKEN": "runtime-test-token",
        "ACTIONS_RESULTS_URL": "https://results.actions.githubusercontent.com/",
    }
    runner = (
        "import {runCanary} from "
        + json.dumps((ACTION / "canary.mjs").as_uri())
        + f"; const result = await runCanary({{deadlineMs: {deadline_ms}}}); "
        + "process.stdout.write(result.stdout); process.exitCode = result.exitCode;"
    )
    started = time.monotonic()
    completed = subprocess.run(
        [NODE, "--input-type=module", "-e", runner],
        cwd=Path(__file__).parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return completed, time.monotonic() - started


def test_node_action_passes_runtime_credentials_only_to_bounded_python_child(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not available")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python = bin_dir / "python"
    python.write_text(
        "#!/bin/sh\n"
        'test -n "$ACTIONS_RUNTIME_TOKEN" || exit 11\n'
        'test -n "$ACTIONS_RESULTS_URL" || exit 12\n'
        'test -n "$GITHUB_TOKEN" || exit 13\n'
        'test -z "$NOUS_API_KEY" || exit 14\n'
        'test -z "$TYPESAFE_API_KEY" || exit 15\n'
        'test -z "$GITHUB_ACTOR" || exit 16\n'
        'printf \'%s\\n\' \'{"state":"UNKNOWN","reason":"canary_fake_test","safe_to_publish":false}\'\n'
    )
    python.chmod(0o700)
    env = {
        "PATH": str(bin_dir),
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
        "GITHUB_WORKSPACE": str(Path(__file__).parents[1]),
        "GITHUB_TOKEN": "read-token",
        "ACTIONS_RUNTIME_TOKEN": "runtime-token",
        "ACTIONS_RESULTS_URL": "https://results.actions.githubusercontent.com/",
        "NOUS_API_KEY": "must-not-enter-python-child",
        "TYPESAFE_API_KEY": "must-not-enter-python-child",
        "GITHUB_ACTOR": "must-not-authorize-writer",
    }
    completed = subprocess.run(
        [node, str(ACTION / "canary.mjs")],
        cwd=Path(__file__).parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        "state": "UNKNOWN",
        "reason": "canary_fake_test",
        "safe_to_publish": False,
    }
    assert "runtime-token" not in completed.stdout + completed.stderr


def test_node_action_fails_closed_without_official_runtime_context(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not available")
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "GITHUB_WORKSPACE": str(Path(__file__).parents[1]),
    }
    completed = subprocess.run(
        [node, str(ACTION / "canary.mjs")],
        cwd=Path(__file__).parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        "state": "UNKNOWN",
        "reason": "actions_runtime_unavailable",
        "safe_to_publish": False,
    }


@pytest.mark.skipif(os.name == "nt", reason="process-group ownership is POSIX-specific")
def test_canary_timeout_kills_owned_process_group_and_returns_unknown(tmp_path):
    marker = tmp_path / "same-group-survived"
    child = (
        "import {spawn} from 'node:child_process';\n"
        f"const marker = {json.dumps(str(marker))};\n"
        "const code = `setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'alive'), 1400); setTimeout(() => {}, 5000)`;\n"
        "spawn(process.execPath, ['-e', code], {stdio: ['ignore', 'inherit', 'ignore']});\n"
        "setInterval(() => {}, 1000);\n"
    )
    completed, elapsed = _run_canary_with_fake_python(tmp_path, child)

    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "state": "UNKNOWN",
        "reason": "canary_deadline_exhausted",
        "safe_to_publish": False,
    }
    assert elapsed < 1.5
    time.sleep(1.5)
    assert not marker.exists()


@pytest.mark.skipif(os.name == "nt", reason="detached descendant behavior is POSIX-specific")
def test_canary_timeout_closes_owned_pipe_when_descendant_escaped_group(tmp_path):
    marker = tmp_path / "escaped-descendant-finished"
    child = (
        "import {spawn} from 'node:child_process';\n"
        f"const marker = {json.dumps(str(marker))};\n"
        "const code = `setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'finished'), 1400)`;\n"
        "spawn(process.execPath, ['-e', code], {detached: true, stdio: ['ignore', 'inherit', 'ignore']});\n"
        "setInterval(() => {}, 1000);\n"
    )
    completed, elapsed = _run_canary_with_fake_python(tmp_path, child)

    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "state": "UNKNOWN",
        "reason": "canary_deadline_exhausted",
        "safe_to_publish": False,
    }
    assert elapsed < 1.5
    deadline = time.monotonic() + 3
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.025)
    assert marker.read_text() == "finished"


def test_canary_oversized_output_is_bounded_and_fails_closed(tmp_path):
    child = "process.stdout.write('x'.repeat(70 * 1024)); setInterval(() => {}, 1000);\n"
    completed, elapsed = _run_canary_with_fake_python(tmp_path, child, deadline_ms=5_000)

    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "state": "UNKNOWN",
        "reason": "canary_runtime_failed_or_oversized",
        "safe_to_publish": False,
    }
    assert elapsed < 1.5


def test_canary_spawn_failure_does_not_leave_deadline_timer_running(tmp_path):
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()
    completed, elapsed = _run_canary_with_fake_python(
        tmp_path,
        "process.stdout.write('unused\\n');\n",
        deadline_ms=5_000,
        path=str(empty_path),
    )

    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "state": "UNKNOWN",
        "reason": "canary_runtime_failed",
        "safe_to_publish": False,
    }
    assert elapsed < 1.5


def test_canary_internal_deadline_hook_cannot_exceed_production_bound():
    if NODE is None:
        pytest.skip("Node.js is not available")
    runner = (
        "import {runCanary} from "
        + json.dumps((ACTION / "canary.mjs").as_uri())
        + "; let spawned = false; "
        + "const result = await runCanary({deadlineMs: 150001, "
        + "spawnProcess: () => { spawned = true; throw new Error('must not run'); }}); "
        + "process.stdout.write(JSON.stringify({result, spawned}));"
    )
    completed = subprocess.run(
        [NODE, "--input-type=module", "-e", runner],
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        "result": {
            "stdout": '{"state":"UNKNOWN","reason":"canary_runtime_failed","safe_to_publish":false}\n',
            "exitCode": 1,
        },
        "spawned": False,
    }
