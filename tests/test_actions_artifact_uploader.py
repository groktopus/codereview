import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ACTION = Path(__file__).parents[1] / "scripts/actions-artifact-uploader"


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
