from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "selected-control-trace-attribution.yml"
TRACE_CAP = 1_048_576
SYSCALL_SCOPE = ["%process", "%file", "socket", "connect", "bind", "listen", "accept", "accept4", "shutdown"]


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _embedded_python() -> list[str]:
    return [
        textwrap.dedent(match.group("source"))
        for match in re.finditer(r"(?ms)<<'PY'\n(?P<source>.*?)^\s*PY\s*$", _workflow_text())
    ]


def test_workflow_is_read_only_same_repo_and_builds_exact_installed_source():
    text = _workflow_text()
    assert "permissions:\n  contents: read" in text
    assert "github.event.pull_request.head.repo.full_name == 'groktopus/codereview'" in text
    assert "ref: ${{ github.event.pull_request.head.sha }}" in text
    assert "persist-credentials: false" in text
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in text
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in text
    assert "pip wheel --no-deps" in text and "pip install --no-deps --no-index" in text
    assert "len(source) != 28" in text
    assert "if source != installed:" in text
    assert "installed_module_inventory_mismatch" in text
    assert "secrets." not in text
    assert "GITHUB_TOKEN" not in text


def test_workflow_runs_only_bounded_loopback_observation_and_uploads_sanitized_json():
    text = _workflow_text()
    assert "ARTIFACT_DIR: ${{ runner.temp }}" not in text
    assert 'echo "ARTIFACT_DIR=$RUNNER_TEMP/selected-control-trace" >> "$GITHUB_ENV"' in text
    assert "sudo unshare --net --fork" in text
    assert "/usr/bin/setpriv --reuid" in text and "--clear-groups" in text
    assert "/usr/bin/env -i" in text
    assert "ip link set lo up" in text
    assert "PROBE_DELAY=\"$delay\"" in text
    assert "--primary-response-delay-seconds \"$PROBE_DELAY\"" in text
    assert "run_probe immediate 0" in text
    assert "run_probe primary-delay-15s 15" in text
    assert "ulimit -f" not in text
    assert "python -m json.tool \"$output\"" in text
    assert "immediate_probe_not_complete" in text
    assert "'trace_cap_bytes':TRACE_MAX_BYTES" in text
    assert "1_048_576" in text
    assert "65536" in text and "128 * 1024" in text
    assert "retention-days: 3" in text
    assert "identity.json" in text and "immediate.json" in text and "primary-delay-15s.json" in text
    assert "loopback-only-synthetic-key" in text
    assert "loopback-only-synthetic-decision-key" in text
    assert "raw_trace" not in text.lower()
    assert "target execution" not in text.lower()


def test_all_embedded_python_blocks_parse_and_delay_probe_gate_is_fail_closed():
    blocks = _embedded_python()
    assert len(blocks) == 3
    trees = [ast.parse(block) for block in blocks]
    gate = trees[1]
    selected = [
        node for node in gate.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "delay_allowed"
    ]
    assert len(selected) == 1
    module = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
    namespace: dict[str, object] = {}
    exec(compile(module, str(WORKFLOW), "exec"), namespace)
    delay_allowed = namespace["delay_allowed"]
    positive = {
        "synthetic_protocol_path_state": "COMPLETE",
        "protocol_exchange_state": "SERVER_WRITES_SETTLED",
        "observer_coverage": "SCOPED_COMPLETE",
        "trace_attribution": {"state": "COMPLETE", "trace_bytes": 500_000},
    }
    assert delay_allowed(positive, TRACE_CAP) is True
    for changed in (
        {"synthetic_protocol_path_state": "INCOMPLETE"},
        {"protocol_exchange_state": "INCOMPLETE"},
        {"observer_coverage": "INCOMPLETE"},
        {"trace_attribution": {"state": "PARTIAL", "trace_bytes": TRACE_CAP + 1}},
        {"trace_attribution": {"state": "UNKNOWN"}},
    ):
        candidate = {**positive, **changed}
        assert delay_allowed(candidate, TRACE_CAP) is False


@pytest.mark.parametrize("bad", [None, {}, {"trace_attribution": []}])
def test_delay_probe_gate_rejects_malformed_summary(bad):
    gate = ast.parse(_embedded_python()[1])
    selected = [
        node for node in gate.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "delay_allowed"
    ]
    namespace: dict[str, object] = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])), str(WORKFLOW), "exec"), namespace)
    assert namespace["delay_allowed"](bad, TRACE_CAP) is False
