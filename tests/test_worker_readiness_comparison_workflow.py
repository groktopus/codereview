from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path

import pytest

from scripts.effect_observer_smoke import (
    LONG_WAIT_ENGINE_DEADLINE_SECONDS,
    LONG_WAIT_OBSERVER_TIMEOUT_SECONDS,
    LONG_WAIT_PROVIDER_DELAY_SECONDS,
    LONG_WAIT_PROVIDER_TIMEOUT_SECONDS,
)

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "worker-readiness-comparison.yml"
BASELINE_SHA = "2116506c8e5a08158c51645502bbcaec6bf9e71f"
BASELINE_PARENT_SHA = "94d35b43d6441e412e3c6123d354c5e78d6c12e9"
COMPARISON_CONTRACT = "worker-readiness-linux.v2"
TRACE_CAP = 1_048_576
OBSERVER_ID = "linux-strace-syscall-observer.v3"
SYSCALL_SCOPE = ["%process", "%file", "socket", "connect", "bind", "listen", "accept", "accept4", "shutdown"]


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _comparison_python_tree() -> ast.Module:
    text = _workflow_text()
    marker = "- name: Run the identical bounded loopback fixture against both installed CLIs"
    section = text.split(marker, maxsplit=1)[1]
    match = re.search(r"(?ms)^\s+\"\$PROBE_PYTHON\" - <<'PY'\n(?P<source>.*?)^\s+PY\s*$", section)
    assert match is not None, "comparison Python heredoc is missing"
    return ast.parse(textwrap.dedent(match.group("source")))


def _comparison_guards() -> tuple[object, object, object, object, object]:
    tree = _comparison_python_tree()
    selected = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {"result", "complete", "valid_baseline_cap_failure", "marker_state"}
    ]
    assert {node.name for node in selected} == {"result", "complete", "valid_baseline_cap_failure", "marker_state"}
    marker_assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id in {"markers", "target_marker_state"} for target in node.targets)
    ]
    assert len(marker_assignments) == 2
    aggregate = ast.FunctionDef(
        name="aggregate_marker_state",
        args=ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg="baseline"), ast.arg(arg="candidate")],
            kwonlyargs=[],
            kw_defaults=[],
            defaults=[],
        ),
        body=marker_assignments + [ast.Return(value=ast.Name(id="target_marker_state", ctx=ast.Load()))],
        decorator_list=[],
    )
    selected.append(aggregate)
    module = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
    environment: dict[str, object] = {
        "identity": {
            "observer_id": OBSERVER_ID,
            "observer_source_sha256": "a" * 64,
            "syscall_scope": SYSCALL_SCOPE,
            "trace_byte_cap": TRACE_CAP,
        }
    }
    exec(compile(module, str(WORKFLOW), "exec"), environment)
    return (
        environment["result"],
        environment["complete"],
        environment["valid_baseline_cap_failure"],
        environment["marker_state"],
        environment["aggregate_marker_state"],
    )


def _candidate_report(**result_overrides: object) -> dict[str, object]:
    result = {
        "status": "NORMAL_REVIEW_COMPLETED",
        "coverage_state": "COMPLETE",
        "completed_tasks": 4,
        "provider_calls": 4,
        "retries": 0,
        "freshness": "CURRENT",
        "disposition": "COMMENT",
        "observer_coverage": "SCOPED_COMPLETE",
        "event_aggregates_complete": True,
        "trace_bytes": 820_000,
        "trace_byte_cap": TRACE_CAP,
        "target_code_execution": False,
    }
    result.update(result_overrides)
    probe = {
        "status": "COMPLETED",
        "observer_id": OBSERVER_ID,
        "observer_source_sha256": "a" * 64,
        "syscall_scope": SYSCALL_SCOPE,
        "provider_endpoint_kind": "LOOPBACK_FAKE",
        "external_provider_dispatch_requested": False,
        "trace_byte_cap": TRACE_CAP,
        "target_execution_marker_present": False,
        "result": result,
    }
    return {"runner_status": "COMPLETED", "return_code": 0, "probe": probe}


def _baseline_cap_failure(
    *,
    trace_bytes: object = 1_048_523,
    reason: str = "trace_byte_cap_exceeded",
    runner_status: str = "COMPLETED",
) -> dict[str, object]:
    return {
        "runner_status": runner_status,
        "return_code": 1,
        "probe": {
            "status": "FAILED_OR_INCOMPLETE",
            "observer_id": OBSERVER_ID,
            "observer_source_sha256": "a" * 64,
            "syscall_scope": SYSCALL_SCOPE,
            "provider_endpoint_kind": "LOOPBACK_FAKE",
            "external_provider_dispatch_requested": False,
            "result": {
                "status": "NORMAL_REVIEW_FAILED",
                "failure_stage": "observer_scope_or_trace_incomplete",
                "observer_coverage": "INCOMPLETE",
                "observer_reason": reason,
                "observer_trace_bytes": trace_bytes,
                "trace_byte_cap": TRACE_CAP,
                "target_execution_marker_present": False,
                "fake_provider_calls": 4,
            },
            "trace_byte_cap": TRACE_CAP,
            "target_execution_marker_present": False,
        },
    }


def test_workflow_pins_sources_builds_both_wheels_and_checks_complete_module_identity():
    text = _workflow_text()
    assert f"BASELINE_SHA: {BASELINE_SHA}" in text
    assert f"ref: {BASELINE_SHA}" in text
    assert f"BASELINE_PARENT_SHA: {BASELINE_PARENT_SHA}" in text
    assert f"COMPARISON_CONTRACT: {COMPARISON_CONTRACT}" in text
    assert "fetch-depth: 2" in text
    assert "CANDIDATE_SHA: ${{ github.event.pull_request.head.sha }}" in text
    assert "ref: ${{ github.event.pull_request.head.sha }}" in text
    assert "path: baseline-source" in text and "path: candidate-source" in text
    assert "${{ github.workspace }}/baseline-source" in text
    assert "${{ github.workspace }}/candidate-source" in text
    assert 'expected_module_count = 28 if label == "BASELINE" else 35' in text
    assert '"module_counts_per_runtime"' in text
    assert "source_modules != installed_modules" in text
    assert '"git", "-C", str(source), "rev-parse", "HEAD^"' in text
    assert "parent != os.environ[\"BASELINE_PARENT_SHA\"]" in text
    assert 'changed_paths != ["src/pr_review_harness/external_effect_observer.py"]' in text
    assert "added_lines != [" in text and "removed_lines" in text
    assert '    "invalid_review_request": "invalid_review_request",' in text
    assert '    "run_id_already_exists": "run_id_already_exists",' in text
    assert '    "resume_state_invalid": "resume_state_invalid",' in text
    assert "baseline_compatibility_patch_mismatch" in text
    assert "observer_runtime_source_changed" in text
    assert 'pip wheel --no-deps --wheel-dir "$BASELINE_WHEELHOUSE" "$BASELINE_SOURCE"' in text
    assert 'pip wheel --no-deps --wheel-dir "$CANDIDATE_WHEELHOUSE" "$CANDIDATE_SOURCE"' in text
    assert 'pip install --no-deps --no-index "$BASELINE_WHEELHOUSE"/*.whl' in text
    assert 'pip install --no-deps --no-index "$CANDIDATE_WHEELHOUSE"/*.whl' in text
    assert "persist-credentials: false" in text
    assert '"fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest()' in text
    assert "fixture_sha != expected_fixture_sha" in text
    assert "FIXTURE_HASH_MISMATCH" in text
    assert '"comparison_contract": os.environ["COMPARISON_CONTRACT"]' in text
    assert '"baseline_parent_sha": os.environ["BASELINE_PARENT_SHA"]' in text
    assert '"baseline_kind": "observer_diagnostic_compatibility_backport"' in text
    assert text.count('"schema_version": 2') >= 6
    assert '"schema_version": 1' not in text
    assert "worker-readiness-comparison-v2-${{ github.run_id }}" in text
    assert "worker-readiness-comparison-v2/identity.json" in text


def test_workflow_is_read_only_secretless_and_always_retains_bounded_receipts():
    text = _workflow_text()
    assert "permissions:\n  contents: read" in text
    assert "${{ secrets." not in text
    assert "LLM_API_KEY" not in text and "JEV_API_KEY" not in text
    assert "permissions:\n      contents: read" in text
    assert "publication_requested" in text
    assert "probe_timeout = 185" in text
    assert "max_output = 128 * 1024" in text
    assert "max_report = 128 * 1024" in text
    assert "SUMMARY_LIMIT_EXCEEDED" in text
    assert "target-source" not in text
    assert "sudo unshare --net -- env" in text
    assert '"failure": "isolated_loopback_unavailable"' in text
    assert '"probes_started": False' in text
    assert "sudo -E" not in text
    assert "sudo unshare --net -- env -i" in text
    probe_step = text.split("sudo unshare --net -- env -i", maxsplit=1)[1].split('"$PROBE_PYTHON"', maxsplit=1)[0]
    expected_bindings = {
        "ARTIFACT_DIR": 'ARTIFACT_DIR="$ARTIFACT_DIR"',
        "LONG_WAIT_FIXTURE": 'LONG_WAIT_FIXTURE="$LONG_WAIT_FIXTURE"',
        "BASELINE_CLI": 'BASELINE_CLI="$BASELINE_CLI"',
        "CANDIDATE_CLI": 'CANDIDATE_CLI="$CANDIDATE_CLI"',
        "HOME": 'HOME="$ARTIFACT_DIR"',
        "PATH": 'PATH="$PATH"',
    }
    for binding in expected_bindings.values():
        assert binding in probe_step
    assert '"$PROBE_PYTHON" - <<' in text
    loopback_commands = [
        node.args[0]
        for node in ast.walk(_comparison_python_tree())
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "run"
        and node.args
        and isinstance(node.args[0], ast.List)
        and all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in node.args[0].elts)
    ]
    assert ["ip", "link", "set", "lo", "up"] in [
        [item.value for item in command.elts] for command in loopback_commands
    ]
    assert "if: always()" in text
    assert "timeout-minutes: 10" in text
    for receipt in ("identity.json", "baseline.json", "candidate.json", "comparison.json"):
        assert receipt in text
    assert "retention-days: 7" in text


def test_long_wait_source_keeps_fixed_comparison_deadlines_and_trace_scope():
    assert LONG_WAIT_PROVIDER_DELAY_SECONDS == 75.0
    assert LONG_WAIT_PROVIDER_TIMEOUT_SECONDS == 120.0
    assert LONG_WAIT_ENGINE_DEADLINE_SECONDS == 150
    assert LONG_WAIT_OBSERVER_TIMEOUT_SECONDS == 180.0
    assert LONG_WAIT_PROVIDER_DELAY_SECONDS < LONG_WAIT_PROVIDER_TIMEOUT_SECONDS
    assert LONG_WAIT_PROVIDER_TIMEOUT_SECONDS < LONG_WAIT_ENGINE_DEADLINE_SECONDS
    assert LONG_WAIT_ENGINE_DEADLINE_SECONDS < LONG_WAIT_OBSERVER_TIMEOUT_SECONDS <= 270
    text = _workflow_text()
    assert '"trace_byte_cap": 1_048_576' in text


def test_candidate_guard_accepts_typed_complete_review_only():
    _, complete, _, _, _ = _comparison_guards()
    assert complete(_candidate_report()) is True


@pytest.mark.parametrize(
    "change",
    [
        {"freshness": "STALE"},
        {"coverage_state": "INCOMPLETE"},
        {"event_aggregates_complete": False},
        {"trace_bytes": TRACE_CAP + 1},
        {"trace_bytes": True},
        {"trace_bytes": -1},
        {"trace_bytes": 0},
        {"target_code_execution": True},
    ],
)
def test_candidate_guard_rejects_stale_incomplete_or_malformed_results(change):
    _, complete, _, _, _ = _comparison_guards()
    assert complete(_candidate_report(**change)) is False


def test_baseline_guard_accepts_only_typed_trace_cap_failure_or_complete_success():
    result, complete, baseline_guard, _, _ = _comparison_guards()
    assert baseline_guard(_baseline_cap_failure()) is True
    assert baseline_guard(_candidate_report()) is False
    # A baseline that completes the same honest workload is also a valid comparator.
    report = _candidate_report()
    assert complete(report) is True
    assert result(report)[1]["status"] == "NORMAL_REVIEW_COMPLETED"


@pytest.mark.parametrize(
    "change",
    [
        {"reason": "unknown"},
        {"reason": "trace_unfinished_syscall"},
        {"trace_bytes": TRACE_CAP + 1},
        {"trace_bytes": True},
        {"trace_bytes": -1},
        {"trace_bytes": 0},
        {"runner_status": "SPAWN_FAILED"},
    ],
)
def test_baseline_guard_rejects_import_failure_and_untyped_or_other_failures(change):
    _, _, baseline_guard, _, _ = _comparison_guards()
    assert baseline_guard(_baseline_cap_failure(**change)) is False


def test_baseline_guard_rejects_missing_cli_result_or_identity_mismatch():
    _, _, baseline_guard, _, _ = _comparison_guards()
    report = _baseline_cap_failure()
    report["probe"]["result"] = None
    assert baseline_guard(report) is False

    report = _baseline_cap_failure()
    report["probe"]["observer_source_sha256"] = "b" * 64
    assert baseline_guard(report) is False


@pytest.mark.parametrize(
    ("baseline_values", "candidate_values", "expected"),
    [
        ((True, False, False), (False, False, False), "PRESENT"),
        ((False, True, False), (False, False, False), "PRESENT"),
        ((False, False, False), (False, False, False), "ABSENT"),
        ((None, None, None), (None, None, None), "UNKNOWN"),
        (("false", False, False), (None, None, None), "UNKNOWN"),
        ((None, None, None), (False, None, False), "UNKNOWN"),
        ((None, None, None), (None, True, False), "PRESENT"),
    ],
)
def test_target_marker_aggregation_preserves_present_absent_and_unknown(baseline_values, candidate_values, expected):
    _, _, _, _, aggregate_marker_state = _comparison_guards()

    def report(values):
        outer, inner, code = values
        return {
            "probe": {
                "target_execution_marker_present": outer,
                "result": {"target_execution_marker_present": inner, "target_code_execution": code},
            }
        }

    assert aggregate_marker_state(report(baseline_values), report(candidate_values)) == expected
