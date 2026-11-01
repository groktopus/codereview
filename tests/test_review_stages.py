"""Stage-level tests for the extracted review controller (CA-1).

These tests exercise stages directly with a constructed :class:`RunState`.  They
do not run a full review and never dispatch a provider call.
"""

import ast
import json
from pathlib import Path

import pytest

import pr_review_harness.engine as engine_module
import pr_review_harness.review_stages as stages
from pr_review_harness.budget import BudgetExhausted
from pr_review_harness.engine import EnginePreflightError
from pr_review_harness.planner import plan_review
from pr_review_harness.review_state import RunState

LIMITS = {
    "deadline_seconds": 5,
    "max_concurrent_scopes": 2,
    "max_provider_calls": 2,
    "max_retries_per_task": 0,
    "max_context_bytes": 120_000,
    "max_input_bytes_per_task": 45_000,
    "max_output_bytes_per_task": 16_000,
    "max_output_bytes": 192_000,
    "max_context_retrievals": 2,
    "max_followup_tasks": 0,
}

STAGE_NAMES = [
    "preflight_review",
    "resume_completed_review",
    "bind_run_state",
    "install_review_input_size",
    "prepare_dispatch",
    "install_budget_helpers",
    "quote_monetary_budget",
    "install_attempt_lifecycle",
    "dispatch_tasks",
    "prepare_followups",
    "install_followup_runner",
    "run_followups",
    "assess_claims",
    "reduce_coverage",
    "install_report_notes",
    "build_and_persist_result",
]


def make_snapshot():
    return {
        "snapshot_id": "snap",
        "base_sha": "b" * 40,
        "head_sha": "c" * 40,
        "profile_version": "p1",
        "snapshot_hash": "d" * 64,
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "inventory": [
            {
                "unit_id": "u0",
                "path": "src/m0.py",
                "kind": "human_code",
                "change": "modified",
                "diff": "-old\n+new",
                "changed_lines": [[1, 2]],
                "evidence_ids": ["diff:u0"],
            }
        ],
        "evidence": {
            "diff:u0": {
                "evidence_id": "diff:u0",
                "snapshot_id": "snap",
                "path": "src/m0.py",
                "line_start": 1,
                "line_end": 2,
                "content": "-old\n+new",
                "content_hash": "a" * 64,
                "source_kind": "diff",
                "trust": "untrusted_pr_content",
            }
        },
        "gaps": [],
    }


def make_profile():
    return {"version": "p1", "required_lenses": ["correctness"], "allow_empty_approval": True}


class OfflineProvider:
    """Records calls; every dispatch would be a test failure."""

    identity = {"kind": "stage-test", "model": "offline"}

    def __init__(self):
        self.calls = 0

    def review(self, task, evidence, limits):  # pragma: no cover - must not run
        self.calls += 1
        raise AssertionError("stage tests must not dispatch a provider call")


class UnavailableProvider:
    identity = {"kind": "stage-test", "model": "unavailable"}


class EstimatingProvider(OfflineProvider):
    def __init__(self, estimate=None):
        super().__init__()
        self.estimates = 0
        self.estimate = estimate or {
            "provider_calls": 1,
            "input_bytes": 100,
            "max_output_bytes": 1_000,
            "deadline_seconds": 1.0,
            "reservation_kind": "unknown",
        }

    def estimate_call(self, task_kind, task, evidence, limits):
        self.estimates += 1
        return dict(self.estimate)


def make_state(tmp_path, **overrides):
    snapshot = overrides.pop("snapshot", None) or make_snapshot()
    profile = overrides.pop("profile", None) or make_profile()
    plan = overrides.pop("plan", None) or plan_review(snapshot, profile)
    values = {
        "snapshot": snapshot,
        "plan": plan,
        "profile": profile,
        "provider": OfflineProvider(),
        "decision_provider": None,
        "limits": dict(LIMITS),
        "output_dir": str(tmp_path / "out"),
        "run_id": "run-1",
        "resume": False,
        "freshness_check": None,
        "context_retriever": None,
        "check_adapter": None,
        "claim_assessor": None,
        "max_claim_assessments": 0,
        "private_capture_dir": None,
        "private_capture_case_id": None,
        "private_capture_request_pins": None,
        "private_capture_snapshot_pin": None,
        "private_capture_source_audit_max_bytes": 64_000,
    }
    values.update(overrides)
    return RunState(**values)


def advance_to_dispatch(state):
    """Run the state-building stages up to (not including) dispatch."""
    stages.preflight_review(state)
    assert stages.resume_completed_review(state) is None
    stages.bind_run_state(state)
    stages.install_review_input_size(state)
    stages.install_budget_helpers(state)
    stages.install_attempt_lifecycle(state)
    stages.prepare_dispatch(state)


# ---------------------------------------------------------------------------
# structural contracts
# ---------------------------------------------------------------------------
def test_run_review_is_a_thin_coordinator_without_nested_functions():
    tree = ast.parse(Path(engine_module.__file__).read_text(encoding="utf-8"))
    run_review = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_review"
    )
    assert run_review.end_lineno - run_review.lineno + 1 <= 300
    nested = [node for node in ast.walk(run_review) if isinstance(node, ast.FunctionDef) and node is not run_review]
    assert nested == []
    called = {
        node.func.id
        for node in ast.walk(run_review)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert set(STAGE_NAMES) <= called


def test_stage_module_import_graph_is_acyclic():
    root = Path(engine_module.__file__).parent
    modules = {path.stem for path in root.glob("*.py")}
    graph = {}
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        edges = set()
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.level == 1:
                names = [node.module.split(".")[0]] if node.module else [alias.name for alias in node.names]
                edges.update(name for name in names if name in modules and name != path.stem)
        graph[path.stem] = edges
    state = {}

    def visit(name):
        if state.get(name) == "visiting":
            raise AssertionError(f"import cycle through {name}")
        if state.get(name) == "done":
            return
        state[name] = "visiting"
        for dependency in graph[name]:
            visit(dependency)
        state[name] = "done"

    for name in sorted(graph):
        visit(name)
    assert graph["review_stages"] == {"review_state"}
    assert "review_stages" in graph["engine"]


def test_every_stage_is_importable_and_takes_explicit_state():
    for name in STAGE_NAMES:
        function = getattr(stages, name)
        parameters = list(function.__code__.co_varnames[: function.__code__.co_argcount])
        assert parameters[0] == "state"
        assert "RunState" in str(function.__annotations__.get("state", ""))
        assert function.__closure__ is None
    source = Path(stages.__file__).read_text(encoding="utf-8")
    assert "nonlocal" not in source
    tree = ast.parse(source)
    nested = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node not in tree.body
    ]
    assert nested == []


def test_run_state_fields_are_explicitly_typed():
    annotations = RunState.__annotations__
    for field, expected in (
        ("snapshot", "dict"),
        ("plan", "dict"),
        ("profile", "dict"),
        ("limits", "dict"),
        ("output_dir", "str"),
        ("run_id", "str"),
        ("resume", "bool"),
        ("max_claim_assessments", "int"),
    ):
        assert annotations[field] == expected
    # Every public run_review parameter is represented on the state.
    assert set(engine_module.run_review.__annotations__) - {"return"} <= set(annotations)
    # Stage-owned fields are declared too, so a stage never invents state.
    for field in ("ledger", "budget", "tasks", "task_results", "checkpoint", "output_path"):
        assert field in annotations


# ---------------------------------------------------------------------------
# preflight / identity
# ---------------------------------------------------------------------------
def test_preflight_fails_closed_before_output_or_dispatch(tmp_path):
    provider = OfflineProvider()
    bad_limits = {**LIMITS, "max_provider_calls": 0}
    state = make_state(tmp_path, provider=provider, limits=bad_limits)
    with pytest.raises(EnginePreflightError) as excinfo:
        stages.preflight_review(state)
    assert excinfo.value.reason == "invalid_review_request"
    assert provider.calls == 0
    assert not (tmp_path / "out").exists()


def test_request_identity_is_deterministic_and_bound_before_dispatch(tmp_path):
    first = make_state(tmp_path / "a")
    second = make_state(tmp_path / "b")
    stages.preflight_review(first)
    stages.preflight_review(second)
    assert stages.resume_completed_review(first) is None
    assert stages.resume_completed_review(second) is None
    assert first.request_hash == second.request_hash
    assert len(first.request_hash) == 64
    identity = first.ledger["identity"]
    assert identity["snapshot_id"] == "snap"
    assert identity["plan_hash"] == second.ledger["identity"]["plan_hash"]
    assert [event["event"] for event in first.ledger["events"]] == ["RUN_STARTED"]
    assert first.ledger["events"][0]["event_hash"] == second.ledger["events"][0]["event_hash"]
    assert first.ledger["budget"]["reservations"] == {}


def test_install_review_input_size_prefers_provider_measure_for_specialists(tmp_path):
    class Measuring(OfflineProvider):
        def review_input_bytes(self, task, evidence, limits):
            return 41

    state = make_state(tmp_path)
    state.provider = Measuring()
    stages.install_review_input_size(state)
    assert state.review_input_size({"task_kind": "SPECIALIST_FINDINGS"}, []) == 41 + 1024
    assert state.review_input_size({"task_kind": "DETERMINISTIC_CHECK"}, []) == len(
        engine_module._canonical({"task": {"task_kind": "DETERMINISTIC_CHECK"}, "evidence": []})
    )


# ---------------------------------------------------------------------------
# reserve-before-dispatch
# ---------------------------------------------------------------------------
def test_reserve_provider_call_reserves_before_dispatch_and_replays(tmp_path):
    provider = EstimatingProvider()
    state = make_state(tmp_path, provider=provider)
    advance_to_dispatch(state)
    task = {"task_id": "task-1", "task_kind": "SPECIALIST_FINDINGS"}
    reservation = state.reserve_provider_call("task-1:review:1", provider, "SPECIALIST_FINDINGS", task, [], 100)
    assert provider.calls == 0  # reserve happens before any dispatch
    assert reservation["status"] == "RESERVED"
    assert state.budget.state["reservations"]["task-1:review:1"] == reservation
    assert state.budget.state["settlements"] == {}
    replay = state.reserve_provider_call("task-1:review:1", provider, "SPECIALIST_FINDINGS", task, [], 100)
    assert replay == reservation
    assert list(state.budget.state["reservations"]) == ["task-1:review:1"]


def test_reserve_provider_call_protects_required_claim_capacity(tmp_path):
    class Adjudicating(EstimatingProvider):
        def adjudicate(self, _candidate, _evidence, _limits):
            raise AssertionError("stage test must not adjudicate")

    def prepared(tmp_path, limits):
        state = make_state(tmp_path, provider=Adjudicating(), limits=limits)
        advance_to_dispatch(state)
        state.reconciliation_policy = {"max_assessments": 1}
        state.ledger["candidate_records"] = [{"validation_state": "VALID"}]
        return state

    # A required assessment reserves its dispatch window before anything else.
    deadline_state = prepared(tmp_path / "deadline", dict(LIMITS))
    with pytest.raises(BudgetExhausted) as deadline_error:
        deadline_state.reserve_provider_call(
            "task-1:judge:0", deadline_state.provider, "SEMANTIC_ADJUDICATION", {}, [], 10
        )
    assert "REQUIRED_CLAIM_ASSESSMENT_DEADLINE_RESERVED" in str(deadline_error.value)
    assert deadline_state.budget.state["reservations"] == {}

    # One reserved call must leave room for the still-required assessment.
    cap_state = prepared(tmp_path / "cap", {**LIMITS, "deadline_seconds": 60, "max_provider_calls": 1})
    with pytest.raises(BudgetExhausted) as cap_error:
        cap_state.reserve_provider_call(
            "task-1:judge:0", cap_state.provider, "SEMANTIC_ADJUDICATION", {}, [], 10
        )
    assert "REQUIRED_CLAIM_ASSESSMENT_CAP_RESERVED" in str(cap_error.value)
    assert cap_state.budget.state["reservations"] == {}

    # With no eligible candidate and enough calls the same request is admitted.
    free_state = prepared(tmp_path / "free", {**LIMITS, "deadline_seconds": 60, "max_provider_calls": 2})
    free_state.ledger["candidate_records"] = []
    admitted = free_state.reserve_provider_call(
        "task-1:judge:0", free_state.provider, "SEMANTIC_ADJUDICATION", {}, [], 10
    )
    assert admitted["provider_calls"] == 1


def test_reserve_provider_call_fails_closed_on_unusable_estimate(tmp_path):
    provider = EstimatingProvider(estimate=["not", "an", "estimate"])
    state = make_state(tmp_path, provider=provider)
    advance_to_dispatch(state)
    with pytest.raises(ValueError):
        state.reserve_provider_call("task-1:review:1", provider, "SPECIALIST_FINDINGS", {}, [], 10)
    assert state.budget.state["reservations"] == {}
    assert provider.calls == 0


# ---------------------------------------------------------------------------
# resume / settlement
# ---------------------------------------------------------------------------
def test_bind_run_state_settles_an_interrupted_reservation(tmp_path):
    state = make_state(tmp_path)
    stages.preflight_review(state)
    assert stages.resume_completed_review(state) is None
    state.ledger["budget"]["reservations"] = {
        "task-old:review:0": {
            "key": "task-old:review:0",
            "kind": "provider",
            "provider_calls": 1,
            "input_bytes": 10,
            "max_output_bytes": 10,
            "deadline_seconds": 1.0,
            "status": "RESERVED",
        }
    }
    stages.bind_run_state(state)
    settlement = state.budget.state["settlements"]["task-old:review:0"]
    assert settlement["status"] == "INTERRUPTED_UNKNOWN"
    assert state.ledger["invocations"][0]["status"] == "INTERRUPTED_UNKNOWN"
    assert state.ledger["invocations"][0]["reservation_key"] == "task-old:review:0"


def test_checkpoint_stage_persists_the_ledger_atomically(tmp_path):
    state = make_state(tmp_path)
    advance_to_dispatch(state)
    state.checkpoint()
    payload = json.loads(state.output_path.read_text(encoding="utf-8"))
    assert payload["run_id"] == "run-1"
    assert payload["request_hash"] == state.request_hash
    assert payload["completed_at"] is None
    assert payload["ledger"]["identity"]["snapshot_id"] == "snap"
    assert len(payload["result_hash"]) == 64
    assert not list(state.output_path.parent.glob(".*.tmp"))


def test_dispatch_stage_skips_an_unavailable_provider_without_reserving(tmp_path):
    state = make_state(tmp_path, provider=UnavailableProvider())
    advance_to_dispatch(state)
    stages.dispatch_tasks(state)
    results = list(state.task_results.values())
    assert results and all(result["status"] == "SKIPPED" for result in results)
    assert all(result["error_code"] == "PROVIDER_UNAVAILABLE" for result in results)
    assert state.budget.state["reservations"] == {}
    assert state.budget.state["settlements"] == {}
