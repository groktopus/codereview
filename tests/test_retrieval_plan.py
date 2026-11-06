"""Deterministic retrieval-plan compilation over captured snapshot evidence."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from pr_review_harness.planner import plan_review
from pr_review_harness.retrieval_plan import (
    RetrievalPlanError,
    assess_retrieval_sufficiency,
    build_retrieval_plan,
    derive_changed_symbols,
    enclosing_definition,
    plan_hash,
    record_dispatch_retrieval_plans,
)
from pr_review_harness.review_stages import prepare_dispatch
from pr_review_harness.review_state import RunState

HEAD = "c" * 40
BASE = "b" * 40
SOURCE = (
    "class Service:\n"
    "    def target(self):\n"
    "        return 1\n"
    "\n"
    "def unrelated():\n"
    "    return 2\n"
    "\n"
    "def changed_enclosing():\n"
    "    value = 1\n"
    "    return value\n"
)


def make_snapshot(*, with_source=True, test_source=True):
    inventory = [
        {
            "unit_id": "u1",
            "path": "src/m1.py",
            "kind": "human_code",
            "change": "modified",
            "diff": "@@ -1 +1 @@\n+def target(self):\n+def unrelated():\n+class Service:",
            "changed_lines": [[9, 10]],
            "evidence_ids": ["diff:u1", "head:u1"],
        }
    ]
    evidence = {
        "diff:u1": {
            "evidence_id": "diff:u1",
            "path": "src/m1.py",
            "source_kind": "diff",
            "content": "+def target(self):\n+def unrelated():\n+class Service:",
            "content_hash": "a" * 64,
            "source_revision": HEAD,
            "trust": "untrusted_pr_content",
        }
    }
    if with_source:
        evidence["head:u1"] = {
            "evidence_id": "head:u1",
            "path": "src/m1.py",
            "source_kind": "head_file",
            "content": SOURCE,
            "content_hash": hashlib.sha256(SOURCE.encode()).hexdigest(),
            "source_revision": HEAD,
            "source_object_id": "e" * 40,
            "line_start": 1,
            "line_end": 10,
            "content_truncated": False,
            "trust": "untrusted_pr_content",
        }
    if test_source:
        test = "from src.m1 import target\n\ndef test_target():\n    assert target() == 1\n"
        inventory.append(
            {
                "unit_id": "u2",
                "path": "tests/test_m1.py",
                "kind": "test",
                "change": "added",
                "diff": "+def test_target():\n+    assert target() == 1",
                "evidence_ids": ["diff:u2", "head:u2"],
            }
        )
        evidence["diff:u2"] = {
            "evidence_id": "diff:u2",
            "path": "tests/test_m1.py",
            "source_kind": "diff",
            "content": "+def test_target():\n+    assert target() == 1",
            "content_hash": "d" * 64,
            "source_revision": HEAD,
            "trust": "untrusted_pr_content",
        }
        evidence["head:u2"] = {
            "evidence_id": "head:u2",
            "path": "tests/test_m1.py",
            "source_kind": "head_file",
            "content": test,
            "content_hash": hashlib.sha256(test.encode()).hexdigest(),
            "source_revision": HEAD,
            "line_start": 1,
            "line_end": 4,
            "content_truncated": False,
            "trust": "untrusted_pr_content",
        }
    return {
        "snapshot_id": "snap-plan",
        "base_sha": BASE,
        "head_sha": HEAD,
        "inventory": inventory,
        "evidence": evidence,
    }


def make_profile(patterns=None):
    return {"version": "p1", "retrieval_context_patterns": patterns or ["src/*.py", "tests/*.py"]}


def make_task():
    return {
        "task_id": "t1",
        "obligation_id": "unit:u1:lens:correctness",
        "obligation_ids": ["unit:u1:lens:correctness"],
        "unit_ids": ["u1"],
        "scope_unit_ids": ["u1"],
        "lens": "correctness",
        "task_kind": "SPECIALIST_FINDINGS",
    }


LIMITS = {"max_context_bytes": 120_000, "max_input_bytes_per_task": 45_000}


def test_changed_symbols_are_derived_from_the_captured_diff_in_order():
    diff = "--- a/src/m1.py\n+++ b/src/m1.py\n+def added_first():\n-def removed_one():\n+class AddedClass:\n def context_line():\n+def added_first():"
    assert derive_changed_symbols(diff) == [
        {"symbol": "added_first", "change": "added"},
        {"symbol": "removed_one", "change": "removed"},
        {"symbol": "AddedClass", "change": "added"},
    ]


def test_enclosing_definition_resolves_function_class_and_missing_ranges():
    assert enclosing_definition(SOURCE, 3) == ("target", 2)
    assert enclosing_definition(SOURCE, 10) == ("changed_enclosing", 8)
    assert enclosing_definition(SOURCE, 99) is None
    assert enclosing_definition("def only():\n    pass\n", 2) == ("only", 1)


def test_plan_resolves_enclosing_definition_and_referenced_test_paths():
    plan = build_retrieval_plan(
        make_snapshot(), make_profile(), make_task(), LIMITS, {"unit:u1:lens:correctness": {"scope_unit_ids": ["u1"]}}
    )
    unit = plan["units"][0]
    assert [item["symbol"] for item in unit["changed_symbols"]] == ["target", "unrelated", "Service"]
    assert unit["referenced_test_paths"][0]["path"] == "tests/test_m1.py"
    assert unit["referenced_test_paths"][0]["unit_id"] == "u2"
    assert {window["role"] for window in unit["windows"]} == {"changed_definition", "enclosing_definition"}
    enclosing = next(window for window in unit["windows"] if window["role"] == "enclosing_definition")
    assert enclosing["symbol"] == "changed_enclosing"
    assert enclosing["line_start"] <= 8 <= enclosing["line_end"]
    window_text = "\n".join(SOURCE.split("\n")[enclosing["line_start"] - 1 : enclosing["line_end"]]) + "\n"
    assert enclosing["content_hash"] == hashlib.sha256(window_text.encode()).hexdigest()


def test_multiple_windows_are_bounded_deduplicated_and_deterministically_ordered():
    snapshot = make_snapshot()
    first = build_retrieval_plan(snapshot, make_profile(), make_task(), LIMITS)
    second = build_retrieval_plan(make_snapshot(), make_profile(), make_task(), LIMITS)
    assert first["units"][0]["windows"] == second["units"][0]["windows"]
    windows = first["units"][0]["windows"]
    keys = [
        (w["path"], w["source_revision"], w["line_start"], w["line_end"], w["content_hash"], w["role"], w["symbol"])
        for w in windows
    ]
    assert keys == sorted(keys)
    assert len(keys) == len(set(keys))
    assert all(w["source_revision"] == HEAD for w in windows)
    assert all(w["content_hash"] for w in windows)
    assert len(windows) <= 4


def test_plan_hash_is_stable_and_ignores_volatile_fields():
    snapshot = make_snapshot()
    plan = build_retrieval_plan(snapshot, make_profile(), make_task(), LIMITS)
    repeated = build_retrieval_plan(make_snapshot(), make_profile(), make_task(), LIMITS)
    assert plan["plan_hash"] == repeated["plan_hash"] == plan_hash(plan)
    volatile = make_snapshot()
    volatile["captured_at"] = "2099-01-01T00:00:00+00:00"
    for item in volatile["evidence"].values():
        item["captured_at"] = "2099-01-01T00:00:00+00:00"
    assert build_retrieval_plan(volatile, make_profile(), make_task(), LIMITS)["plan_hash"] == plan["plan_hash"]
    mutated = make_snapshot()
    mutated["evidence"]["head:u1"]["line_start"] = 2
    assert build_retrieval_plan(mutated, make_profile(), make_task(), LIMITS)["plan_hash"] != plan["plan_hash"]


def test_missing_source_window_records_a_required_typed_gap_before_dispatch():
    plan = build_retrieval_plan(make_snapshot(with_source=False), make_profile(), make_task(), LIMITS)
    assert plan["units"][0]["windows"] == []
    assert [gap["code"] for gap in plan["gaps"]] == ["changed_symbol_window_unavailable"]
    assert plan["gaps"][0]["severity"] == "REQUIRED"
    assert plan["gaps"][0]["symbols"] == ["target", "unrelated", "Service"]
    sufficient = assess_retrieval_sufficiency(plan)
    assert sufficient == {"schema": "retrieval-plan.v1", "sufficient": False, "required_gap_count": 1}


def test_non_allowlisted_referenced_path_fails_closed_with_a_typed_gap():
    plan = build_retrieval_plan(make_snapshot(), make_profile(["src/*.py"]), make_task(), LIMITS)
    assert not plan["sufficiency"]["sufficient"]
    assert [gap["code"] for gap in plan["gaps"]] == ["referenced_test_not_allowlisted"]
    assert plan["gaps"][0]["paths"] == ["tests/test_m1.py"]
    assert plan["units"][0]["referenced_test_paths"] == []


def test_invalid_snapshot_identity_fails_closed():
    snapshot = make_snapshot()
    snapshot["head_sha"] = "not-a-sha"
    with pytest.raises(RetrievalPlanError):
        build_retrieval_plan(snapshot, make_profile(), make_task(), LIMITS)


def test_record_dispatch_retrieval_plans_persists_plans_and_gaps():
    state = SimpleNamespace(
        snapshot=make_snapshot(with_source=False),
        snapshot_captured_evidence=make_snapshot(with_source=False)["evidence"],
        profile=make_profile(),
        limits=LIMITS,
        primary_tasks=[make_task()],
        obligation_by_id={"unit:u1:lens:correctness": {"scope_unit_ids": ["u1"]}},
        ledger={},
        checkpoint=lambda: None,
    )
    record_dispatch_retrieval_plans(state)
    assert state.retrieval_sufficient is False
    assert state.ledger["retrieval_plans"][0]["plan_hash"] == state.retrieval_plans[0]["plan_hash"]
    assert state.ledger["retrieval_plan_gaps"][0]["task_id"] == "t1"
    assert state.ledger["retrieval_plan_gaps"][0]["severity"] == "REQUIRED"


def test_prepare_dispatch_records_the_plan_before_provider_dispatch(tmp_path):
    snapshot = make_snapshot()
    profile = make_profile()
    plan = plan_review(snapshot, profile)
    state = RunState(
        snapshot=snapshot,
        plan=plan,
        profile=profile,
        provider=None,
        decision_provider=None,
        limits={
            "deadline_seconds": 2,
            "max_concurrent_scopes": 1,
            "max_provider_calls": 1,
            "max_retries_per_task": 0,
            "max_context_bytes": 120_000,
            "max_input_bytes_per_task": 45_000,
            "max_output_bytes_per_task": 16_000,
            "max_output_bytes": 192_000,
            "max_context_retrievals": 1,
            "max_followup_tasks": 1,
        },
        output_dir=str(tmp_path),
        run_id="plan-run",
        resume=False,
        freshness_check=None,
        context_retriever=None,
        check_adapter=None,
        claim_assessor=None,
        max_claim_assessments=0,
        private_capture_dir=None,
        private_capture_case_id=None,
        private_capture_request_pins=None,
        private_capture_snapshot_pin=None,
        private_capture_source_audit_max_bytes=64_000,
    )
    from pr_review_harness import review_stages

    review_stages.preflight_review(state)
    assert review_stages.resume_completed_review(state) is None
    review_stages.bind_run_state(state)
    review_stages.install_review_input_size(state)
    prepare_dispatch(state)
    assert state.ledger["retrieval_plans"]
    assert all(item["task_id"] for item in state.ledger["retrieval_plans"])
