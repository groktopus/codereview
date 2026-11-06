"""Deterministic retrieval-plan compilation over captured snapshot evidence."""

from __future__ import annotations

import copy
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
BASE_SOURCE = "def base_target():\n    return 0\n\n\ndef base_enclosing():\n    old = 1\n    return old\n"
DIFF = "@@ -1 +1 @@\n+def target(self):\n+def unrelated():\n+class Service:"
TEST_SOURCE = "from src.m1 import target\n\ndef test_target():\n    assert target() == 1\n"


def _file(path: str, source: str, revision: str, kind: str, **extra):
    return {
        "evidence_id": extra.pop("evidence_id"),
        "path": path,
        "source_kind": kind,
        "content": source,
        "content_hash": hashlib.sha256(source.encode()).hexdigest(),
        "source_revision": revision,
        "source_object_id": "e" * 40,
        "line_start": 1,
        "line_end": len(source.splitlines()),
        "content_truncated": False,
        "trust": "untrusted_pr_content",
        **extra,
    }


def make_snapshot(*, with_head=True, with_base=False, test_source=True, diff=DIFF, gaps=None, old_path=None):
    inventory = [
        {
            "unit_id": "u1",
            "path": "src/m1.py",
            "kind": "human_code",
            "change": "modified",
            "diff": diff,
            "changed_lines": [[9, 10]],
            "old_line_ranges": [[5, 5]],
            "evidence_ids": ["diff:u1"],
        }
    ]
    evidence = {
        "diff:u1": {
            "evidence_id": "diff:u1",
            "path": "src/m1.py",
            "source_kind": "diff",
            "content": diff,
            "content_hash": "a" * 64,
            "source_revision": HEAD,
            "trust": "untrusted_pr_content",
        }
    }
    if old_path is not None:
        inventory[0]["old_path"] = old_path
    if with_head:
        inventory[0]["evidence_ids"].append("head:u1")
        evidence["head:u1"] = _file("src/m1.py", SOURCE, HEAD, "head_file", evidence_id="head:u1", source_side="HEAD")
    if with_base:
        inventory[0]["evidence_ids"].append("base:u1")
        evidence["base:u1"] = _file(
            old_path or "src/m1.py", BASE_SOURCE, BASE, "base_file", evidence_id="base:u1", source_side="BASE"
        )
    if test_source:
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
        evidence["head:u2"] = _file("tests/test_m1.py", TEST_SOURCE, HEAD, "head_file", evidence_id="head:u2")
    snapshot = {
        "snapshot_id": "snap-plan",
        "base_sha": BASE,
        "head_sha": HEAD,
        "inventory": inventory,
        "evidence": evidence,
    }
    if gaps is not None:
        snapshot["gaps"] = gaps
    return snapshot


def make_profile(patterns=None, **window):
    profile = {"version": "p1", "retrieval_context_patterns": patterns or ["src/*.py", "tests/*.py"]}
    if window:
        profile["context_selection"] = {"window": window}
    return profile


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


def plans(snapshot, profile=None):
    return build_retrieval_plan(snapshot, profile or make_profile(), make_task(), LIMITS)


def codes(plan):
    return [gap["code"] for gap in plan["gaps"]]


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
    assert enclosing_definition(BASE_SOURCE, 6) == ("base_enclosing", 5)


def test_plan_resolves_enclosing_definition_and_referenced_test_paths():
    plan = plans(make_snapshot())
    unit = plan["units"][0]
    assert [item["symbol"] for item in unit["changed_symbols"]] == ["target", "unrelated", "Service"]
    assert unit["referenced_test_paths"][0]["path"] == "tests/test_m1.py"
    assert unit["referenced_test_paths"][0]["unit_id"] == "u2"
    roles = {role for window in unit["windows"] for role in window["roles"]}
    assert roles == {"changed_definition", "enclosing_definition"}
    enclosing = next(window for window in unit["windows"] if "enclosing_definition" in window["roles"])
    assert "changed_enclosing" in enclosing["symbols"]
    assert enclosing["line_start"] <= 8 <= enclosing["line_end"]
    window_text = "\n".join(SOURCE.split("\n")[enclosing["line_start"] - 1 : enclosing["line_end"]]) + "\n"
    assert enclosing["content_hash"] == hashlib.sha256(window_text.encode()).hexdigest()


def test_base_rows_use_old_line_ranges_and_base_source_side():
    plan = plans(make_snapshot(with_base=True))
    windows = plan["units"][0]["windows"]
    base = [window for window in windows if window["source_side"] == "BASE"]
    head = [window for window in windows if window["source_side"] == "HEAD"]
    assert base and head
    base_enclosing = next(window for window in base if "enclosing_definition" in window["roles"])
    assert "base_enclosing" in base_enclosing["symbols"]
    assert "changed_enclosing" not in base_enclosing["symbols"]
    head_enclosing = next(window for window in head if "enclosing_definition" in window["roles"])
    assert "changed_enclosing" in head_enclosing["symbols"]
    assert "base_enclosing" not in head_enclosing["symbols"]
    assert [window["source_side"] for window in windows[: len(head)]] == ["HEAD"] * len(head)


def test_removed_symbols_resolve_only_against_base_source():
    plan = plans(make_snapshot(with_base=True, diff="-def base_target():\n"))
    windows = plan["units"][0]["windows"]
    removed = [
        window
        for window in windows
        if window["source_side"] == "BASE"
        and "changed_definition" in window["roles"]
        and "base_target" in window["symbols"]
    ]
    assert len(removed) == 1
    assert not [
        window
        for window in windows
        if window["source_side"] == "HEAD"
        and "base_target" in window["symbols"]
        and "changed_definition" in window["roles"]
    ]


def test_rename_uses_old_path_for_base_rows_and_snapshot_gaps():
    gaps = [{"path": "src/old_m1.py", "source_kind": "base_file", "reason": "context_truncated", "required": True}]
    snapshot = make_snapshot(with_base=True, old_path="src/old_m1.py", diff="-def base_target():\n", gaps=gaps)
    snapshot["inventory"][0]["change"] = "rename"
    snapshot["inventory"][0]["old_line_ranges"] = [[5, 5]]
    plan = plans(snapshot)
    windows = plan["units"][0]["windows"]
    base = [window for window in windows if window["source_side"] == "BASE"]
    head = [window for window in windows if window["source_side"] == "HEAD"]
    assert base and head
    assert {window["path"] for window in base} == {"src/old_m1.py"}
    assert {window["path"] for window in head} == {"src/m1.py"}
    removed = next(window for window in base if "changed_definition" in window["roles"])
    assert "base_target" in removed["symbols"]
    base_enclosing = next(window for window in base if "enclosing_definition" in window["roles"])
    assert "base_enclosing" in base_enclosing["symbols"]
    imported = [gap for gap in plan["gaps"] if gap["code"] == "snapshot_gap_required"]
    assert [gap["path"] for gap in imported] == ["src/old_m1.py"]
    assert "current_side_window_unavailable" not in codes(plan)


def test_deletion_only_and_removed_only_units_exempt_current_side_requirement():
    deletion = make_snapshot(with_head=False, with_base=True)
    deletion["inventory"][0].update(
        change="delete", diff="-def base_target():\n", changed_lines=[[0, 0]], old_line_ranges=[[5, 5]]
    )
    deletion_plan = plans(deletion)
    assert codes(deletion_plan).count("current_side_window_unavailable") == 0
    assert deletion_plan["sufficiency"]["sufficient"] is True

    removed_only = make_snapshot(with_head=False, with_base=True, diff="-def base_target():\n")
    removed_only["inventory"][0]["change"] = "modify"
    removed_only["inventory"][0]["changed_lines"] = []
    removed_plan = plans(removed_only)
    assert "current_side_window_unavailable" not in codes(removed_plan)
    assert removed_plan["sufficiency"]["sufficient"] is True


def test_identical_bytes_across_roles_are_merged_into_one_anchor():
    diff = "+def target(self):\n+    return 1"
    snapshot = make_snapshot(diff=diff)
    snapshot["inventory"][0]["changed_lines"] = [[3, 3]]
    plan = plans(snapshot)
    windows = plan["units"][0]["windows"]
    shared = [window for window in windows if window["line_start"] == 1 and window["line_end"] == 10]
    assert len(shared) == 1
    assert shared[0]["roles"] == ["changed_definition", "enclosing_definition"]
    assert set(shared[0]["symbols"]) == {"target"}


def test_window_cap_keeps_head_first_and_records_required_head_truncation():
    plan = plans(make_snapshot(with_base=True), make_profile(max_windows_per_unit=1, before_lines=0, after_lines=0))
    unit = plan["units"][0]
    assert len(unit["windows"]) == 1
    assert unit["windows"][0]["source_side"] == "HEAD"
    cap = next(gap for gap in plan["gaps"] if gap["code"] == "window_count_limit")
    assert cap["severity"] == "REQUIRED"
    assert cap["dropped_head_windows"] >= 1
    assert plan["sufficiency"]["sufficient"] is False


def test_cap_truncating_only_base_windows_is_optional():
    snapshot = make_snapshot(with_base=True)
    snapshot["inventory"][0]["changed_lines"] = []
    plan = plans(snapshot, make_profile(max_windows_per_unit=1))
    cap = next(gap for gap in plan["gaps"] if gap["code"] == "window_count_limit")
    assert cap["dropped_head_windows"] == 0
    assert cap["severity"] == "OPTIONAL"


def test_partial_symbol_resolution_records_a_gap_per_missing_symbol():
    snapshot = make_snapshot(diff="+def target(self):\n+def absent_definition():")
    plan = plans(snapshot)
    missing = [gap for gap in plan["gaps"] if gap["code"] == "changed_symbol_window_unavailable"]
    assert [gap["symbol"] for gap in missing] == ["absent_definition"]
    assert "target" in {symbol for window in plan["units"][0]["windows"] for symbol in window["symbols"]}


def test_modified_unit_without_a_current_side_window_is_required_unsufficient():
    snapshot = make_snapshot(with_head=False, with_base=True)
    plan = plans(snapshot)
    assert "current_side_window_unavailable" in codes(plan)
    current = next(gap for gap in plan["gaps"] if gap["code"] == "current_side_window_unavailable")
    assert current["severity"] == "REQUIRED"
    assert plan["sufficiency"]["sufficient"] is False


def test_required_snapshot_gaps_are_imported_only_for_scoped_paths():
    gaps = [
        {"path": "src/m1.py", "source_kind": "diff", "reason": "diff_truncated", "required": True},
        {"path": "src/other.py", "source_kind": "diff", "reason": "diff_truncated", "required": True},
        {"path": "src/m1.py", "source_kind": "source_window", "reason": "window_scan_limit", "required": False},
    ]
    plan = plans(make_snapshot(gaps=gaps))
    imported = [gap for gap in plan["gaps"] if gap["code"] == "snapshot_gap_required"]
    assert [gap["path"] for gap in imported] == ["src/m1.py"]
    assert imported[0]["reason"] == "diff_truncated"
    assert imported[0]["severity"] == "REQUIRED"


def test_empty_and_truncated_diffs_record_required_gaps():
    empty = make_snapshot(diff="")
    empty_plan = plans(empty)
    assert "diff_unavailable" in codes(empty_plan)
    truncated = make_snapshot()
    truncated["evidence"]["diff:u1"]["content_truncated"] = True
    truncated_plan = plans(truncated)
    assert "diff_truncated" in codes(truncated_plan)
    assert truncated_plan["sufficiency"]["sufficient"] is False


def test_missing_source_window_records_required_symbol_gaps_before_dispatch():
    plan = build_retrieval_plan(make_snapshot(with_head=False), make_profile(), make_task(), LIMITS)
    assert plan["units"][0]["windows"] == []
    missing = [gap for gap in plan["gaps"] if gap["code"] == "changed_symbol_window_unavailable"]
    assert [gap["symbol"] for gap in missing] == ["target", "unrelated", "Service"]
    assert all(gap["severity"] == "REQUIRED" for gap in missing)
    sufficient = assess_retrieval_sufficiency(plan)
    assert sufficient["sufficient"] is False
    assert sufficient["required_gap_count"] == len([gap for gap in plan["gaps"] if gap["severity"] == "REQUIRED"])


def test_non_allowlisted_referenced_path_fails_closed_with_a_typed_gap():
    plan = plans(make_snapshot(), make_profile(["src/*.py"]))
    assert "referenced_test_not_allowlisted" in codes(plan)
    denied = next(gap for gap in plan["gaps"] if gap["code"] == "referenced_test_not_allowlisted")
    assert denied["paths"] == ["tests/test_m1.py"]
    assert plan["units"][0]["referenced_test_paths"] == []
    assert plan["sufficiency"]["sufficient"] is False


def test_plan_hash_is_stable_and_covers_only_anchor_fields():
    snapshot = make_snapshot()
    plan = plans(snapshot)
    repeated = plans(make_snapshot())
    assert plan["plan_hash"] == repeated["plan_hash"] == plan_hash(plan)
    volatile = make_snapshot()
    volatile["captured_at"] = "2099-01-01T00:00:00+00:00"
    for item in volatile["evidence"].values():
        item["captured_at"] = "2099-01-01T00:00:00+00:00"
    assert plans(volatile)["plan_hash"] == plan["plan_hash"]
    gap_only = copy.deepcopy(plan)
    gap_only["gaps"].append({"code": "synthetic", "severity": "REQUIRED"})
    assert plan_hash(gap_only) == plan["plan_hash"]
    mutated = copy.deepcopy(plan)
    mutated["units"][0]["windows"][0]["line_start"] += 1
    assert plan_hash(mutated) != plan["plan_hash"]


def test_invalid_snapshot_identity_fails_closed():
    snapshot = make_snapshot()
    snapshot["head_sha"] = "not-a-sha"
    with pytest.raises(RetrievalPlanError):
        plans(snapshot)


def test_record_dispatch_retrieval_plans_persists_plans_and_gaps():
    snapshot = make_snapshot(with_head=False)
    state = SimpleNamespace(
        snapshot=snapshot,
        snapshot_captured_evidence=snapshot["evidence"],
        profile=make_profile(),
        limits=LIMITS,
        primary_tasks=[make_task()],
        ledger={},
    )
    record_dispatch_retrieval_plans(state)
    assert state.retrieval_sufficient is False
    assert state.ledger["retrieval_plans"][0]["plan_hash"] == state.retrieval_plans[0]["plan_hash"]
    assert state.ledger["retrieval_plan_gaps"][0]["task_id"] == "t1"
    assert state.ledger["retrieval_plan_gaps"][0]["severity"] == "REQUIRED"


def test_prepare_dispatch_records_the_plan_before_provider_dispatch(tmp_path):
    snapshot = make_snapshot(with_base=True)
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
