"""Whole reconcile API boundaries; deterministic, local and effect-free.

Oracles are snapshot-inventory membership and stable identity semantics, not a
second implementation of reconciliation. Replays use the original candidates:
consolidated output is not an input-event ledger and need not be re-consolidated.
"""

from __future__ import annotations

from copy import deepcopy
from itertools import permutations

import pytest

from pr_review_harness.reconcile import consolidate_findings, stable_candidate_id, validate_location


def candidate():
    return {
        "unit_id": "unit-a",
        "path": "fallback.py",
        "line": 99,
        "location": {"path": "new.py", "side": "HEAD", "line": 10, "kind": "line"},
        "observation": "  StraßE\n value\tLOST ",
        "consequence": " Callers\nFAIL ",
        "rule_or_contract": " API\tContract ",
    }


def inventory(**overrides):
    unit = {
        "path": "new.py",
        "old_path": "old.py",
        "change_type": "rename",
        "changed_lines": [[10, 12]],
        "line_ranges": [[90, 100]],
        "old_line_ranges": [[20, 22]],
    }
    unit.update(overrides)
    return {"unit-a": unit}


def test_stable_id_is_exact_snapshot_bound_and_replay_pure():
    value = candidate()
    before = deepcopy(value)
    # Independently frozen SHA-256 of the documented identity fields, canonical
    # JSON (UTF-8, sorted keys, compact separators), truncated to 20 hex digits.
    assert stable_candidate_id("snapshot-a", value) == "finding-6302c88249085623703f"
    assert stable_candidate_id("snapshot-a", value) == stable_candidate_id("snapshot-a", before)
    assert value == before
    assert stable_candidate_id("snapshot-b", value) != stable_candidate_id("snapshot-a", value)


@pytest.mark.parametrize("field", ["unit_id", "observation", "consequence", "rule_or_contract"])
def test_stable_id_changes_for_each_semantic_identity_field(field):
    original = candidate()
    changed = deepcopy(original)
    changed[field] = "different"
    assert stable_candidate_id("snapshot-a", changed) != stable_candidate_id("snapshot-a", original)


@pytest.mark.parametrize("field,value", [("path", "else.py"), ("side", "BASE"), ("line", 11), ("kind", "file")])
def test_stable_id_changes_for_each_location_dimension(field, value):
    original = candidate()
    changed = deepcopy(original)
    changed["location"][field] = value
    assert stable_candidate_id("snapshot-a", changed) != stable_candidate_id("snapshot-a", original)


def test_stable_id_normalizes_text_but_ignores_nonidentity_metadata():
    original = candidate()
    changed = deepcopy(original)
    changed.update(
        observation="strasse value lost",
        consequence="callers fail",
        rule_or_contract="api contract",
        task_id="another-task",
        semantic_assessment={"outcome": "CONTRADICTED"},
        status="REJECTED",
        evidence_refs=["unrelated-evidence"],
        path="ignored-fallback.py",
        line=1000,
    )
    assert stable_candidate_id("snapshot-a", changed) == stable_candidate_id("snapshot-a", original)


@pytest.mark.parametrize("location", [None, [], "not-a-location", {}])
def test_stable_id_legacy_location_fallback_and_defaults(location):
    legacy = candidate()
    legacy["location"] = location
    explicit = deepcopy(legacy)
    explicit["location"] = {"path": "fallback.py", "line": 99, "side": "HEAD", "kind": "line"}
    assert stable_candidate_id("snapshot-a", legacy) == stable_candidate_id("snapshot-a", explicit)


@pytest.mark.parametrize("value", [None, "", False, 0])
def test_stable_id_absent_and_falsey_text_have_empty_identity(value):
    missing = {"unit_id": "unit-a"}
    supplied = {**missing, "observation": value, "consequence": value, "rule_or_contract": value}
    assert stable_candidate_id("snapshot-a", supplied) == stable_candidate_id("snapshot-a", missing)


@pytest.mark.parametrize("change_type", ["rename", "renamed"])
@pytest.mark.parametrize("side,path,first,last", [("HEAD", "new.py", 10, 12), ("BASE", "old.py", 20, 22)])
@pytest.mark.parametrize("offset,expected", [(-1, False), (0, True), (1, True), (2, True), (3, False)])
def test_location_inclusive_inventory_ranges_and_rename_sides(change_type, side, path, first, last, offset, expected):
    value = candidate()
    line = first + offset
    value["location"] = {"path": path, "side": side, "line": line, "reason": "preserve me"}
    units = inventory(change_type=change_type)
    before = deepcopy((value, units))
    assert last == first + 2
    assert validate_location(value, None, {"unit-a"}, units) == (
        expected,
        {"path": path, "side": side, "line": line, "kind": "line", "reason": "preserve me"},
        line,
        "unit-a",
    )
    assert (value, units) == before


@pytest.mark.parametrize("line", [True, False, 0, -1, 1.0, "10", None, [], {}])
def test_location_rejects_nonpositive_or_noninteger_lines(line):
    value = {"unit_id": "unit-a", "location": {"path": "new.py", "line": line}}
    assert validate_location(value, None, {"unit-a"}, inventory()) == (False, value["location"], None, "unit-a")


@pytest.mark.parametrize("side,path", [("HEAD", "old.py"), ("BASE", "new.py"), ("OTHER", "new.py"), (None, "new.py")])
def test_location_wrong_revision_path_or_side_never_validates(side, path):
    value = candidate()
    value["location"] = {"path": path, "side": side, "line": 10}
    valid, _, _, uid = validate_location(value, None, {"unit-a"}, inventory())
    assert valid is False
    assert uid == "unit-a"


@pytest.mark.parametrize("change_type", ["add", "added", "delete", "deleted", "modify", "modified"])
def test_old_path_is_not_an_alias_for_nonrenames(change_type):
    value = {"unit_id": "unit-a", "location": {"path": "old.py", "side": "BASE", "line": 20}}
    assert validate_location(value, None, {"unit-a"}, inventory(change_type=change_type)) == (
        False,
        value["location"],
        None,
        "unit-a",
    )


@pytest.mark.parametrize("explicit_uid", [None, "foreign-unit", "unit-a"])
@pytest.mark.parametrize("path", ["new.py", "old.py"])
def test_unique_path_resolution_uses_only_task_units(explicit_uid, path):
    value = {
        "unit_id": explicit_uid,
        "location": {
            "path": path,
            "side": "BASE" if path == "old.py" else "HEAD",
            "line": 20 if path == "old.py" else 10,
        },
    }
    units = inventory()
    units["not-in-task"] = deepcopy(units["unit-a"])
    valid, _, line, uid = validate_location(value, None, {"unit-a"}, units)
    assert valid is True
    assert uid == "unit-a"
    assert line == value["location"]["line"]


def test_ambiguous_missing_and_out_of_task_units_cannot_authorize_anchor():
    value = candidate()
    value.pop("unit_id")
    units = inventory()
    units["unit-b"] = deepcopy(units["unit-a"])
    assert validate_location(value, None, {"unit-a", "unit-b"}, units) == (False, value["location"], None, None)
    assert validate_location(value, None, set(), units) == (False, value["location"], None, None)
    value["unit_id"] = "unit-a"
    assert validate_location(value, None, {"unit-a"}, {}) == (False, value["location"], None, "unit-a")
    value["location"]["path"] = "unknown.py"
    value.pop("unit_id")
    assert validate_location(value, None, {"unit-a"}, units) == (False, value["location"], None, None)


def test_explicit_unit_disambiguates_path_and_supplied_unit_is_respected():
    value = candidate()
    units = inventory()
    units["unit-b"] = deepcopy(units["unit-a"])
    assert validate_location(value, None, {"unit-a", "unit-b"}, units)[0] is True
    supplied = {"path": "other.py"}
    assert validate_location(value, supplied, {"unit-a"}, units) == (False, value["location"], None, "unit-a")
    assert validate_location(value, {}, {"unit-a"}, units) == (False, value["location"], None, "unit-a")


@pytest.mark.parametrize("raw", [None, [], "bad", {}])
def test_legacy_top_level_anchor_defaults_and_line_ranges_fallback(raw):
    value = {"path": "new.py", "line": 10, "location": raw}
    units = inventory()
    units["unit-a"].pop("changed_lines")
    units["unit-a"]["line_ranges"] = [[10, 10]]
    assert validate_location(value, None, {"unit-a"}, units) == (
        True,
        {"path": "new.py", "side": "HEAD", "line": 10, "kind": "line"},
        10,
        "unit-a",
    )


@pytest.mark.parametrize("side,path", [("HEAD", "new.py"), ("BASE", "old.py")])
@pytest.mark.parametrize(
    "ranges,expected",
    [([], False), ([[10]], False), ([None, "10:12", [], [10, 12]], True), ([(10, 12)], True), ([["10", "12"]], True)],
)
def test_location_range_shapes_and_absent_ranges(side, path, ranges, expected):
    value = {"unit_id": "unit-a", "location": {"path": path, "side": side, "line": 11}}
    units = inventory(changed_lines=ranges, old_line_ranges=ranges)
    assert validate_location(value, None, {"unit-a"}, units) == (
        expected,
        {**value["location"], "kind": "line"},
        11,
        "unit-a",
    )
    units["unit-a"].pop("old_line_ranges")
    units["unit-a"].pop("changed_lines")
    units["unit-a"].pop("line_ranges")
    assert validate_location(value, None, {"unit-a"}, units)[0] is False


@pytest.mark.parametrize(
    "expected",
    [
        None,
        [],
        {},
        {"kind": "line", "path": "new.py", "side": "HEAD"},
        {"kind": "file", "path": "wrong.py", "side": "HEAD"},
        {"kind": "file", "path": "new.py", "side": "BASE"},
        {"kind": "file", "path": "new.py", "side": "HEAD"},
    ],
)
def test_file_anchor_requires_exact_explicit_inventory_record(expected):
    value = {"unit_id": "unit-a", "location": {"kind": "file", "path": "new.py", "reason": "file contract"}}
    units = inventory(file_level_location=expected)
    valid = expected == {"kind": "file", "path": "new.py", "side": "HEAD"}
    assert validate_location(value, None, {"unit-a"}, units) == (
        valid,
        {**value["location"], "side": "HEAD"},
        None,
        "unit-a",
    )


def test_deleted_base_file_anchor_preserves_reason_and_ignores_line():
    value = {"path": "gone.py", "line": True, "location": {"kind": "file", "side": "BASE", "reason": "removed"}}
    units = {
        "unit-a": {
            "path": "gone.py",
            "change_type": "deleted",
            "file_level_location": {"kind": "file", "path": "gone.py", "side": "BASE"},
        }
    }
    assert validate_location(value, None, {"unit-a"}, units) == (
        True,
        {"kind": "file", "side": "BASE", "path": "gone.py", "reason": "removed"},
        None,
        "unit-a",
    )


@pytest.mark.parametrize("conflicting", [False, True])
def test_consolidation_permutation_replay_purity_and_blocker_conflict_invariants(conflicting):
    values = []
    for index in range(3):
        values.append(
            {
                **candidate(),
                "finding_id": f"finding-{index}",
                "candidate_id": f"candidate-{index}",
                "task_id": f"task-{index}",
                "snapshot_id": "snapshot-a",
                "evidence_refs": [f"evidence-{index}"],
                "status": "ACCEPTED",
                "blocking_class": "BLOCKING",
                "blocking_rationale": "supported blocker",
                "semantic_assessment": {"outcome": "CONTRADICTED" if conflicting and index == 2 else "SUPPORTED"},
                "semantic_usage": {"input_tokens": index},
                "semantic_provenance": {"request_id": f"request-{index}"},
            }
        )
    before = deepcopy(values)
    expected = consolidate_findings(values)
    for ordering in permutations(values):
        assert consolidate_findings(list(ordering)) == expected
    assert consolidate_findings(values) == expected
    assert values == before
    assert len(expected) == 1
    merged = expected[0]
    assert merged["status"] == ("CONTRADICTED" if conflicting else "ACCEPTED")
    assert merged["blocking_class"] == ("UNRESOLVED" if conflicting else "BLOCKING")
    assert merged["duplicate_count"] == 2
    assert merged["candidate_ids"] == [f"candidate-{index}" for index in range(3)]
    assert merged["task_ids"] == [f"task-{index}" for index in range(3)]
    assert merged["evidence_refs"] == [f"evidence-{index}" for index in range(3)]
    assert merged["assessment_records"] == [
        {
            key: row[key]
            for key in ("candidate_id", "task_id", "semantic_assessment", "semantic_usage", "semantic_provenance")
        }
        for row in values
    ]
    if conflicting:
        assert merged["reconciliation_conflict"] is True
        assert (
            merged["blocking_rationale"]
            == "Conflicting bounded assessments were preserved; no provider count or vote selects a result."
        )
    else:
        assert merged["blocking_rationale"] == "supported blocker"
        assert "reconciliation_conflict" not in merged
