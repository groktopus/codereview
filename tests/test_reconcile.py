from __future__ import annotations

import hashlib
import json

import pytest

from pr_review_harness.reconcile import consolidate_findings


def finding(finding_id: str, **overrides):
    value = {
        "finding_id": finding_id,
        "snapshot_id": "snap-1",
        "unit_id": "unit-1",
        "location": {"path": "src/a.py", "line": 10, "side": "HEAD", "kind": "line"},
        "observation": "A value is dropped.",
        "consequence": "Callers see stale data.",
        "rule_or_contract": "CONTRACTS.md#data",
        "candidate_id": f"cand-{finding_id}",
        "task_id": "task-1",
        "evidence_refs": ["ev-1"],
        "status": "ACCEPTED",
        "blocking_class": "BLOCKING",
    }
    value.update(overrides)
    return value


def test_empty_input_returns_empty() -> None:
    assert consolidate_findings([]) == []


def test_identical_findings_merge_and_union_provenance() -> None:
    left = finding("b", task_id="task-2", candidate_id="cand-b", evidence_refs=["ev-2", "ev-1"])
    right = finding("a", task_id="task-1", candidate_id="cand-a", evidence_refs=["ev-1", "ev-3"])

    merged = consolidate_findings([left, right])

    assert len(merged) == 1
    item = merged[0]
    assert item["finding_id"] == "a"
    assert item["candidate_ids"] == ["cand-a", "cand-b"]
    assert item["task_ids"] == ["task-1", "task-2"]
    assert item["evidence_refs"] == ["ev-1", "ev-2", "ev-3"]
    assert item["duplicate_count"] == 1
    assert item["correlation_group_id"].startswith("correlation-")


def test_distinct_locations_do_not_merge() -> None:
    base = finding("a")
    merged = consolidate_findings(
        [
            base,
            finding("b", location={"path": "src/b.py", "line": 10, "side": "HEAD", "kind": "line"}),
            finding("c", location={"path": "src/a.py", "line": 11, "side": "HEAD", "kind": "line"}),
            finding("d", location={"path": "src/a.py", "line": 10, "side": "BASE", "kind": "line"}),
        ]
    )

    assert [item["finding_id"] for item in merged] == ["a", "b", "c", "d"]


def test_location_defaults_and_non_mapping_fallback() -> None:
    merged = consolidate_findings(
        [
            finding("a", location={"path": "src/a.py"}),
            finding("b", location="not-a-mapping", path="src/a.py"),
        ]
    )

    assert len(merged) == 1
    assert merged[0]["finding_id"] == "a"
    assert merged[0]["duplicate_count"] == 1


def test_normalized_text_groups_and_different_text_does_not() -> None:
    merged = consolidate_findings(
        [
            finding("a"),
            finding("b", observation="  A VALUE is dropped.  "),
            finding("c", observation="A different value is dropped."),
        ]
    )

    assert len(merged) == 2
    assert {item["finding_id"]: item["duplicate_count"] for item in merged} == {"a": 1, "c": 0}


def test_contradicted_assessment_forces_unresolved_conflict() -> None:
    merged = consolidate_findings(
        [
            finding("a", semantic_assessment={"outcome": "SUPPORTED"}),
            finding("b", semantic_assessment={"outcome": "CONTRADICTED"}),
        ]
    )

    item = merged[0]
    assert item["status"] == "CONTRADICTED"
    assert item["blocking_class"] == "UNRESOLVED"
    assert item["reconciliation_conflict"] is True
    assert item["correlation_group_id"].startswith("correlation-")


def test_supported_shape_disagreement_is_a_conflict() -> None:
    merged = consolidate_findings(
        [
            finding("a", semantic_assessment={"outcome": "SUPPORTED", "material_consequence": True}),
            finding("b", semantic_assessment={"outcome": "SUPPORTED", "material_consequence": False}),
        ]
    )

    item = merged[0]
    assert item["status"] == "CONTRADICTED"
    assert item["blocking_class"] == "UNRESOLVED"
    assert item["reconciliation_conflict"] is True


def test_no_assessment_has_no_conflict() -> None:
    merged = consolidate_findings([finding("a"), finding("b")])

    assert merged[0]["status"] == "ACCEPTED"
    assert merged[0].get("reconciliation_conflict") is None


def test_assessment_records_are_sorted_and_complete() -> None:
    merged = consolidate_findings(
        [
            finding("a", task_id="task-b", candidate_id="cand-b", semantic_assessment={"outcome": "SUPPORTED"}),
            finding("b", task_id="task-a", candidate_id="cand-a", semantic_assessment={"outcome": "SUPPORTED"}),
        ]
    )

    records = merged[0]["assessment_records"]
    assert [record["task_id"] for record in records] == ["task-a", "task-b"]
    assert [record["candidate_id"] for record in records] == ["cand-a", "cand-b"]
    assert all(record["semantic_assessment"] == {"outcome": "SUPPORTED"} for record in records)
    assert all(record["semantic_usage"] == {} for record in records)
    assert all(record["semantic_provenance"] == {} for record in records)


def test_output_is_sorted_by_finding_id() -> None:
    merged = consolidate_findings(
        [
            finding("z", location={"path": "z.py", "line": 1}),
            finding("a", location={"path": "a.py", "line": 1}),
        ]
    )

    assert [item["finding_id"] for item in merged] == ["a", "z"]


def test_group_key_is_a_sha256_of_canonical_basis() -> None:
    merged = consolidate_findings([finding("a"), finding("b")])
    basis = {
        "snapshot_id": "snap-1",
        "unit_id": "unit-1",
        "path": "src/a.py",
        "side": "HEAD",
        "kind": "line",
        "line": 10,
        "observation": "a value is dropped.",
        "consequence": "callers see stale data.",
        "rule": "contracts.md#data",
    }
    expected = hashlib.sha256(json.dumps(basis, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    assert merged[0]["correlation_group_id"] == "correlation-" + expected[:16]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("snapshot_id", "snap-2"),
        ("unit_id", "unit-2"),
        ("path", "src/other.py"),
        ("observation", "A different observation."),
        ("consequence", "A different consequence."),
        ("rule_or_contract", "OTHER.md"),
        ("side", "BASE"),
        ("kind", "file"),
        ("line", 11),
    ],
)
def test_each_grouping_field_separates_a_finding(field, value) -> None:
    left = finding("a")
    right = finding("b")
    if field in {"path", "side", "kind", "line"}:
        right["location"] = {**left["location"], field: value}
    else:
        right[field] = value

    merged = consolidate_findings([left, right])

    assert len(merged) == 2


def test_default_side_and_file_kind_when_location_omits_them() -> None:
    left = finding("a", location={"path": "src/a.py"})
    right = finding("b", location={"path": "src/a.py", "side": "HEAD", "kind": "file"})

    merged = consolidate_findings([left, right])

    assert len(merged) == 1
    assert merged[0]["duplicate_count"] == 1


def test_candidate_id_falls_back_to_finding_id() -> None:
    left = finding("a")
    right = finding("b")
    left.pop("candidate_id")
    right.pop("candidate_id")

    merged = consolidate_findings([left, right])

    assert merged[0]["candidate_ids"] == ["a", "b"]


def test_task_ids_and_evidence_refs_filter_empty_values() -> None:
    left = finding("a", task_id=None, evidence_refs=[])
    right = finding("b", task_id="task-2", evidence_refs=["ev-2"])

    merged = consolidate_findings([left, right])

    assert merged[0]["task_ids"] == ["task-2"]
    assert merged[0]["evidence_refs"] == ["ev-2"]


@pytest.mark.parametrize(
    "key",
    [
        "observation_support",
        "consequence_support",
        "rule_connection_support",
        "introducedness",
        "material_consequence",
    ],
)
def test_supported_shape_disagreement_on_each_field_is_a_conflict(key) -> None:
    merged = consolidate_findings(
        [
            finding("a", semantic_assessment={"outcome": "SUPPORTED", key: True}),
            finding("b", semantic_assessment={"outcome": "SUPPORTED", key: False}),
        ]
    )

    assert merged[0]["status"] == "CONTRADICTED"
    assert merged[0]["blocking_class"] == "UNRESOLVED"


def test_shape_disagreement_without_supported_or_contradicted_is_not_a_conflict() -> None:
    merged = consolidate_findings(
        [
            finding("a", semantic_assessment={"outcome": "UNCERTAIN", "material_consequence": True}),
            finding("b", semantic_assessment={"outcome": "UNCERTAIN", "material_consequence": False}),
        ]
    )

    assert merged[0]["status"] == "ACCEPTED"
    assert merged[0].get("reconciliation_conflict") is None


def test_three_duplicates_keep_the_lowest_id_and_count_two() -> None:
    merged = consolidate_findings([finding("c"), finding("a"), finding("b")])

    assert merged[0]["finding_id"] == "a"
    assert merged[0]["duplicate_count"] == 2
