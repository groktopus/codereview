import copy

import pytest

from pr_review_harness.report import render_report


def result_with_coverage_reason(reason_code, *, note_state="PARTIAL", references=None):
    references = ["diff:u0"] if references is None else references
    return {
        "run_id": "coverage-report-test",
        "disposition": "INCOMPLETE",
        "coverage_state": "PARTIAL",
        "freshness": "UNKNOWN",
        "merge_eligibility": "NOT_EVALUATED",
        "base_sha": "b" * 40,
        "head_sha": "c" * 40,
        "project_profile_version": "p1",
        "budget": {},
        "findings": [],
        "report_sections": {
            "blockers": [],
            "suggested_improvements": [],
            "specific_strengths": [],
            "future_guidance": [],
        },
        "coverage_ledger": [
            {
                "obligation_id": "unit:u0:lens:correctness",
                "obligation_kind": "CHANGED_UNIT_LENS",
                "required": True,
                "scope_unit_ids": ["u0"],
                "task_ids": ["task-u0"],
                "state": "PARTIAL",
                "reason_code": "PARTIAL_REVIEW_COVERAGE",
            }
        ],
        "task_results": {
            "task-u0": {
                "status": "SUCCEEDED",
                "input_evidence_ids": ["diff:u0"],
                "payload": {
                    "coverage_notes": [
                        {
                            "unit_id": "u0",
                            "state": note_state,
                            "reason_code": reason_code,
                            "coverage_basis": "STATIC_REVIEW",
                            "evidence_refs": references,
                        }
                    ]
                },
            }
        },
        "evidence_index": {"diff:u0": {"path": "src/m0.py", "source_kind": "diff"}},
    }


def test_partial_report_separates_fixed_reason_from_bounded_specialist_advisory():
    rendered = render_report(result_with_coverage_reason("LIMITED_CHANGED_SCOPE_EVIDENCE"))
    assert "unit:u0:lens:correctness: PARTIAL (PARTIAL\\_REVIEW\\_COVERAGE)" in rendered
    assert "Specialist reported partial coverage: LIMITED\\_CHANGED\\_SCOPE\\_EVIDENCE." in rendered


def test_report_does_not_render_untrusted_or_unbound_specialist_reason_text():
    untrusted = render_report(result_with_coverage_reason("leak: key=abc [click](https://attacker.invalid)"))
    unbound = render_report(result_with_coverage_reason("NO_TEST_SOURCE_SUPPLIED", references=["not-dispatched"]))
    assert "key=abc" not in untrusted
    assert "attacker.invalid" not in untrusted
    assert "leak" not in untrusted
    assert "NO_TEST_SOURCE_SUPPLIED" not in unbound


def test_report_ignores_malformed_partial_note_containers():
    malformed = result_with_coverage_reason("NO_TEST_SOURCE_SUPPLIED")
    malformed["task_results"]["task-u0"]["payload"]["coverage_notes"] = None
    assert "Specialist reported partial coverage" not in render_report(malformed)


@pytest.mark.parametrize(
    ("priced", "calls", "amount", "expected"),
    [
        (0, 2, 0, "estimated cost UNKNOWN (0/2 calls priced)"),
        (1, 2, 0.25, "estimated cost partial $0.2500000000 (1/2 calls priced)"),
        (2, 2, 0.25, "estimated cost $0.2500000000 (2/2 calls priced)"),
    ],
)
def test_report_labels_unknown_partial_and_complete_estimates(priced, calls, amount, expected):
    result = result_with_coverage_reason("LIMITED_CHANGED_SCOPE_EVIDENCE")
    result["budget"]["provider_observability"] = {
        "provider_calls_reserved": calls,
        "estimated_cost_calls_known": priced,
        "estimated_cost_usd_observed": amount,
        "billed_cost_usd": "UNKNOWN",
    }

    rendered = render_report(result)

    assert expected in rendered
    assert "billed cost UNKNOWN" in rendered


def test_not_applicable_check_report_separates_reason_from_profile_rationale():
    result = result_with_coverage_reason("NO_TEST_SOURCE_SUPPLIED")
    result["not_applicable"] = [
        {
            "obligation_id": "check:portal",
            "state": "NOT_APPLICABLE",
            "reason": "configured_path_patterns_did_not_match",
            "profile_rationale": "trusted profile rationale",
        }
    ]

    rendered = render_report(result)

    assert r"check:portal: NOT_APPLICABLE (configured\_path\_patterns\_did\_not\_match)" in rendered
    assert "profile rationale: trusted profile rationale" in rendered


def blocker_result():
    finding = {
        "finding_id": "finding-1",
        "snapshot_id": "snapshot-1",
        "unit_id": "unit-1",
        "title": "Reject invalid caller input",
        "status": "ACCEPTED",
        "blocking_class": "BLOCKING",
        "path": "src/handler.py",
        "location": {"path": "src/handler.py", "side": "HEAD", "line": 17, "kind": "line"},
        "observation": "The handler accepts an invalid value.",
        "consequence": "The caller receives a corrupt result.",
        "rule_or_contract": "The API rejects invalid values.",
        "blocking_rationale": "The accepted behavior violates the API contract.",
        "evidence_refs": ["diff:unit-1"],
    }
    rendered = {
        key: value
        for key, value in {
            **finding,
            "rationale": finding["blocking_rationale"],
            "line": finding["location"]["line"],
        }.items()
        if key not in {"blocking_class", "blocking_rationale"}
    }
    result = result_with_coverage_reason("LIMITED_CHANGED_SCOPE_EVIDENCE")
    result["findings"] = [finding]
    result["report_sections"]["blockers"] = [rendered]
    result["disposition"] = "REQUEST_CHANGES"
    result["evidence_index"]["diff:unit-1"] = {
        "path": "src/handler.py",
        "source_kind": "diff",
        "line_start": 17,
    }
    return result


def test_canonical_blocker_is_rendered_and_matches_accepted_finding():
    rendered = render_report(blocker_result())

    assert "Reject invalid caller input" in rendered
    assert "The caller receives a corrupt result." in rendered
    assert "The API rejects invalid values." in rendered
    assert "[src/handler.py:17](./src/handler.py#L17)" in rendered
    assert "[diff:unit-1](./src/handler.py#L17)" in rendered
    assert "[ACCEPTED / BLOCKING]" in rendered
    assert rendered.count("## ") == 4


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "NEEDS_EVIDENCE"),
        ("location", {"path": "src/other.py", "side": "HEAD", "line": 99, "kind": "line"}),
        ("evidence_refs", ["diff:other-unit"]),
    ],
)
def test_report_rejects_same_id_blocker_with_changed_canonical_details(field, value):
    result = blocker_result()
    result["report_sections"]["blockers"][0][field] = value

    with pytest.raises(ValueError, match="does not match canonical finding"):
        render_report(result)


def test_report_rejects_added_or_duplicate_blocker_ids():
    added = blocker_result()
    unknown = copy.deepcopy(added["report_sections"]["blockers"][0])
    unknown["finding_id"] = "invented-finding"
    added["report_sections"]["blockers"].append(unknown)
    with pytest.raises(ValueError, match="no canonical finding"):
        render_report(added)

    duplicate = blocker_result()
    duplicate["report_sections"]["blockers"].append(copy.deepcopy(duplicate["report_sections"]["blockers"][0]))
    with pytest.raises(ValueError, match="duplicate report blocker"):
        render_report(duplicate)


@pytest.mark.parametrize("nonblocking_first", [True, False])
def test_report_rejects_duplicate_canonical_id_across_blocking_and_nonblocking_findings(nonblocking_first):
    result = blocker_result()
    blocker = result["findings"][0]
    nonblocking = copy.deepcopy(blocker)
    nonblocking.update(status="NEEDS_EVIDENCE", blocking_class="UNRESOLVED")
    result["findings"] = [nonblocking, blocker] if nonblocking_first else [blocker, nonblocking]

    with pytest.raises(ValueError, match="duplicate canonical finding identity"):
        render_report(result)


def test_report_rejects_omitted_canonical_blocker():
    result = blocker_result()
    result["report_sections"]["blockers"] = []

    with pytest.raises(ValueError, match="omits an accepted blocker"):
        render_report(result)


def test_partial_report_keeps_canonical_blocker_and_full_coverage_ledger_visible():
    result = blocker_result()
    result["coverage_ledger"] = [
        {
            "obligation_id": f"obligation-{index}",
            "obligation_kind": "CHANGED_UNIT_LENS",
            "required": True,
            "scope_unit_ids": [f"unit-{index}"],
            "task_ids": [f"task-{index}"],
            "state": "PARTIAL",
            "reason_code": "PARTIAL_REVIEW_COVERAGE",
            "context_gap_ids": [],
            "evidence_refs": [f"diff:unit-{index}"],
        }
        for index in range(11)
    ]
    result["coverage_ledger"][10]["obligation_id"] = "obligation-<script>alert(1)</script>"
    result["coverage_ledger"][10]["task_ids"] = ["task-secret-looking-but-not-secret"]

    rendered = render_report(result)

    assert r"PR review coverage-report-test: REQUEST\_CHANGES" in rendered
    assert "0 complete, 11 partial, 0 not started across 11 obligations." in rendered
    assert "3 more unresolved obligations are listed in the full coverage ledger below." in rendered
    assert "<summary>Full coverage ledger (11 obligations)</summary>" in rendered
    assert "obligation-&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "task-secret-looking-but-not-secret" in rendered
    assert "## Blockers" in rendered and "Reject invalid caller input" in rendered
    assert rendered.count("## ") == 4


def test_report_rejects_malformed_coverage_ledger_instead_of_rendering_partial_inventory():
    result = result_with_coverage_reason("NO_TEST_SOURCE_SUPPLIED")
    result["coverage_ledger"].append("not-an-obligation")

    with pytest.raises(ValueError, match="coverage ledger rows must be objects"):
        render_report(result)
