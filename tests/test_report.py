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
