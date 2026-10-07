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


def test_partial_report_renders_native_lowercase_reason_for_bound_changed_unit():
    result = result_with_coverage_reason("changed_dependency_has_no_related_test_evidence")
    result["coverage_ledger"][0]["obligation_id"] = "unit:unit-2bc59af71c35b8be0988:lens:tests"
    result["coverage_ledger"][0]["scope_unit_ids"] = ["unit-2bc59af71c35b8be0988"]
    result["task_results"]["task-u0"]["payload"]["coverage_notes"][0]["unit_id"] = "unit-2bc59af71c35b8be0988"
    rendered = render_report(result)

    assert "unit:unit-2bc59af71c35b8be0988:lens:tests: PARTIAL" in rendered
    assert (
        "Specialist reported partial coverage: changed\\_dependency\\_has\\_no\\_related\\_test\\_evidence."
    ) in rendered


@pytest.mark.parametrize("reason", ["a" * 129, "é" * 128])
def test_partial_report_renders_contract_valid_long_coverage_reason(reason):
    rendered = render_report(result_with_coverage_reason(reason))

    assert f"Specialist reported partial coverage: {reason}." in rendered


def test_partial_report_omits_over_contract_size_coverage_reason():
    rendered = render_report(result_with_coverage_reason("é" * 129))

    assert "Specialist reported partial coverage" not in rendered


def test_report_escapes_native_reason_text_and_rejects_unbound_reason():
    untrusted = render_report(result_with_coverage_reason("leak: key=abc [click](https://attacker.invalid)"))
    unbound = render_report(result_with_coverage_reason("NO_TEST_SOURCE_SUPPLIED", references=["not-dispatched"]))
    assert r"\[click\]\(https://attacker.invalid\)" in untrusted
    assert "[click](https://attacker.invalid)" not in untrusted
    assert "Specialist reported partial coverage" not in unbound
    assert "NO_TEST_SOURCE_SUPPLIED" not in unbound


def test_report_escapes_html_and_flattens_newline_in_bounded_reason_text():
    reason = "<img src=x onerror=alert(1)>\nINJECTED_LINE"
    rendered = render_report(result_with_coverage_reason(reason))
    reason_line = next(line for line in rendered.splitlines() if "Specialist reported partial coverage" in line)

    assert r"coverage: \<img" in reason_line
    assert "coverage: <img" not in reason_line
    assert r"alert\(1\)" in reason_line
    assert r"INJECTED\_LINE" in reason_line
    assert "\nINJECTED_LINE" not in reason_line


def test_report_renders_bounded_plain_text_reason_from_native_string_contract():
    rendered = render_report(result_with_coverage_reason("Changed dependency has no related test evidence."))

    assert "Specialist reported partial coverage: Changed dependency has no related test evidence." in rendered


def test_historical_freshness_and_provider_call_reservations_are_labeled_without_live_claims():
    result = result_with_coverage_reason("NO_TEST_SOURCE_SUPPLIED")
    result["freshness"] = "CURRENT"
    result["freshness_details"] = {
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "expected_head_sha": "c" * 40,
        "observed_head_sha": "c" * 40,
    }
    result["budget"] = {
        "provider_calls_reserved": 10,
        "provider_calls_limit": 10,
        "context_bytes_reserved": 389_656,
        "context_bytes_limit": 600_000,
        "output_bytes_reserved": 160_000,
        "output_bytes_limit": 192_000,
        "cost": "UNKNOWN",
    }

    rendered = render_report(result)

    assert r"Freshness: CURRENT (basis: HISTORICAL\_SNAPSHOT)" in rendered
    assert "Historical snapshot freshness compares the fixed revisions only" in rendered
    assert "it does not check the pull request's current state." in rendered
    assert "provider-call reservations 10/10" in rendered
    assert "10/10 calls" not in rendered


def test_live_freshness_basis_is_rendered_without_historical_disclaimer():
    result = result_with_coverage_reason("NO_TEST_SOURCE_SUPPLIED")
    result["freshness"] = "CURRENT"
    result["freshness_details"] = {"freshness_basis": "GITHUB_API"}

    rendered = render_report(result)

    assert r"Freshness: CURRENT (basis: GITHUB\_API)" in rendered
    assert "Historical snapshot freshness" not in rendered


@pytest.mark.parametrize("binding", ["unit", "task", "evidence"])
def test_report_rejects_specialist_reason_without_scope_task_and_source_bindings(binding):
    result = result_with_coverage_reason("changed_dependency_has_no_related_test_evidence")
    note = result["task_results"]["task-u0"]["payload"]["coverage_notes"][0]
    row = result["coverage_ledger"][0]
    if binding == "unit":
        note["unit_id"] = "other-unit"
    elif binding == "task":
        row["task_ids"] = ["other-task"]
    else:
        note["evidence_refs"] = ["not-dispatched"]

    rendered = render_report(result)

    assert "changed\\_dependency" not in rendered


def test_report_ignores_malformed_partial_note_containers():
    malformed = result_with_coverage_reason("NO_TEST_SOURCE_SUPPLIED")
    malformed["task_results"]["task-u0"]["payload"]["coverage_notes"] = None
    assert "Specialist reported partial coverage" not in render_report(malformed)


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
    assert "Coverage ledger (11 obligations)" in rendered
    assert "<summary>Coverage ledger (11 obligations)</summary>" in rendered
    assert r"obligation-\<script\>alert\(1\)\</script\>" in rendered
    assert "task-secret-looking-but-not-secret" in rendered
    assert "## Blockers" in rendered and "Reject invalid caller input" in rendered
    assert rendered.count("## ") == 4
    assert "<pre><code>" not in rendered


def test_compact_ledger_preserves_all_obligations_and_stable_evidence_mapping():
    result = blocker_result()
    result["coverage_ledger"] = []
    states = ("COMPLETE", "PARTIAL", "NOT_STARTED")
    lenses = ("correctness", "tests", "security", "project_specific")
    for index in range(48):
        refs = [f"ev-{(index + offset) % 53:03d}" for offset in range(4)]
        result["coverage_ledger"].append(
            {
                "obligation_id": f"unit:unit-{index:03d}:lens:{lenses[index % len(lenses)]}",
                "obligation_kind": "CHANGED_UNIT_LENS" if index % 3 else "REQUIRED_CONTEXT",
                "required": index % 7 != 0,
                "scope_unit_ids": [f"unit-{index:03d}"],
                "lens": lenses[index % len(lenses)],
                "task_ids": [f"task-{index:03d}:chunk-{index % 2 + 1}"],
                "state": states[index % len(states)],
                "reason_code": "PARTIAL_REVIEW_COVERAGE" if index % 3 else "café_context_gap_<review>",
                "context_gap_ids": [f"gap-{index:03d}"] if index % 3 else [],
                "evidence_refs": refs,
            }
        )

    rendered = render_report(result)
    evidence_ids = sorted(
        {
            evidence_id
            for row in result["coverage_ledger"]
            for evidence_id in row["evidence_refs"]
        }
    )
    header = [
        "Required",
        "Obligation",
        "Lens",
        "Scope units",
        "State",
        "Reason",
        "Tasks",
        "Context gaps",
        "Evidence refs",
    ]
    table_rows = {}
    in_table = False
    for line in rendered.splitlines():
        if line.startswith("| Required | Obligation |"):
            in_table = True
            continue
        if in_table and line.startswith("| --- |"):
            continue
        if in_table and line.startswith("| "):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            table_rows[cells[1]] = dict(zip(header, cells, strict=True))
            continue
        if in_table:
            break
    evidence_index = {
        alias: evidence_id
        for line in rendered.splitlines()
        if line.startswith("- E")
        for alias, evidence_id in [line[2:].split(" = ", 1)]
    }
    assert evidence_index == {
        f"E{position:04d}": evidence_id
        for position, evidence_id in enumerate(evidence_ids, start=1)
    }

    def safe_cell(value):
        value = str(value if value is not None else "").replace("\r", " ").replace("\n", " ")
        for char in ("|", "<", ">", "`", "[", "]", "(", ")", "#", "*", "_", "!"):
            value = value.replace(char, "\\" + char)
        return value

    assert len(rendered.encode("utf-8")) < 60_000
    assert "Coverage ledger (48 obligations)" in rendered
    assert "<summary>Coverage ledger (48 obligations)</summary>" in rendered
    assert "<pre><code>" not in rendered
    assert r"café\_context\_gap\_\<review\>" in rendered
    assert "| Required | Obligation | Lens | Scope units | State | Reason | Tasks | Context gaps | Evidence refs |" in rendered
    assert "## Blockers" in rendered and "Reject invalid caller input" in rendered
    for row in result["coverage_ledger"]:
        rendered_row = table_rows[safe_cell(row["obligation_id"])]
        assert rendered_row["Required"] == safe_cell(row["required"])
        assert rendered_row["Lens"] == safe_cell(row["lens"])
        assert rendered_row["Scope units"] == safe_cell(", ".join(row["scope_unit_ids"]))
        assert rendered_row["State"] == safe_cell(row["state"])
        assert rendered_row["Reason"] == safe_cell(row["reason_code"])
        assert rendered_row["Tasks"] == safe_cell(", ".join(row["task_ids"]))
        assert rendered_row["Context gaps"] == safe_cell(", ".join(row["context_gap_ids"]))
        rendered_refs = [
            evidence_index[alias]
            for alias in rendered_row["Evidence refs"].split(", ")
            if alias
        ]
        assert rendered_refs == row["evidence_refs"]


def test_report_rejects_malformed_coverage_ledger_instead_of_rendering_partial_inventory():
    result = result_with_coverage_reason("NO_TEST_SOURCE_SUPPLIED")
    result["coverage_ledger"].append("not-an-obligation")

    with pytest.raises(ValueError, match="coverage ledger rows must be objects"):
        render_report(result)
