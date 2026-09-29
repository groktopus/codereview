from __future__ import annotations

import json
import ssl
from pathlib import Path
from types import SimpleNamespace

import pytest

from pr_review_harness.claim_assessment import (
    CONTRACT_VERSION,
    PRIMARY_ASSESSMENT_CONTRACT_VERSION,
    _questions,
)
from pr_review_harness.selected_model_trial import _limits, canonical_json
from scripts import selected_control_trace_attribution as diagnostic


def test_trace_attributor_accounts_only_fixed_labels_and_keeps_no_raw_lines():
    seen: list[str] = []

    def parser(line: str, _cwd: Path):
        seen.append(line)
        return {"syscall": "newfstatat"}

    attributor = diagnostic._LineAttributor(parser, Path("/tmp"))
    first = '[pid 7] newfstatat(AT_FDCWD, "/private/value", {}, 0) = 0'
    second = '[pid 8] custom_syscall("private-value") = 0'

    attributor(first, Path("/tmp"))
    attributor(second, Path("/tmp"))

    assert attributor.bytes_by_label == {
        "OTHER": len(second.encode("utf-8")) + 1,
        "newfstatat": len(first.encode("utf-8")) + 1,
    }
    assert attributor.lines_by_label == {"OTHER": 1, "newfstatat": 1}
    assert attributor.total_line_bytes == sum(attributor.bytes_by_label.values())
    assert seen == [first, second]  # parser receives lines, but retained state is numeric counters only
    assert set(attributor.__dict__) == {
        "parser", "cwd", "roots", "bytes_by_label", "lines_by_label",
        "file_path_bytes", "file_path_lines", "target_file_bytes", "target_file_lines",
        "resumed_file_bytes", "resumed_file_lines", "total_line_bytes", "parse_failures",
    }
    assert "private/value" not in repr(attributor.__dict__)


def test_file_path_classes_are_lexical_bounded_and_reconcile_exact_newline_bytes():
    roots = (
        ("CASE_WORKDIR", "/tmp/private-case"),
        ("CLI_ENVIRONMENT", "/opt/cli-env"),
        ("REPO_SUPPORT", "/work/repo"),
        ("TEMP_ROOT", "/tmp"),
        ("SYSTEM_ROOT", "/usr"),
    )
    lines = [
        '[pid 7] openat(AT_FDCWD, "/tmp/private-case/src/é.py", O_RDONLY) = 3',
        '[pid 8] newfstatat(0xffffff9c, 0x7fff00000000, 0x7fff00001000, 0) = 0',
        '[pid 9] openat(AT_FDCWD, "relative/name", O_RDONLY) = 3',
        '[pid 10] newfstatat(AT_FDCWD, "unterminated, {}, 0) = -1 EINVAL (Invalid argument)',
        '[pid 11] openat(AT_FDCWD, "/tmp/private-case/partial", O_RDONLY <unfinished ...>',
        '[pid 11] <... openat resumed> ) = 3',
        '[pid 12] openat(AT_FDCWD, "/tmp/private-case/truncated...", O_RDONLY) = 3',
    ]
    attributor = diagnostic._LineAttributor(
        diagnostic.observer._parse_line,
        Path("/tmp"),
        roots,
    )
    for line in lines:
        try:
            attributor(line, Path("/tmp"))
        except ValueError:
            # The deliberately malformed quote must remain counted and UNKNOWN.
            pass

    projection = diagnostic._file_path_projection(attributor, complete_trace=True)
    assert projection["state"] == "COMPLETE"
    assert projection["reconciliation"] == "MATCH"
    assert projection["lines_by_syscall_class"] == {
        "openat": {
            "CASE_WORKDIR": 1,
            "UNKNOWN_RELATIVE": 1,
            "UNKNOWN_UNFINISHED": 1,
            "UNKNOWN_RESUMED": 1,
            "UNKNOWN_ELLIPSIS_AMBIGUOUS": 1,
        },
        "newfstatat": {"UNKNOWN_RAW_ARGUMENTS": 1, "UNKNOWN_SYNTAX": 1},
    }
    assert projection["target_lines_by_syscall"] == {"openat": 5, "newfstatat": 2}
    assert projection["target_bytes_by_syscall"] == {
        syscall: sum(
            len(line.encode("utf-8")) + 1
            for line in lines
            if diagnostic._target_syscall(line) == syscall
        )
        for syscall in ("openat", "newfstatat")
    }
    assert "private-case" not in json.dumps(projection)
    assert "relative/name" not in repr(attributor.file_path_bytes)
    assert diagnostic._path_class_for_line(
        '[pid 13] openat(AT_FDCWD, "/tmp/private-case-other/file", O_RDONLY) = 3',
        "openat",
        roots,
    ) == "TEMP_ROOT"
    assert diagnostic._path_class_for_line(
        '[pid 14] openat(AT_FDCWD, "/tmp/private-case/link/../source.py", O_RDONLY) = 3',
        "openat",
        roots,
    ) == "CASE_WORKDIR"


def test_file_path_attribution_rejects_mismatch_with_original_syscall_buckets():
    line = '[pid 7] openat(AT_FDCWD, "/outside/path", O_RDONLY) = 3'
    attributor = diagnostic._LineAttributor(
        diagnostic.observer._parse_line,
        Path("/tmp"),
        (("REPO_SUPPORT", "/work/repo"),),
    )
    attributor(line, Path("/tmp"))
    attributor.bytes_by_label["openat"] -= 1
    projection = diagnostic._file_path_projection(attributor, complete_trace=True)
    assert projection["state"] == "PARTIAL"
    assert projection["reconciliation"] == "MISMATCH"


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ('"/repo/a\\\"b"', "REPO_SUPPORT"),
        ('"/repo/a\\\\b"', "REPO_SUPPORT"),
        ('"/repo\\057file"', "REPO_SUPPORT"),
        ('"/repo/invalid\\q"', "UNKNOWN_SYNTAX"),
        ('"\\u002frepo/file"', "UNKNOWN_SYNTAX"),
    ],
)
def test_strace_c_path_escapes_are_conservative(token, expected):
    line = f"[pid 7] openat(AT_FDCWD, {token}, O_RDONLY) = 3"
    assert diagnostic._path_class_for_line(line, "openat", (("REPO_SUPPORT", "/repo"),)) == expected


@pytest.mark.parametrize(
    ("line", "expected_outcome"),
    [
        ('[pid 7] newfstatat(0xffffff9c, 0x7fff00000000, 0x7fff00001000, 0) = 0', "SUCCESS"),
        ('[pid 8] newfstatat(0xffffff9c, 0x7fff00000000, 0x7fff00001000, 0) = -1 ENOENT (No such file or directory)', "ERROR"),
    ],
)
def test_raw_newfstatat_uses_real_observer_shape_but_never_claims_path(line, expected_outcome):
    parsed = diagnostic.observer._parse_line(line, Path("/tmp"))
    assert parsed["syscall"] == "newfstatat"
    assert parsed["outcome"] == expected_outcome
    assert diagnostic._path_class_for_line(line, "newfstatat", ()) == "UNKNOWN_RAW_ARGUMENTS"
    assert "/" not in json.dumps(parsed)


@pytest.mark.parametrize(
    "line",
    [
        '[pid 9] newfstatat(0xffffff9c, 0x7fff00000000, 0x7fff00001000, 0) = 0x0',
        '[pid 10] newfstatat(0xffffff9c, "pathname", 0x7fff00001000, 0) = 0',
    ],
)
def test_newfstatat_nonproduction_renderings_remain_unknown_syntax(line):
    assert diagnostic._path_class_for_line(line, "newfstatat", ()) == "UNKNOWN_SYNTAX"


def test_file_path_attribution_never_claims_complete_when_trace_has_residual_bytes():
    line = '[pid 7] openat(AT_FDCWD, "/outside/path", O_RDONLY) = 3'
    attributor = diagnostic._LineAttributor(
        diagnostic.observer._parse_line,
        Path("/tmp"),
        (("REPO_SUPPORT", "/work/repo"),),
    )
    attributor(line, Path("/tmp"))
    projection = diagnostic._file_path_projection(attributor, complete_trace=False)
    assert projection["state"] == "PARTIAL"
    assert projection["lines_by_syscall_class"] == {"openat": {"OTHER_ABSOLUTE": 1}, "newfstatat": {}}


def test_diagnostic_limits_bytes_match_selected_trial_canonical_input(tmp_path):
    path = tmp_path / "limits.json"
    written = diagnostic._write_limits(path)
    assert written == canonical_json(_limits()) + b"\n"
    assert path.read_bytes() == written


def test_oversized_summary_fails_closed_without_truncating_json():
    encoded, within_limit = diagnostic._bounded_summary_bytes({"safe": "x" * diagnostic.MAX_SUMMARY_BYTES})
    assert not within_limit
    assert len(encoded) < diagnostic.MAX_SUMMARY_BYTES
    assert json.loads(encoded) == {"status": "FAILED", "error_type": "summary_limit_exceeded"}


def test_observation_projection_marks_trace_tail_as_unattributed(monkeypatch):
    line = "[pid 1] wait4(-1, NULL, 0, NULL) = 0"
    line_bytes = len(line.encode("utf-8")) + 1

    def fake_observe(_command, *, cwd, env, timeout_seconds):
        diagnostic.observer._parse_line(line, cwd)
        return {
            "invocation": {"run_status": "CLI_COMPLETED", "exit_code": 0},
            "observer": {"coverage": "INCOMPLETE", "reason": "trace_byte_cap_exceeded", "trace_bytes": line_bytes + 19},
            "cli_result": None,
        }

    monkeypatch.setattr(diagnostic.observer, "observe_cli", fake_observe)
    result, projection = diagnostic._attributed_observation(["pr-review"], cwd=Path("/tmp"), env={}, timeout=10)

    assert result["observer"]["reason"] == "trace_byte_cap_exceeded"
    assert projection["state"] == "PARTIAL"
    assert projection["trace_bytes"] == line_bytes + 19
    assert projection["newline_terminated_line_bytes"] == line_bytes
    assert projection["unattributed_or_partial_bytes"] == 19
    assert projection["bytes_by_syscall"] == {"wait4": line_bytes}


def test_synthetic_security_response_is_bound_to_control_unit_and_diff_evidence():
    request = {
        "messages": [
            {"role": "system", "content": "synthetic system instruction"},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": {"lens": "security", "unit_ids": ["unit-u0"]},
                        "evidence": [
                            {"evidence_id": "diff:u0", "source_kind": "diff"},
                            {"evidence_id": "base:u0", "source_kind": "base_file"},
                        ],
                    }
                ),
            },
        ]
    }
    counters = diagnostic._CallCounters()
    envelope = diagnostic._primary_payload(request, counters)
    payload = {key: value for key, value in envelope.items() if key != "_envelope"}
    candidate = payload["finding_candidates"][0]

    assert counters["primary_security_received"] == 1
    assert candidate["unit_id"] == "unit-u0"
    assert candidate["location"] == {
        "kind": "line", "path": "src/auth.py", "side": "HEAD", "line": 2, "reason": None
    }
    assert candidate["evidence_refs"] == ["diff:u0"]
    assert payload["coverage_notes"][0]["unit_id"] == "unit-u0"


def test_two_candidate_fixture_response_is_distinct_but_uses_same_bound_unit_and_evidence():
    request = {
        "messages": [
            {"role": "system", "content": "synthetic system instruction"},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": {"lens": "security", "unit_ids": ["unit-u0"]},
                        "evidence": [
                            {"evidence_id": "diff:u0", "source_kind": "diff"},
                            {"evidence_id": "base:u0", "source_kind": "base_file"},
                        ],
                    }
                ),
            },
        ]
    }
    counters = diagnostic._CallCounters()
    envelope = diagnostic._primary_payload(request, counters, candidate_cardinality=2)
    payload = {key: value for key, value in envelope.items() if key != "_envelope"}
    candidates = payload["finding_candidates"]

    assert len(candidates) == 2
    assert len({
        (candidate["title"], candidate["observation"], candidate["consequence"], candidate["rule_or_contract"])
        for candidate in candidates
    }) == 2
    assert all(candidate["unit_id"] == "unit-u0" for candidate in candidates)
    assert all(candidate["location"]["path"] == "src/auth.py" for candidate in candidates)
    assert all(candidate["evidence_refs"] == ["diff:u0"] for candidate in candidates)
    assert counters["primary_security_received"] == 1


@pytest.mark.parametrize("bad", [True, 0, 3, "2", None])
def test_candidate_cardinality_rejects_unbounded_or_ambiguous_values(bad):
    with pytest.raises(ValueError, match="candidate_cardinality_invalid"):
        diagnostic._validate_candidate_cardinality(bad)


def _cardinality_identity_for_test():
    return {
        "runtime_source_commit": "a" * 40,
        "diagnostic_script_sha256": "b" * 64,
        "runtime_tree_sha256": "c" * 64,
        "runtime_module_count": 35,
        "runtime_module_hashes": {f"pr_review_harness/mod{i}.py": "d" * 64 for i in range(35)},
        "installed_source_match": True,
        "fixture_suite_sha256": "e" * 64,
        "generated_profile_sha256": "f" * 64,
        "limits_sha256": "1" * 64,
        "base_sha": "2" * 40,
        "head_sha": "3" * 40,
        "snapshot_id": "snap-test",
        "snapshot_hash": "4" * 64,
        "observer_id": diagnostic.observer.OBSERVER_ID,
        "observer_source_sha256": "5" * 64,
        "syscall_scope": diagnostic.observer.SYSCALL_SCOPE,
        "trace_cap_bytes": diagnostic.observer.TRACE_MAX_BYTES,
        "configured_transport": "HTTP_LOOPBACK_FAKE",
    }


def _complete_cardinality_arm_for_test(count: int, *, trace_bytes: int = 400_000):
    stages = diagnostic._cardinality_stage_counts(count)
    return {
        "requested_candidate_count": count,
        "input_identity": _cardinality_identity_for_test(),
        "observer_reason": None,
        "trace_attribution": {
            "state": "COMPLETE",
            "trace_bytes": trace_bytes,
            "unattributed_or_partial_bytes": 0,
            "bytes_by_syscall": {
                "newfstatat": 1000,
                "openat": 800,
                "OTHER": trace_bytes - 1000 - 800 - 4 - 5 - 6,
                "PROCESS_END": 4,
                "SIGNAL": 5,
                "UNPARSED": 6,
            },
            "lines_by_syscall": {"newfstatat": 10, "openat": 8, "OTHER": 1, "PROCESS_END": 1, "SIGNAL": 1, "UNPARSED": 1},
            "newline_terminated_line_bytes": trace_bytes,
            "parsed_line_count": 22,
            "parse_failure_count": 0,
            "file_path_attribution": {
                "state": "COMPLETE",
                "reconciliation": "MATCH",
                "lines_by_syscall_class": {"openat": {"SYSTEM_ROOT": 8}, "newfstatat": {"UNKNOWN_RAW_ARGUMENTS": 10}},
                "bytes_by_syscall_class": {"openat": {"SYSTEM_ROOT": 800}, "newfstatat": {"UNKNOWN_RAW_ARGUMENTS": 1000}},
                "target_lines_by_syscall": {"openat": 8, "newfstatat": 10},
                "target_bytes_by_syscall": {"openat": 800, "newfstatat": 1000},
            },
        },
        "protocol_stage_counts": stages,
        "primary_task_statuses": [
            {"lens": lens, "status": "SUCCEEDED"} for lens in ("correctness", "security", "tests")
        ],
        "candidate_count": count,
        "claim_assessment_rows": count,
        "claim_assessment_statuses": ["COMPLETE"] * count,
        "native_advisory_status": "RECEIVED",
        "cli_invocation_status": "CLI_COMPLETED",
        "cli_exit_code": 0,
        "coverage_state": "COMPLETE",
        "protocol_exchange_state": "SERVER_WRITES_SETTLED",
        "fake_server_handlers_settled": True,
        "fake_server_active_handlers_at_snapshot": 0,
        "http_requests_received": 4 + 2 * count,
        "server_response_writes_completed": 4 + 2 * count,
        "observer_coverage": "SCOPED_COMPLETE",
        "synthetic_protocol_path_state": "COMPLETE",
        "request_body_bytes_by_stage": {"primary_security": 2000 + count},
        "response_body_bytes_by_stage": {"primary_security": 400 + 100 * count},
    }


def test_candidate_cardinality_pair_projection_requires_complete_normal_path_and_reports_byte_deltas():
    one = _complete_cardinality_arm_for_test(1, trace_bytes=400_000)
    two = _complete_cardinality_arm_for_test(2, trace_bytes=410_000)
    result = diagnostic._candidate_cardinality_comparison(one, two)

    assert diagnostic._cardinality_arm_state(one, 1) == "COMPLETE"
    assert diagnostic._cardinality_arm_state(two, 2) == "COMPLETE"
    assert result["state"] == "COMPLETE"
    assert result["input_identity_match"] is True
    assert result["trace_bytes_delta_two_minus_one"] == 10_000
    assert result["request_body_bytes_delta_two_minus_one"]["primary_security"] == 1
    assert result["response_body_bytes_delta_two_minus_one"]["primary_security"] == 100
    assert result["arms"][0]["http_requests_received"] == 6
    assert result["arms"][1]["http_requests_received"] == 8
    assert diagnostic.CARDINALITY_PAIR_CONTRACT_VERSION.endswith(".v2")
    assert "Synthetic" not in json.dumps(result)


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"candidate_count": 1}, "CANDIDATE_STAGES_INCOMPLETE"),
        ({"protocol_stage_counts": {"primary_security_received": 2}}, "PROTOCOL_STAGE_MISMATCH"),
        ({"trace_attribution": {"state": "COMPLETE", "trace_bytes": 1_048_577,
                                "unattributed_or_partial_bytes": 0}}, "TRACE_CAP_EXCEEDED"),
        ({"trace_attribution": {"state": "UNKNOWN", "trace_bytes": None}}, "TRACE_MEASUREMENT_UNKNOWN"),
    ],
)
def test_candidate_cardinality_arm_rejects_stage_count_and_cap_near_misses(change, expected):
    arm = _complete_cardinality_arm_for_test(2)
    arm.update(change)
    assert diagnostic._cardinality_arm_state(arm, 2) == expected


def test_candidate_cardinality_pair_rejects_input_identity_mismatch_and_preserves_incomplete_arm():
    one = _complete_cardinality_arm_for_test(1)
    two = _complete_cardinality_arm_for_test(2)
    two["input_identity"] = {**two["input_identity"], "generated_profile_sha256": "6" * 64}
    result = diagnostic._candidate_cardinality_comparison(one, two)
    assert result["state"] == "INPUT_IDENTITY_MISMATCH"
    assert result["input_identity_match"] is False

    two = _complete_cardinality_arm_for_test(2)
    two["observer_reason"] = "trace_byte_cap_exceeded"
    two["trace_attribution"]["trace_bytes"] = diagnostic.observer.TRACE_MAX_BYTES
    two["arm_state"] = "TRACE_CAP_EXCEEDED"
    result = diagnostic._candidate_cardinality_comparison(one, two)
    assert result["state"] == "INCOMPLETE"
    assert result["arms"][1]["state"] == "TRACE_CAP_EXCEEDED"
    assert result["trace_bytes_delta_two_minus_one"] == diagnostic.observer.TRACE_MAX_BYTES - 400_000


def test_candidate_cardinality_comparison_recomputes_arm_state_and_projects_bounded_trace_attribution():
    one = _complete_cardinality_arm_for_test(1)
    two = _complete_cardinality_arm_for_test(2)
    one["arm_state"] = "COMPLETE"
    two["arm_state"] = "COMPLETE"
    two["observer_coverage"] = "INCOMPLETE"
    result = diagnostic._candidate_cardinality_comparison(one, two)

    assert result["state"] == "INCOMPLETE"
    assert result["arms"][0]["state"] == "COMPLETE"
    assert result["arms"][1]["state"] == "PROTOCOL_OR_OBSERVER_INCOMPLETE"
    assert result["arms"][0]["trace_bytes_by_syscall"] == {
        "OTHER": 398_185,
        "PROCESS_END": 4,
        "SIGNAL": 5,
        "UNPARSED": 6,
        "newfstatat": 1000,
        "openat": 800,
    }
    assert result["arms"][0]["trace_parsed_line_count"] == 22
    assert sum(result["arms"][0]["trace_lines_by_syscall"].values()) == result["arms"][0]["trace_parsed_line_count"]
    assert sum(result["arms"][0]["trace_bytes_by_syscall"].values()) == result["arms"][0]["trace_newline_terminated_line_bytes"]
    assert result["arms"][0]["file_path_attribution"]["bytes_by_syscall_class"] == {
        "openat": {"SYSTEM_ROOT": 800},
        "newfstatat": {"UNKNOWN_RAW_ARGUMENTS": 1000},
    }
    assert "/" not in json.dumps(result)


def test_cardinality_trace_allowlist_covers_actual_line_attributor_labels_only():
    lines = (
        'openat(AT_FDCWD, "/tmp/file", O_RDONLY) = 3',
        "+++ exited with 0 +++",
        "--- SIGCHLD {si_signo=SIGCHLD} ---",
        "unparsed but bounded trace fragment",
        "custom_fake_syscall(1) = 0",
    )
    labels = [diagnostic._label_line(line) for line in lines]
    assert labels == ["openat", "PROCESS_END", "SIGNAL", "UNPARSED", "OTHER"]
    projected = diagnostic._bounded_numeric_map(dict.fromkeys(labels, 1), diagnostic._TRACE_LINE_LABELS)
    assert projected == {"OTHER": 1, "PROCESS_END": 1, "SIGNAL": 1, "UNPARSED": 1, "openat": 1}
    assert diagnostic._bounded_numeric_map({"UNEXPECTED_RAW_LABEL": 1}, diagnostic._TRACE_LINE_LABELS) is None


@pytest.mark.parametrize(
    "mutation",
    [
        lambda trace: trace["bytes_by_syscall"].__setitem__("OTHER", trace["bytes_by_syscall"]["OTHER"] - 1),
        lambda trace: trace.__setitem__("newline_terminated_line_bytes", trace["trace_bytes"] - 1),
        lambda trace: trace.__setitem__("parsed_line_count", trace["parsed_line_count"] - 1),
        lambda trace: trace.__setitem__("unattributed_or_partial_bytes", 1),
    ],
    ids=("syscall-byte-sum", "newline-byte-total", "parsed-line-total", "residual-bytes"),
)
def test_cardinality_complete_state_requires_reconciled_trace_totals(mutation):
    arm = _complete_cardinality_arm_for_test(1)
    mutation(arm["trace_attribution"])
    assert diagnostic._cardinality_arm_state(arm, 1) == "TRACE_SYSCALL_ATTRIBUTION_INCOMPLETE"


def test_candidate_cardinality_comparison_rejects_claimed_complete_with_missing_attribution():
    one = _complete_cardinality_arm_for_test(1)
    two = _complete_cardinality_arm_for_test(2)
    two["arm_state"] = "COMPLETE"
    del two["trace_attribution"]["file_path_attribution"]
    result = diagnostic._candidate_cardinality_comparison(one, two)
    assert result["state"] == "INCOMPLETE"
    assert result["arms"][1]["state"] == "FILE_PATH_ATTRIBUTION_INCOMPLETE"


@pytest.mark.parametrize(("pair_state", "expected_exit"), [("COMPLETE", 0), ("INCOMPLETE", 2)])
def test_pair_cli_exit_code_uses_pair_state(pair_state, expected_exit, monkeypatch, capsys):
    monkeypatch.setattr(
        diagnostic,
        "run_candidate_cardinality_pair",
        lambda *_args, **_kwargs: {"pair_state": pair_state},
    )
    assert diagnostic.main(["--cli", "/usr/bin/pr-review", "--candidate-cardinality-pair"]) == expected_exit
    assert json.loads(capsys.readouterr().out) == {"pair_state": pair_state}


def test_second_cardinality_arm_guard_rejects_empty_and_bad_baselines_but_allows_normal_path_without_observer():
    assert diagnostic._cardinality_baseline_allows_second_arm([]) is False
    assert diagnostic._cardinality_baseline_allows_second_arm([None]) is False
    assert diagnostic._cardinality_baseline_allows_second_arm([{"arm_state": "COMPLETE"}]) is False
    assert diagnostic._cardinality_baseline_allows_second_arm([_complete_cardinality_arm_for_test(1)]) is True
    no_observer_completed_protocol = {
        "arm_state": "TRACE_MEASUREMENT_UNKNOWN",
        "observer_mode": "NOT_OBSERVED_PLATFORM_OR_EXPLICIT",
        "trace_attribution": {"state": "UNKNOWN"},
        "synthetic_protocol_path_state": "COMPLETE",
        "protocol_exchange_state": "SERVER_WRITES_SETTLED",
    }
    assert diagnostic._cardinality_baseline_allows_second_arm([no_observer_completed_protocol]) is True
    cap_failed_protocol = {**no_observer_completed_protocol, "observer_mode": "LINUX_STRACE", "arm_state": "TRACE_CAP_EXCEEDED"}
    assert diagnostic._cardinality_baseline_allows_second_arm([cap_failed_protocol]) is False


def test_native_claim_questions_match_exact_supported_contract_shapes():
    candidate_id = "candidate-17"
    base_head_questions, _ = _questions(
        candidate_id, True, PRIMARY_ASSESSMENT_CONTRACT_VERSION
    )
    primary_request = {
        "model": diagnostic.JEV_ALIAS,
        "state": {
            "candidate": {"candidate_id": candidate_id},
            "cited_evidence": [{"side": "BASE"}, {"side": "HEAD"}],
            "assessment_contract_version": PRIMARY_ASSESSMENT_CONTRACT_VERSION,
        },
        "questions": base_head_questions,
    }
    assert len(base_head_questions) == 6
    assert diagnostic._native_claim_contract_valid(primary_request)
    assert not diagnostic._native_claim_contract_valid(
        {**primary_request, "questions": dict(list(base_head_questions.items())[:-1])}
    )
    mixed_evidence_request = {
        **primary_request,
        "state": {
            **primary_request["state"],
            "cited_evidence": [{"side": "BASE"}, {"side": "HEAD"}, {"side": None}],
        },
    }
    assert diagnostic._native_claim_contract_valid(mixed_evidence_request)
    wrong_questions = dict(base_head_questions)
    wrong_questions["ca-" + "0" * 24] = wrong_questions.pop(next(iter(wrong_questions)))
    assert not diagnostic._native_claim_contract_valid({**primary_request, "questions": wrong_questions})
    changed_criteria = json.loads(json.dumps(base_head_questions))
    first_question = next(iter(changed_criteria.values()))
    first_question["criteria"] = {"UNEXPECTED": "not from the pinned contract"}
    assert not diagnostic._native_claim_contract_valid({**primary_request, "questions": changed_criteria})

    legacy_questions, _ = _questions(candidate_id, False, CONTRACT_VERSION)
    legacy_request = {
        "model": diagnostic.JEV_ALIAS,
        "state": {
            "candidate": {"candidate_id": candidate_id},
            "cited_evidence": [{"side": "BASE"}],
        },
        "questions": legacy_questions,
    }
    assert len(legacy_questions) == 5
    assert diagnostic._native_claim_contract_valid(legacy_request)


def test_native_summary_contract_is_exact_and_typed():
    request = {
        "model": diagnostic.JEV_ALIAS,
        "state": {"review_evidence": "bounded evidence"},
        "questions": {"review_claim": {"type": "noul", "instructions": "Assess only this evidence."}},
    }
    assert diagnostic._native_summary_contract_valid(request)
    assert not diagnostic._native_summary_contract_valid(
        {**request, "questions": {**request["questions"], "extra": {"type": "noul"}}}
    )
    assert not diagnostic._native_summary_contract_valid({**request, "model": "other-model"})


def test_task_projection_preserves_denominator_and_quarantines_unknown_values():
    plan = [
        {"task_id": "t1", "lens": "correctness"},
        {"task_id": "t2", "lens": "security"},
        {"task_id": "t3", "lens": "tests"},
    ]
    durable = {
        "task_results": {
            "t1:chunk-1": {"status": "SUCCEEDED"},
            "t2:chunk-1": {"status": "UNTRUSTED_PRIVATE_TEXT", "error_code": "untrusted"},
            "unexpected:model": {"status": "SUCCEEDED"},
        }
    }
    rows, unexpected = diagnostic._project_task_statuses(durable, plan)
    assert rows == [
        {"task_id": "t1", "lens": "correctness", "status": "SUCCEEDED", "chunk_count": 1, "completed_chunks": 1},
        {"task_id": "t2", "lens": "security", "status": "UNKNOWN", "chunk_count": 1, "completed_chunks": 0},
        {"task_id": "t3", "lens": "tests", "status": "MISSING_RESULT", "chunk_count": 0, "completed_chunks": 0},
    ]
    assert unexpected == 1


def test_invalid_runtime_provenance_stops_before_fake_server_creation(monkeypatch, tmp_path):
    cli = tmp_path / "pr-review"
    cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    cli.chmod(0o700)

    def reject_runtime(*_args):
        raise RuntimeError("runtime_mismatch")

    monkeypatch.setattr(diagnostic, "_runtime_provenance", reject_runtime)
    monkeypatch.setattr(diagnostic, "_FakeServer", lambda *_args: pytest.fail("server bound before runtime validation"))
    with pytest.raises(RuntimeError, match="runtime_mismatch"):
        diagnostic.run(cli)


def test_fake_server_idle_wait_reports_unsettled_then_settled_handlers():
    server = object.__new__(diagnostic._FakeServer)
    server._active_handlers = 1
    server._idle_condition = diagnostic.threading.Condition()
    release = diagnostic.threading.Event()

    def finish():
        assert release.wait(1)
        server.handler_finished()

    thread = diagnostic.threading.Thread(target=finish)
    thread.start()
    try:
        assert server.wait_until_idle(0.001) == (False, 1)
        release.set()
        assert server.wait_until_idle(1) == (True, 0)
    finally:
        release.set()
        thread.join(timeout=1)
    assert not thread.is_alive()


@pytest.mark.parametrize("delay", [True, float("nan"), float("inf"), -0.01, 15.01])
def test_primary_latency_probe_rejects_invalid_or_over_timeout_values(delay):
    with pytest.raises(ValueError, match="primary_response_delay_invalid"):
        diagnostic.run(Path("/unused"), primary_response_delay_seconds=delay)


@pytest.mark.parametrize("fail_at", [None, "write", "flush"])
def test_server_write_receipt_is_recorded_only_after_write_and_flush(fail_at):
    counters = diagnostic._CallCounters()

    class Writer:
        def write(self, _data):
            if fail_at == "write":
                raise OSError("simulated disconnected peer")

        def flush(self):
            if fail_at == "flush":
                raise OSError("simulated disconnected peer")

    class Handler:
        def __init__(self):
            self.server = SimpleNamespace(counters=counters)
            self.wfile = Writer()

        def send_response(self, _status):
            return None

        def send_header(self, _name, _value):
            return None

        def end_headers(self):
            return None

        def send_error(self, _status):
            return None

    if fail_at is None:
        assert diagnostic._write_json_response(Handler(), {"ok": True}, "native_claim")
        assert counters["server_response_writes_completed"] == 1
        assert counters["native_claim_response_writes_completed"] == 1
    else:
        with pytest.raises(OSError):
            diagnostic._write_json_response(Handler(), {"ok": True}, "native_claim")
        assert counters["server_response_writes_completed"] == 0
        assert counters["native_claim_response_writes_completed"] == 0


def _complete_transport_arm(transport, *, trace_bytes=500_000):
    stages = {
        name: 1
        for name in (
            "primary_correctness_received", "primary_security_received", "primary_tests_received",
            "semantic_adjudication_received", "native_claim_received", "native_summary_received",
            "primary_correctness_response_writes_completed", "primary_security_response_writes_completed",
            "primary_tests_response_writes_completed", "semantic_adjudication_response_writes_completed",
            "native_claim_response_writes_completed", "native_summary_response_writes_completed",
        )
    }
    return {
        "configured_transport": "HTTPS_LOOPBACK_FAKE" if transport == "https" else "HTTP_LOOPBACK_FAKE",
        "runtime_tree_sha256": "1" * 64,
        "runtime_source_commit": "2" * 40,
        "runtime_source_tree_dirty": False,
        "runtime_module_hashes": {f"pr_review_harness/m{i}.py": "3" * 64 for i in range(35)},
        "diagnostic_script_sha256": "4" * 64,
        "fixture_suite_sha256": "5" * 64,
        "generated_profile_sha256": "6" * 64,
        "limits_sha256": "7" * 64,
        "base_sha": "8" * 40,
        "head_sha": "9" * 40,
        "snapshot_id": "snap-fixed",
        "snapshot_hash": "a" * 64,
        "task_lenses": ["correctness", "security", "tests"],
        "run_id": "r1-control",
        "event_mode": "LOCAL_EXPLICIT_BASE_HEAD_NO_GITHUB_EVENT",
        "event_identity": None,
        "task_ids": ["task-1", "task-2", "task-3"],
        "primary_task_statuses": [
            {"task_id": f"task-{i}", "lens": lens, "status": "SUCCEEDED"}
            for i, lens in enumerate(("correctness", "security", "tests"), 1)
        ],
        "observer_id": "linux-strace-syscall-observer.v3",
        "observer_source_sha256": "b" * 64,
        "strace_version": "strace -- version test",
        "strace_executable_sha256": "c" * 64,
        "syscall_scope": list(diagnostic.observer.SYSCALL_SCOPE),
        "trace_cap_bytes": diagnostic.observer.TRACE_MAX_BYTES,
        "observer_mode": "LINUX_STRACE",
        "observer_coverage": "SCOPED_COMPLETE",
        "observer_reason": None,
        "trace_attribution": {"state": "COMPLETE", "trace_bytes": trace_bytes,
                              "bytes_by_syscall": {"openat": trace_bytes - 100, "connect": 100}},
        "protocol_exchange_state": "SERVER_WRITES_SETTLED",
        "protocol_stage_counts": stages,
        "http_requests_received": 6,
        "server_response_writes_completed": 6,
        "fake_server_handlers_settled": True,
        "fake_server_active_handlers_at_snapshot": 0,
        "synthetic_protocol_path_state": "COMPLETE",
        "coverage_state": "COMPLETE",
        "claim_assessment_statuses": ["COMPLETE"],
        "native_advisory_status": "RECEIVED",
        "cli_invocation_status": "CLI_COMPLETED",
        "cli_exit_code": 0,
        "cli_result_present": True,
        "candidate_count": 1,
        "unexpected_task_result_count": 0,
        "transport_payload_hashes": {
            stage: {
                "request_bytes": 100,
                "request_sha256": "d" * 64,
                "response_bytes": 80,
                "response_sha256": "e" * 64,
            }
            for stage in ("primary_correctness", "primary_security", "primary_tests",
                          "semantic_adjudication", "native_claim", "native_summary")
        },
        "provider_config_sha256": "f" * 64 if transport == "http" else "0" * 64,
        "decision_config_sha256": "a" * 64 if transport == "http" else "b" * 64,
        "normalized_transport_config_sha256": "c" * 64,
    }


def _mock_transport_pair_inputs(monkeypatch, tmp_path, run_arms):
    monkeypatch.setattr(diagnostic, "CASE_IDS", ("r1-control",))
    cli = tmp_path / "pr-review"
    cli.write_text("synthetic-test-only\n", encoding="utf-8")
    cli.chmod(0o700)
    profile = tmp_path / "profile.json"
    profile.write_text("{}\n", encoding="utf-8")
    case = SimpleNamespace(
        case_id="r1-control", snapshot={"snapshot_id": "snap-fixed", "snapshot_hash": "a" * 64},
        base_sha="8" * 40, head_sha="9" * 40,
    )
    prepared = SimpleNamespace(suite_sha256="5" * 64, profile_path=profile, profile={}, cases=(case,))
    module_files = {f"src/pr_review_harness/m{i}.py": "3" * 64 for i in range(35)}
    monkeypatch.setattr(diagnostic, "_runtime_provenance", lambda *_: {
        "runtime_tree_sha256": "1" * 64,
        "source_fingerprint": {"git_revision": "2" * 40, "working_tree_dirty": False, "file_hashes": module_files},
    })
    monkeypatch.setattr(diagnostic, "_diagnostic_checkout_identity", lambda: {
        "diagnostic_head_sha": "4" * 40, "diagnostic_script_sha256": "5" * 64,
        "diagnostic_script_differs_from_head": True,
    })
    monkeypatch.setattr(diagnostic, "prepare_suite", lambda *_args, **_kwargs: prepared)
    monkeypatch.setattr(diagnostic, "plan_review", lambda *_args: {
        "tasks": [{"task_id": f"task-{i}", "lens": lens}
                  for i, lens in enumerate(("correctness", "security", "tests"), 1)]
    })
    cert = tmp_path / "ca.pem"
    key = tmp_path / "key.pem"
    cert.write_text("synthetic cert placeholder\n", encoding="utf-8")
    key.write_text("synthetic private key placeholder\n", encoding="utf-8")
    monkeypatch.setattr(diagnostic, "_write_loopback_certificate", lambda _root: (cert, key, "6" * 64))
    monkeypatch.setattr(diagnostic, "_transport_server_context", lambda *_: object())
    calls = []

    def fake_run(_cli, **kwargs):
        calls.append(kwargs)
        return run_arms[kwargs["_transport"]]

    monkeypatch.setattr(diagnostic, "run", fake_run)
    return cli, prepared, calls


def test_transport_pair_stops_before_tls_when_http_baseline_is_incomplete(monkeypatch, tmp_path):
    monkeypatch.setattr(diagnostic.sys, "platform", "linux")
    http = _complete_transport_arm("http", trace_bytes=diagnostic.observer.TRACE_MAX_BYTES)
    cli, prepared, calls = _mock_transport_pair_inputs(
        monkeypatch, tmp_path, {"http": http, "https": _complete_transport_arm("https")}
    )
    result = diagnostic.run_transport_pair(cli, workdir=tmp_path)
    assert result["pair_state"] == "INCOMPLETE"
    assert result["reason"] == "HTTP_BASELINE_INCOMPLETE_TLS_NOT_RUN"
    assert len(calls) == 1 and calls[0]["_transport"] == "http"
    assert calls[0]["_prepared"] is prepared
    assert result["arms"][1]["state"] == "NOT_RUN_HTTP_BASELINE_INCOMPLETE"


def test_transport_pair_rejects_incomplete_observer_even_when_trace_is_below_cap():
    arm = _complete_transport_arm("http", trace_bytes=510_000)
    arm["observer_reason"] = "observer_cleanup_incomplete"
    assert not diagnostic._transport_pair_complete(arm)


def test_transport_pair_reuses_exact_prepared_case_and_requires_matching_body_hashes(monkeypatch, tmp_path):
    monkeypatch.setattr(diagnostic.sys, "platform", "linux")
    http = _complete_transport_arm("http", trace_bytes=510_000)
    https = _complete_transport_arm("https", trace_bytes=525_000)
    cli, prepared, calls = _mock_transport_pair_inputs(monkeypatch, tmp_path, {"http": http, "https": https})
    result = diagnostic.run_transport_pair(cli, workdir=tmp_path)
    assert result["pair_state"] == "COMPLETE"
    assert result["run_id"] == "r1-control"
    assert result["event_mode"] == "LOCAL_EXPLICIT_BASE_HEAD_NO_GITHUB_EVENT"
    assert result["task_ids"] == ["task-1", "task-2", "task-3"]
    assert result["comparison"]["trace_bytes_delta_https_minus_http"] == 15_000
    assert len(calls) == 2 and [call["_transport"] for call in calls] == ["http", "https"]
    assert all(call["_prepared"] is prepared for call in calls)
    assert calls[0]["_environment_override"] == calls[1]["_environment_override"]
    assert calls[0]["_ssl_context"] is None and calls[1]["_ssl_context"] is not None

    https["transport_payload_hashes"] = {**https["transport_payload_hashes"], "native_claim": {"request_sha256": "f" * 64}}
    result = diagnostic.run_transport_pair(cli, workdir=tmp_path)
    assert result["pair_state"] == "INCOMPLETE"
    assert result["comparison"] is None


def test_transport_pair_requires_verified_local_tls_certificate_and_explicit_failure(tmp_path, monkeypatch):
    if diagnostic.shutil.which("openssl") is None:
        pytest.skip("openssl unavailable for the local TLS fixture")
    cert, key, cert_hash = diagnostic._write_loopback_certificate(tmp_path)
    assert cert_hash == diagnostic.hashlib.sha256(cert.read_bytes()).hexdigest()
    assert key.stat().st_mode & 0o777 == 0o600
    server_context = diagnostic._transport_server_context(cert, key)
    client_context = ssl.create_default_context(cafile=str(cert))
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(
        client_in, client_out, server_side=False, server_hostname="127.0.0.1"
    )
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    client_done = server_done = False
    for _ in range(20):
        for endpoint, outgoing, opposite_incoming in (
            (client, client_out, server_in),
            (server, server_out, client_in),
        ):
            if endpoint is client and client_done or endpoint is server and server_done:
                continue
            try:
                endpoint.do_handshake()
                if endpoint is client:
                    client_done = True
                else:
                    server_done = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            pending = outgoing.read()
            if pending:
                opposite_incoming.write(pending)
        if client_done and server_done:
            break
    assert client_done and server_done
    assert client.getpeercert().get("subjectAltName")

    monkeypatch.setattr(diagnostic.shutil, "which", lambda _name: None)
    with pytest.raises(RuntimeError, match="transport_tls_openssl_unavailable"):
        diagnostic._write_loopback_certificate(tmp_path / "no-openssl")


def test_transport_pair_cli_is_opt_in_and_mutually_exclusive(monkeypatch, capsys):
    monkeypatch.setattr(diagnostic, "run_transport_pair", lambda *_args, **_kwargs: {"pair_state": "COMPLETE"})
    assert diagnostic.main(["--cli", "/unused", "--transport-pair"]) == 0
    row = json.loads(capsys.readouterr().out)
    assert row == {"pair_state": "COMPLETE"}
    with pytest.raises(SystemExit):
        diagnostic.main(["--cli", "/unused", "--transport-pair", "--candidate-cardinality-pair"])
    assert diagnostic.main(["--cli", "/unused", "--transport-pair", "--no-observer"]) == 2
    assert json.loads(capsys.readouterr().out)["error_type"] == "ValueError"
