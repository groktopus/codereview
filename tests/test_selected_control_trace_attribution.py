from __future__ import annotations

import json
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
        "runtime_module_count": 28,
        "runtime_module_hashes": {f"pr_review_harness/mod{i}.py": "d" * 64 for i in range(28)},
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
            "bytes_by_syscall": {"newfstatat": 1000, "openat": 800},
            "lines_by_syscall": {"newfstatat": 10, "openat": 8},
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
    assert result["arms"][0]["trace_bytes_by_syscall"] == {"newfstatat": 1000, "openat": 800}
    assert result["arms"][0]["file_path_attribution"]["bytes_by_syscall_class"] == {
        "openat": {"SYSTEM_ROOT": 800},
        "newfstatat": {"UNKNOWN_RAW_ARGUMENTS": 1000},
    }
    assert "/" not in json.dumps(result)


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
