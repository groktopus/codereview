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
    assert set(attributor.__dict__) == {"parser", "cwd", "bytes_by_label", "lines_by_label", "total_line_bytes", "parse_failures"}


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
