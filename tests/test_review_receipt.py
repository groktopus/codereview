"""Tests for the merge-review receipt validator (GA-1)."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_review_receipt as receipt_check  # noqa: E402

HEAD_SHA = "0123456789abcdef0123456789abcdef01234567"
AUTHOR = "pull-request-author"


def receipt(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "schema": "review-receipt.v1",
        "reviewer": {"identity": "independent-reviewer", "kind": "human"},
        "reviewed_sha": HEAD_SHA,
        "independence": "Independent reviewer; did not author, pair on, or advise this change.",
        "scope": ["diff 0123456..89abcde", "src/example.py", "tests/test_example.py"],
        "verdict": "CLEAR",
        "evidence": [
            {"kind": "link", "value": "https://github.com/groktopus/codereview/actions/runs/1"},
            {"kind": "command", "value": "python -m pytest -q tests/test_example.py -> 12 passed"},
        ],
        "reviewed_at": "2026-11-02T12:00:00Z",
        "self_review": False,
        "post_merge_verification": "Verify the merge commit contains the reviewed head and its required checks pass.",
    }
    data.update(copy.deepcopy(overrides))
    return data


def body_with(receipt_object: Any) -> str:
    return "Summary\n\n```review-receipt\n" + json.dumps(receipt_object, indent=2) + "\n```\n"


def event(body: str, *, head_sha: str = HEAD_SHA, author: str = AUTHOR) -> dict[str, Any]:
    return {
        "number": 1,
        "pull_request": {
            "body": body,
            "head": {"sha": head_sha},
            "base": {"sha": "f" * 40},
            "user": {"login": author},
        },
    }


def write_event(tmp_path: Path, payload: Any) -> Path:
    path = tmp_path / "pull_request.json"
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def run_cli(tmp_path: Path, payload: Any, *extra: str) -> int:
    path = write_event(tmp_path, payload)
    return receipt_check.main(["--event", str(path), *extra])


def failure_codes(report: receipt_check.Report) -> set[str]:
    return {failure.code for failure in report.failures}


def test_valid_receipt_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli(tmp_path, event(body_with(receipt()))) == 0
    captured = capsys.readouterr()
    assert "review-receipt: PASS" in captured.out
    assert f"reviewed_sha={HEAD_SHA}" in captured.out
    assert captured.err == ""


def test_valid_receipt_json_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli(tmp_path, event(body_with(receipt())), "--json") == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "PASS"
    assert report["exit_code"] == 0
    assert report["head_sha"] == HEAD_SHA
    assert report["reviewed_sha"] == HEAD_SHA
    assert report["verdict"] == "CLEAR"
    assert report["failures"] == []


def test_missing_event_path_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    assert receipt_check.main(["--event", str(tmp_path / "absent.json")]) == receipt_check.EXIT_EVENT
    path = tmp_path / "absent.json"
    assert receipt_check.check(path).failures[0].code == "EVENT_PATH_MISSING"


def test_missing_environment_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    assert receipt_check.main([]) == receipt_check.EXIT_EVENT


def test_invalid_event_json_fails_closed(tmp_path: Path) -> None:
    assert run_cli(tmp_path, "{not json") == receipt_check.EXIT_EVENT


def test_event_without_pull_request_fails_closed(tmp_path: Path) -> None:
    assert run_cli(tmp_path, {"number": 1}) == receipt_check.EXIT_EVENT


def test_event_without_head_fails_closed(tmp_path: Path) -> None:
    payload = event(body_with(receipt()))
    del payload["pull_request"]["head"]
    assert run_cli(tmp_path, payload) == receipt_check.EXIT_EVENT


def test_event_without_author_fails_closed(tmp_path: Path) -> None:
    payload = event(body_with(receipt()))
    del payload["pull_request"]["user"]
    assert run_cli(tmp_path, payload) == receipt_check.EXIT_EVENT


def test_environment_event_path_is_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write_event(tmp_path, event(body_with(receipt())))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    assert receipt_check.main([]) == 0


def test_missing_receipt_block_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli(tmp_path, event("Summary only.\n")) == receipt_check.EXIT_RECEIPT
    assert "RECEIPT_MISSING" in capsys.readouterr().err


def test_duplicate_receipt_blocks_fail(tmp_path: Path) -> None:
    body = body_with(receipt()) + body_with(receipt())
    report = receipt_check.validate_event(event(body))
    assert failure_codes(report) == {"RECEIPT_DUPLICATE"}
    assert report.exit_code == receipt_check.EXIT_RECEIPT


def test_unclosed_receipt_fence_fails(tmp_path: Path) -> None:
    body = "```review-receipt\n" + json.dumps(receipt()) + "\n"
    report = receipt_check.validate_event(event(body))
    assert failure_codes(report) == {"RECEIPT_UNCLOSED"}


def test_receipt_not_json_fails(tmp_path: Path) -> None:
    assert run_cli(tmp_path, event("```review-receipt\nnope\n```\n")) == receipt_check.EXIT_RECEIPT


def test_abbreviated_reviewed_sha_fails(tmp_path: Path) -> None:
    assert run_cli(tmp_path, event(body_with(receipt(reviewed_sha=HEAD_SHA[:12])))) == receipt_check.EXIT_FIELD


def test_reviewed_sha_mismatch_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli(tmp_path, event(body_with(receipt()), head_sha="b" * 40)) == receipt_check.EXIT_SHA
    assert "SHA_MISMATCH" in capsys.readouterr().err


def test_not_clear_verdict_blocks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli(tmp_path, event(body_with(receipt(verdict="NOT CLEAR")))) == receipt_check.EXIT_VERDICT
    assert "VERDICT_NOT_CLEAR" in capsys.readouterr().err


def test_unknown_verdict_fails_schema(tmp_path: Path) -> None:
    assert run_cli(tmp_path, event(body_with(receipt(verdict="APPROVED")))) == receipt_check.EXIT_FIELD


def test_placeholder_in_required_field_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    placeholder = receipt(independence="<state whether the reviewer is independent of the author>")
    assert run_cli(tmp_path, event(body_with(placeholder))) == receipt_check.EXIT_PLACEHOLDER
    assert "PLACEHOLDER" in capsys.readouterr().err


def test_placeholder_in_scope_fails(tmp_path: Path) -> None:
    assert run_cli(tmp_path, event(body_with(receipt(scope=["TODO"])))) == receipt_check.EXIT_PLACEHOLDER


def test_empty_required_field_fails(tmp_path: Path) -> None:
    assert run_cli(tmp_path, event(body_with(receipt(scope=[])))) == receipt_check.EXIT_FIELD


def test_unknown_field_rejected(tmp_path: Path) -> None:
    assert run_cli(tmp_path, event(body_with(receipt(auto_approve=True)))) == receipt_check.EXIT_FIELD


def test_unknown_reviewer_field_rejected(tmp_path: Path) -> None:
    reviewer = {"identity": "independent-reviewer", "kind": "human", "approved": True}
    assert run_cli(tmp_path, event(body_with(receipt(reviewer=reviewer)))) == receipt_check.EXIT_FIELD


def test_undeclared_self_review_blocks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    self_review = receipt(reviewer={"identity": AUTHOR, "kind": "human"})
    assert run_cli(tmp_path, event(body_with(self_review))) == receipt_check.EXIT_SELF_REVIEW
    assert "SELF_REVIEW_UNDECLARED" in capsys.readouterr().err


def test_declared_self_review_passes(tmp_path: Path) -> None:
    self_review = receipt(reviewer={"identity": AUTHOR, "kind": "human"}, self_review=True)
    assert run_cli(tmp_path, event(body_with(self_review))) == 0


def test_self_review_identity_comparison_is_case_insensitive(tmp_path: Path) -> None:
    self_review = receipt(reviewer={"identity": AUTHOR.upper(), "kind": "human"})
    assert run_cli(tmp_path, event(body_with(self_review))) == receipt_check.EXIT_SELF_REVIEW


def test_failure_codes_map_to_stable_exit_codes() -> None:
    assert set(receipt_check.CODE_EXITS) == {
        "EVENT_PATH_MISSING",
        "EVENT_PATH_UNREADABLE",
        "EVENT_TOO_LARGE",
        "EVENT_INVALID_JSON",
        "EVENT_INVALID_SHAPE",
        "EVENT_HEAD_UNKNOWN",
        "EVENT_AUTHOR_UNKNOWN",
        "RECEIPT_MISSING",
        "RECEIPT_DUPLICATE",
        "RECEIPT_UNCLOSED",
        "RECEIPT_TOO_LARGE",
        "RECEIPT_NOT_JSON",
        "RECEIPT_NOT_OBJECT",
        "RECEIPT_DUPLICATE_KEY",
        "FIELD_MISSING",
        "FIELD_TYPE",
        "FIELD_EMPTY",
        "FIELD_INVALID",
        "FIELD_UNKNOWN",
        "PLACEHOLDER",
        "SHA_MISMATCH",
        "VERDICT_NOT_CLEAR",
        "SELF_REVIEW_UNDECLARED",
        "SELF_REVIEW_INCONSISTENT",
        "AGENT_PROTOCOL_MISSING",
    }
    assert sorted(set(receipt_check.CODE_EXITS.values())) == [2, 3, 4, 5, 6, 7, 8, 9]


def test_self_review_declared_for_other_reviewer_fails(tmp_path: Path) -> None:
    declared = receipt(self_review=True)
    assert run_cli(tmp_path, event(body_with(declared))) == receipt_check.EXIT_SELF_REVIEW


def test_agent_without_protocol_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    agent = receipt(reviewer={"identity": "review-agent/test", "kind": "agent"})
    assert run_cli(tmp_path, event(body_with(agent))) == receipt_check.EXIT_AGENT
    assert "AGENT_PROTOCOL_MISSING" in capsys.readouterr().err


def test_agent_with_protocol_passes(tmp_path: Path) -> None:
    agent = receipt(
        reviewer={
            "identity": "review-agent/test",
            "kind": "agent",
            "protocol": "DeepSeek Harness subagent, disclosed model, read-only diff review; no target execution.",
        }
    )
    assert run_cli(tmp_path, event(body_with(agent))) == 0


def test_evidence_link_requires_http_url(tmp_path: Path) -> None:
    bad = receipt(evidence=[{"kind": "link", "value": "file:///etc/passwd"}])
    assert run_cli(tmp_path, event(body_with(bad))) == receipt_check.EXIT_FIELD


def test_command_evidence_is_not_executed(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    command = f"touch {marker}"
    assert run_cli(tmp_path, event(body_with(receipt(evidence=[{"kind": "command", "value": command}])))) == 0
    assert not marker.exists()


def test_timestamp_requires_timezone(tmp_path: Path) -> None:
    assert run_cli(tmp_path, event(body_with(receipt(reviewed_at="2026-11-02T12:00:00")))) == receipt_check.EXIT_FIELD


def test_timestamp_must_be_iso8601(tmp_path: Path) -> None:
    assert run_cli(tmp_path, event(body_with(receipt(reviewed_at="yesterday")))) == receipt_check.EXIT_FIELD


def test_other_fenced_blocks_are_ignored(tmp_path: Path) -> None:
    body = "```json\n{\"not\": \"a receipt\"}\n```\n\n" + body_with(receipt())
    assert run_cli(tmp_path, event(body)) == 0


def test_tilde_fence_is_supported(tmp_path: Path) -> None:
    body = "~~~review-receipt\n" + json.dumps(receipt()) + "\n~~~\n"
    assert run_cli(tmp_path, event(body)) == 0


def test_repository_template_is_rejected_by_ci() -> None:
    template = (ROOT / ".github/pull_request_template.md").read_text(encoding="utf-8")
    report = receipt_check.validate_event(event(template))
    assert not report.ok
    assert report.exit_code in {
        receipt_check.EXIT_FIELD,
        receipt_check.EXIT_PLACEHOLDER,
        receipt_check.EXIT_VERDICT,
    }


def test_duplicate_json_keys_are_rejected_before_last_key_wins(tmp_path):
    body = body_with(receipt()).replace('"verdict": "CLEAR"', '"verdict": "NOT CLEAR", "verdict": "CLEAR"')
    path = write_event(tmp_path, event(body))
    report = receipt_check.check(path)
    assert report.exit_code == 3
    assert [failure.code for failure in report.failures] == ["RECEIPT_DUPLICATE_KEY"]
