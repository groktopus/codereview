"""Adversarial tests for fail-closed GA-2 decision-record enforcement (issue #270)."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_decision_record_links as links  # noqa: E402

HEAD_SHA = "0123456789abcdef0123456789abcdef01234567"
AUTHOR = "pull-request-author"


def record_text(record_id: str, title: str, status: str) -> str:
    return f"""# {record_id} — {title}

- **Status:** {status}
- **Date:** 2026-11-01
- **Owner:** Test owner
- **Decision authority:** Test authority
- **Scope:** Test scope
- **Evidence:** Test evidence
- **Reversal/expiry:** Never

## Context

Test context.

## Decision

Test decision.

## Consequences

Test consequences.

## Alternatives considered

Test alternative.
"""


INDEX = """# Decision records (ADR index)

| ID | Record | Status | Owner | Date | Evidence |
|---|---|---|---|---|---|
| 0001 | [First record](0001-test-record-1.md) | Accepted | Test owner | 2026-11-01 | Test evidence |
| 0002 | [Second record](0002-test-record-2.md) | Accepted | Test owner | 2026-11-01 | Test evidence |
| 0003 | [Third record](0003-test-record-3.md) | Proposed | Test owner | 2026-11-01 | Test evidence |
"""

MANIFEST = {
    "schema": "decision-record-safety-invariants.v1",
    "invariants": [
        {
            "id": "control-plane",
            "statement": "A test deterministic-control-plane invariant.",
            "paths": ["src/safety.py", "src/safety/*.py", ".github/workflows/safety.yml"],
            "records": ["0002"],
        },
        {
            "id": "globbed",
            "statement": "A test recursive-glob invariant.",
            "paths": ["src/globbed/**/*.py"],
            "records": ["0002"],
        },
    ],
}


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_repo(
    tmp_path: Path,
    *,
    record_status: dict[str, str] | None = None,
    index_status: dict[str, str] | None = None,
) -> Path:
    record_status = record_status or {"0001": "Accepted", "0002": "Accepted", "0003": "Proposed"}
    index_status = index_status or dict(record_status)
    for record_id, status in record_status.items():
        title = f"Test record {record_id.lstrip('0')}"
        write(tmp_path / "docs" / "adr" / f"{record_id}-test-record-{record_id.lstrip('0')}.md", record_text(record_id, title, status))
    index = INDEX
    for record_id, status in index_status.items():
        for previous in ("Accepted", "Proposed"):
            index = index.replace(
                f"| {record_id} | [Test record {record_id.lstrip('0')}]({record_id}-test-record-{record_id.lstrip('0')}.md) | {previous}",
                f"| {record_id} | [Test record {record_id.lstrip('0')}]({record_id}-test-record-{record_id.lstrip('0')}.md) | {status}",
            )
    write(tmp_path / "docs" / "adr" / "README.md", index)
    write(tmp_path / "docs" / "adr" / "safety-invariants.json", json.dumps(MANIFEST, indent=2))
    return tmp_path


def receipt(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "schema": "review-receipt.v1",
        "reviewer": {"identity": "independent-reviewer", "kind": "human"},
        "reviewed_sha": HEAD_SHA,
        "independence": "Independent reviewer; did not author, pair on, or advise this change.",
        "scope": ["diff 0123456..89abcde", "the changed safety-invariant path"],
        "verdict": "CLEAR",
        "evidence": [
            {"kind": "link", "value": "https://github.com/groktopus/codereview/actions/runs/1"},
        ],
        "reviewed_at": "2026-11-02T12:00:00Z",
        "self_review": False,
        "post_merge_verification": "Verify the merge commit contains the reviewed head and its required checks pass.",
    }
    data.update(copy.deepcopy(overrides))
    return data


def event(body_object: dict[str, Any] | None, *, body: str | None = None) -> dict[str, Any]:
    if body is None:
        body = "Summary\n\n```review-receipt\n" + json.dumps(body_object, indent=2) + "\n```\n"
    return {
        "action": "opened",
        "number": 7,
        "pull_request": {
            "number": 7,
            "body": body,
            "head": {"sha": HEAD_SHA},
            "base": {"sha": "f" * 40, "ref": "main"},
            "user": {"login": AUTHOR},
        },
        "repository": {"full_name": "groktopus/codereview"},
    }


class Harness:
    def __init__(self, tmp_path: Path) -> None:
        self.root = make_repo(tmp_path)
        self.event_path = tmp_path / "event.json"
        self.files_path = tmp_path / "changed-files.json"
        self.set_event(receipt())
        self.set_files(["src/other.py"])

    def set_event(self, receipt_object: dict[str, Any] | None, *, body: str | None = None) -> None:
        self.event_path.write_text(json.dumps(event(receipt_object, body=body)), encoding="utf-8")

    def set_files(self, paths: list[Any]) -> None:
        self.files_path.write_text(json.dumps(paths), encoding="utf-8")

    def run(self, *extra: str, monkeypatch: pytest.MonkeyPatch | None = None) -> int:
        argv = [
            "--event",
            str(self.event_path),
            "--changed-files",
            str(self.files_path),
            "--repo-root",
            str(self.root),
            *extra,
        ]
        return links.main(argv)


def report_json(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    return json.loads(capsys.readouterr().out)


def codes(report: dict[str, Any]) -> set[str]:
    return {failure["code"] for failure in report["failures"]}


# ---------------------------------------------------------------------------
# Required-record behaviour


def test_safety_path_changed_without_records_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety.py"])
    assert harness.run("--json") == links.EXIT_DECISION_RECORDS
    report = report_json(capsys)
    assert report["status"] == "FAIL"
    assert codes(report) == {"DECISION_RECORDS_MISSING"}
    assert [match["path"] for match in report["safety_paths"]] == ["src/safety.py"]


def test_glob_safety_path_changed_without_records_fails(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety/guard.py"])
    assert harness.run() == links.EXIT_DECISION_RECORDS


def test_recursive_glob_safety_path_changed_without_records_fails(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/globbed/deep/nested/module.py"])
    assert harness.run() == links.EXIT_DECISION_RECORDS


def test_safety_path_with_accepted_record_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety.py"])
    harness.set_event(receipt(decision_records=["0002"]))
    assert harness.run("--json") == 0
    report = report_json(capsys)
    assert report["status"] == "PASS"
    assert report["decision_records"] == ["0002"]
    assert report["failures"] == []


def test_path_reference_passes(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety.py"])
    harness.set_event(receipt(decision_records=["docs/adr/0002-test-record-2.md"]))
    assert harness.run() == 0


def test_repository_link_reference_passes(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety.py"])
    harness.set_event(
        receipt(decision_records=["https://github.com/groktopus/codereview/blob/main/docs/adr/0002-test-record-2.md"])
    )
    assert harness.run() == 0


def test_unknown_record_id_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety.py"])
    harness.set_event(receipt(decision_records=["0099"]))
    assert harness.run("--json") == links.EXIT_RECORD
    report = report_json(capsys)
    assert codes(report) == {"RECORD_NOT_INDEXED"}
    assert "0099" in report["failures"][0]["message"]


def test_proposed_record_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety.py"])
    harness.set_event(receipt(decision_records=["0003"]))
    assert harness.run("--json") == links.EXIT_RECORD
    report = report_json(capsys)
    assert codes(report) == {"RECORD_NOT_ACCEPTED"}
    assert "Proposed" in report["failures"][0]["message"]


def test_record_file_status_must_be_accepted_even_when_index_says_accepted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = Harness(tmp_path)
    make_repo(harness.root, record_status={"0002": "Proposed"}, index_status={"0002": "Accepted"})
    harness.set_files(["src/safety.py"])
    harness.set_event(receipt(decision_records=["0002"]))
    assert harness.run("--json") == links.EXIT_RECORD
    assert codes(report_json(capsys)) == {"RECORD_NOT_ACCEPTED"}


def test_missing_record_file_on_base_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    (harness.root / "docs" / "adr" / "0002-test-record-2.md").unlink()
    harness.set_files(["src/safety.py"])
    harness.set_event(receipt(decision_records=["0002"]))
    assert harness.run("--json") == links.EXIT_RECORD
    assert codes(report_json(capsys)) == {"RECORD_MISSING"}


def test_reference_path_must_match_indexed_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety.py"])
    harness.set_event(receipt(decision_records=["docs/adr/0002-other-name.md"]))
    assert harness.run("--json") == links.EXIT_RECORD
    assert codes(report_json(capsys)) == {"RECORD_PATH_MISMATCH"}


def test_unindexed_record_file_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    index = harness.root / "docs" / "adr" / "README.md"
    write(index, "# Decision records\n")
    harness.set_files(["src/safety.py"])
    harness.set_event(receipt(decision_records=["0002"]))
    assert harness.run("--json") == links.EXIT_RECORD
    assert codes(report_json(capsys)) == {"RECORD_NOT_INDEXED"}


def test_non_safety_path_without_records_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/other.py", "docs/README.md", "tests/test_other.py"])
    assert harness.run("--json") == 0
    report = report_json(capsys)
    assert report["status"] == "PASS"
    assert report["safety_paths"] == []
    assert report["decision_records"] is None


def test_option_shaped_base_ref_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    assert harness.run("--json", "--base-ref=--help") == links.EXIT_BASE
    assert codes(report_json(capsys)) == {"BASE_UNAVAILABLE"}


def test_manifest_is_itself_a_safety_path(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["docs/adr/safety-invariants.json"])
    assert harness.run() == links.EXIT_DECISION_RECORDS


def test_renamed_safety_path_counts_as_changed(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.set_files([{"filename": "src/moved.py", "previous_filename": "src/safety.py", "status": "renamed"}])
    assert harness.run() == links.EXIT_DECISION_RECORDS


def test_deleted_safety_path_counts_as_changed(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.set_files([{"filename": "src/safety.py", "status": "removed"}])
    assert harness.run() == links.EXIT_DECISION_RECORDS


def test_multiple_bad_records_report_deterministically(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety.py", "src/safety/guard.py"])
    harness.set_event(receipt(decision_records=["0003", "0099"]))
    assert harness.run("--json") == links.EXIT_RECORD
    first = capsys.readouterr().out
    assert harness.run("--json") == links.EXIT_RECORD
    second = capsys.readouterr().out
    assert first == second
    assert [failure["code"] for failure in json.loads(first)["failures"]] == [
        "RECORD_NOT_INDEXED",
        "RECORD_NOT_ACCEPTED",
    ]


# ---------------------------------------------------------------------------
# Receipt requirement


def test_missing_receipt_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety.py"])
    harness.set_event(None, body="No receipt here.\n")
    assert harness.run("--json") == links.EXIT_RECEIPT
    report = report_json(capsys)
    assert codes(report) == {"RECEIPT_NOT_VALID"}
    assert "RECEIPT_MISSING" in report["failures"][0]["message"]


def test_empty_decision_records_list_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety.py"])
    harness.set_event(receipt(decision_records=[]))
    assert harness.run("--json") == links.EXIT_RECEIPT
    assert "FIELD_EMPTY" in report_json(capsys)["failures"][0]["message"]


def test_not_clear_verdict_fails_closed(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety.py"])
    harness.set_event(receipt(decision_records=["0002"], verdict="NOT CLEAR"))
    assert harness.run() == links.EXIT_RECEIPT


# ---------------------------------------------------------------------------
# Changed-file acquisition: fixture mode and API failure


def test_fixture_mode_never_contacts_the_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety.py"])
    harness.set_event(receipt(decision_records=["0002"]))

    def explode(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("fixture mode must not call the GitHub API")

    monkeypatch.setattr(links, "_request_page", explode)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert harness.run() == 0


def test_missing_changed_files_fixture_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    harness.files_path = tmp_path / "absent.json"
    assert harness.run("--json") == links.EXIT_CHANGED_FILES
    assert codes(report_json(capsys)) == {"CHANGED_FILES_FIXTURE_MISSING"}


def test_invalid_changed_files_fixture_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    harness.files_path.write_text("{not json", encoding="utf-8")
    assert harness.run("--json") == links.EXIT_CHANGED_FILES
    assert codes(report_json(capsys)) == {"CHANGED_FILES_FIXTURE_INVALID"}

    harness.files_path.write_text(json.dumps({"unexpected": []}), encoding="utf-8")
    assert harness.run("--json") == links.EXIT_CHANGED_FILES
    assert codes(report_json(capsys)) == {"CHANGED_FILES_FIXTURE_INVALID"}


def test_fixture_accepts_api_shaped_pages(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.set_files({"files": [{"filename": "src/safety.py", "status": "modified"}]})
    assert harness.run() == links.EXIT_DECISION_RECORDS


def api_run(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict[str, Any]]:
    """Run without --changed-files so the GitHub API path is exercised."""

    monkeypatch.setenv("GITHUB_TOKEN", "ghs_test_token")
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    status = links.main(["--event", str(harness.event_path), "--repo-root", str(harness.root), "--json"])
    return status, report_json(capsys)


def test_api_transport_failure_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path)
    monkeypatch.setattr(links, "_open", lambda request: (_ for _ in ()).throw(URLError(OSError("boom"))))
    status, report = api_run(harness, monkeypatch, capsys)
    assert status == links.EXIT_CHANGED_FILES
    assert codes(report) == {"CHANGED_FILES_API_UNAVAILABLE"}


def test_api_http_error_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = Harness(tmp_path)

    def forbidden(request: Any) -> None:
        raise HTTPError(request.full_url, 403, "Forbidden", None, None)  # type: ignore[arg-type]

    monkeypatch.setattr(links, "_open", forbidden)
    status, report = api_run(harness, monkeypatch, capsys)
    assert status == links.EXIT_CHANGED_FILES
    assert codes(report) == {"CHANGED_FILES_API_ERROR"}
    assert "403" in report["failures"][0]["message"]


def test_api_invalid_payload_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = Harness(tmp_path)
    monkeypatch.setattr(links, "_request_page", lambda url, token: b'{"message": "nope"}')
    status, report = api_run(harness, monkeypatch, capsys)
    assert status == links.EXIT_CHANGED_FILES
    assert codes(report) == {"CHANGED_FILES_API_INVALID"}

    monkeypatch.setattr(links, "_request_page", lambda url, token: b"[{\"no_filename\": 1}]")
    status, report = api_run(harness, monkeypatch, capsys)
    assert status == links.EXIT_CHANGED_FILES
    assert codes(report) == {"CHANGED_FILES_API_INVALID"}


def test_api_truncation_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = Harness(tmp_path)
    page = [{"filename": f"src/generated/file-{index}.py"} for index in range(links.PER_PAGE)]
    monkeypatch.setattr(links, "_request_page", lambda url, token: json.dumps(page).encode("utf-8"))
    status, report = api_run(harness, monkeypatch, capsys)
    assert status == links.EXIT_CHANGED_FILES
    assert codes(report) == {"CHANGED_FILES_API_TRUNCATED"}


def test_api_single_page_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = Harness(tmp_path)
    harness.set_event(receipt(decision_records=["0002"]))
    page = [{"filename": "src/other.py"}, {"filename": "src/safety.py"}]
    monkeypatch.setattr(links, "_request_page", lambda url, token: json.dumps(page).encode("utf-8"))
    status, report = api_run(harness, monkeypatch, capsys)
    assert status == 0
    assert report["changed_source"] == "github-api"
    assert report["changed_files"] == 2


def test_missing_token_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = Harness(tmp_path)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.setattr(
        links,
        "_request_page",
        lambda url, token: pytest.fail("missing token must not attempt a request"),
    )
    status = links.main(["--event", str(harness.event_path), "--repo-root", str(harness.root), "--json"])
    assert status == links.EXIT_CHANGED_FILES
    assert codes(report_json(capsys)) == {"CHANGED_FILES_TOKEN_MISSING"}


def test_missing_event_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    assert links.main(["--event", str(tmp_path / "absent.json")]) == links.EXIT_EVENT
    assert links.main([]) == links.EXIT_EVENT


def test_event_without_number_or_repository_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = Harness(tmp_path)
    payload = event(receipt(decision_records=["0002"]))
    del payload["number"]
    del payload["pull_request"]["number"]
    harness.event_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_test_token")
    assert links.main(["--event", str(harness.event_path), "--repo-root", str(harness.root), "--json"]) == links.EXIT_EVENT
    assert codes(report_json(capsys)) == {"EVENT_NUMBER_UNKNOWN"}


# ---------------------------------------------------------------------------
# Base-revision content


def test_missing_manifest_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    (harness.root / "docs" / "adr" / "safety-invariants.json").unlink()
    assert harness.run("--json") == links.EXIT_BASE
    assert codes(report_json(capsys)) == {"MANIFEST_MISSING"}


def test_invalid_manifest_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    write(harness.root / "docs" / "adr" / "safety-invariants.json", "{not json")
    assert harness.run("--json") == links.EXIT_BASE
    assert codes(report_json(capsys)) == {"MANIFEST_INVALID"}

    write(harness.root / "docs" / "adr" / "safety-invariants.json", json.dumps({"invariants": []}))
    assert harness.run("--json") == links.EXIT_BASE
    assert codes(report_json(capsys)) == {"MANIFEST_INVALID"}


def test_manifest_with_escaping_path_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    manifest = copy.deepcopy(MANIFEST)
    manifest["invariants"][0]["paths"] = ["../outside.py"]
    write(harness.root / "docs" / "adr" / "safety-invariants.json", json.dumps(manifest))
    assert harness.run("--json") == links.EXIT_BASE
    assert codes(report_json(capsys)) == {"MANIFEST_INVALID"}


def test_missing_index_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    (harness.root / "docs" / "adr" / "README.md").unlink()
    harness.set_files(["src/safety.py"])
    harness.set_event(receipt(decision_records=["0002"]))
    assert harness.run("--json") == links.EXIT_BASE
    assert codes(report_json(capsys)) == {"INDEX_MISSING"}


def git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", "-C", str(root), *arguments], check=True, capture_output=True)


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required for base-ref mode")
def test_base_ref_reads_committed_content_not_the_working_tree(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = Harness(tmp_path)
    git(harness.root, "init", "-q")
    git(harness.root, "add", "-A")
    git(harness.root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "base")
    record = harness.root / "docs" / "adr" / "0002-test-record-2.md"
    record.write_text(record.read_text(encoding="utf-8").replace("- **Status:** Accepted", "- **Status:** Proposed"))

    harness.set_files(["src/safety.py"])
    harness.set_event(receipt(decision_records=["0002"]))

    assert harness.run("--json", "--base-ref", "HEAD") == 0
    report = report_json(capsys)
    assert report["status"] == "PASS"

    assert harness.run("--json") == links.EXIT_RECORD
    assert codes(report_json(capsys)) == {"RECORD_NOT_ACCEPTED"}


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required for base-ref mode")
def test_missing_manifest_at_base_ref_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    harness = Harness(tmp_path)
    git(harness.root, "init", "-q")
    assert harness.run("--json", "--base-ref", "0000000000000000000000000000000000000000") == links.EXIT_BASE
    assert codes(report_json(capsys)) == {"MANIFEST_MISSING"}


# ---------------------------------------------------------------------------
# Contract stability, summaries, and hardening


def test_failure_codes_map_to_stable_exit_codes() -> None:
    assert set(links.CODE_EXITS) == {
        "EVENT_PATH_MISSING",
        "EVENT_PATH_UNREADABLE",
        "EVENT_TOO_LARGE",
        "EVENT_INVALID_JSON",
        "EVENT_INVALID_SHAPE",
        "EVENT_NUMBER_UNKNOWN",
        "EVENT_REPOSITORY_UNKNOWN",
        "CHANGED_FILES_FIXTURE_MISSING",
        "CHANGED_FILES_FIXTURE_INVALID",
        "CHANGED_FILES_TOKEN_MISSING",
        "CHANGED_FILES_API_UNAVAILABLE",
        "CHANGED_FILES_API_ERROR",
        "CHANGED_FILES_API_INVALID",
        "CHANGED_FILES_API_TRUNCATED",
        "BASE_UNAVAILABLE",
        "MANIFEST_MISSING",
        "MANIFEST_INVALID",
        "INDEX_MISSING",
        "RECEIPT_NOT_VALID",
        "DECISION_RECORDS_MISSING",
        "RECORD_REFERENCE_INVALID",
        "RECORD_NOT_INDEXED",
        "RECORD_NOT_ACCEPTED",
        "RECORD_FILE_UNRESOLVED",
        "RECORD_PATH_MISMATCH",
        "RECORD_MISSING",
        "RECORD_INVALID",
    }
    assert sorted(set(links.CODE_EXITS.values())) == [2, 3, 4, 5, 6, 7]


def test_summary_is_deterministic_and_never_contains_the_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path)
    harness.set_files(["src/safety.py"])
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_super_secret")
    summary = tmp_path / "summary.md"
    assert harness.run("--summary", str(summary)) == links.EXIT_DECISION_RECORDS
    first = summary.read_text(encoding="utf-8")
    assert harness.run("--summary", str(summary)) == links.EXIT_DECISION_RECORDS
    second = summary.read_text(encoding="utf-8")
    assert second == first + first
    assert "ghs_super_secret" not in first
    assert "Decision record links" in first
    assert "DECISION_RECORDS_MISSING" in first


def test_request_headers_carry_the_token_outside_the_url() -> None:
    request = links._build_request("https://api.github.com/repos/o/r/pulls/1/files", "ghs_test_token")
    assert request.full_url == "https://api.github.com/repos/o/r/pulls/1/files"
    headers = {key.lower(): value for key, value in request.header_items()}
    assert headers["authorization"] == "Bearer ghs_test_token"
    assert headers["accept"] == "application/vnd.github+json"
    assert all("ghs_test_token" not in value for key, value in headers.items() if key != "authorization")


def test_unexpected_internal_error_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = Harness(tmp_path)
    monkeypatch.setattr(links, "evaluate", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
    assert harness.run() == links.EXIT_INTERNAL
    assert "internal failure" in capsys.readouterr().err


def test_glob_semantics() -> None:
    assert links.pattern_matches("src/safety.py", "./src/safety.py")
    assert links.pattern_matches("src/safety/*.py", "src/safety/guard.py")
    assert not links.pattern_matches("src/safety/*.py", "src/safety/deep/guard.py")
    assert links.pattern_matches("src/globbed/**/*.py", "src/globbed/a.py")
    assert links.pattern_matches("src/globbed/**/*.py", "src/globbed/deep/a.py")
    assert not links.pattern_matches("src/globbed/**/*.py", "src/globbed/a.txt")
    assert links.pattern_matches(".github/workflows/decision-record-*.yml", ".github/workflows/decision-record-links.yml")
    assert links.pattern_matches("docs/", "docs/adr/README.md")
    assert not links.pattern_matches("src/safety.py", "src/safety.pyc")


def test_safety_matches_are_sorted_and_deduplicated() -> None:
    changed = [
        {"filename": "src/safety.py"},
        {"filename": "src/safety.py", "previous_filename": "src/safety/guard.py", "status": "renamed"},
    ]
    entries = links.parse_manifest(json.dumps(MANIFEST))
    matches = links.safety_matches(changed, entries)
    keys = [(match["path"], match["invariant"], match["pattern"]) for match in matches]
    assert keys == sorted(set(keys))
    assert ("src/safety.py", "control-plane", "src/safety.py") in keys
    assert ("src/safety/guard.py", "control-plane", "src/safety/*.py") in keys


def test_checker_uses_no_shell_and_no_eval() -> None:
    source = (ROOT / "scripts/check_decision_record_links.py").read_text(encoding="utf-8")
    for forbidden in ("shell=True", "os.system", "eval(", "exec(", "os.popen", "requests.", "http.client"):
        assert forbidden not in source
    assert 'subprocess.run(command, capture_output=True' in source
