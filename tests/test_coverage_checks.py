"""Refusal-branch coverage for authoritative check-run evidence ingestion.

Each test asserts the typed reason or the fail-closed outcome, plus that no
evidence entry is manufactured for a refused binding.
"""

from __future__ import annotations

import pytest

from pr_review_harness.checks import (
    CheckEvidenceError,
    GitHubCheckAdapter,
    ingest_check_runs,
    make_check_runs_document,
)

HEAD = "a" * 40
REQUEST = {"repository": "owner/repo", "pull_request_number": 7, "head_sha": HEAD}
BINDINGS = [{"id": "unit-tests", "github_check_name": "unit-tests", "github_app_id": 12}]


def run(**overrides):
    value = {
        "id": 88,
        "name": "unit-tests",
        "status": "completed",
        "conclusion": "success",
        "head_sha": HEAD,
        "app_id": 12,
        "completed_at": "2026-09-26T12:00:00Z",
    }
    value.update(overrides)
    return value


def document(runs=(), **overrides):
    value = {
        "schema_version": "2.0",
        "repository": "owner/repo",
        "pull_request_number": 7,
        "head_sha": HEAD,
        "captured_at": "2026-09-26T12:01:00Z",
        "complete": True,
        "runs": list(runs),
    }
    value.update(overrides)
    return value


def test_adapter_returns_unknown_and_diagnostic_without_ingested_evidence():
    task = {"check_binding_id": "unit-tests", "check_id": "unit-tests"}
    snapshot = {"external_check_results": {"unit-tests": {"outcome": "PASS"}}, "evidence": {}}
    result = GitHubCheckAdapter()(task, snapshot)
    assert result["outcome"] == "PASS"
    assert result["evidence_refs"] == []
    assert result["diagnostics"] == ["authoritative_check_run_evidence_unavailable"]


def test_adapter_normalizes_unknown_outcomes_and_returns_evidence_refs():
    task = {"check_binding_id": "unit-tests"}
    snapshot = {
        "external_check_results": {"unit-tests": {"outcome": "NOT_A_STATE", "evidence_id": "e-1"}},
        "evidence": {"e-1": {"evidence_id": "e-1"}},
    }
    result = GitHubCheckAdapter()(task, snapshot)
    assert result["outcome"] == "UNKNOWN"
    assert result["evidence_refs"] == ["e-1"]
    assert result["diagnostics"] == []
    assert result["check_id"] == "unit-tests"


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        (document(schema_version="3.0"), "unsupported check evidence schema"),
        (document(pull_request_number=None), "does not match review identity"),
        ({key: value for key, value in document().items() if key != "runs"}, "missing required identity"),
        ({**document(), "runs": "not a list"}, "collections are invalid"),
        (document(complete="yes"), "completeness flag is invalid"),
        (document(captured_at=None), "capture time is required"),
        (document(captured_at="2026-09-26T12:01:00"), "capture time is required"),
        (document(captured_at="not-a-time"), "capture time is required"),
    ],
)
def test_ingestion_refuses_invalid_envelopes(doc, message):
    with pytest.raises(CheckEvidenceError, match=message):
        ingest_check_runs(doc, REQUEST, BINDINGS)


def test_ingestion_refuses_invalid_binding_identity_before_producing_evidence():
    with pytest.raises(CheckEvidenceError, match="binding identity is invalid"):
        ingest_check_runs(document([run()]), REQUEST, [{"github_check_name": "unit-tests"}])
    with pytest.raises(CheckEvidenceError, match="binding identity is invalid"):
        ingest_check_runs(document([run()]), REQUEST, ["not a binding"])


def test_binding_without_check_name_or_app_is_unknown_without_evidence():
    result = ingest_check_runs(document([run()]), REQUEST, [{"id": "unit-tests"}])
    assert result["results"]["unit-tests"] == {"outcome": "UNKNOWN", "reason": "github_check_name_not_configured"}
    assert result["evidence"] == {}
    result = ingest_check_runs(document([run()]), REQUEST, [{"id": "unit-tests", "github_check_name": "unit-tests"}])
    assert result["results"]["unit-tests"]["reason"] == "app_identity_not_configured"
    assert result["evidence"] == {}


def test_incomplete_listing_never_becomes_pass_evidence():
    result = ingest_check_runs(document([run()], complete=False), REQUEST, BINDINGS)
    assert result["results"]["unit-tests"] == {
        "outcome": "UNKNOWN",
        "reason": "check_run_listing_incomplete",
    }
    assert result["evidence"] == {}


@pytest.mark.parametrize(
    "overrides",
    [
        {"id": True},
        {"id": 0},
        {"status": "mystery"},
        {"head_sha": "bad"},
        {"head_sha": "b" * 40},
        {"completed_at": None},
    ],
)
def test_run_identity_or_status_refusals_never_emit_pass_evidence(overrides):
    result = ingest_check_runs(document([run(**overrides)]), REQUEST, BINDINGS)
    assert result["results"]["unit-tests"]["outcome"] == "UNKNOWN"
    assert result["results"]["unit-tests"]["reason"] == "check_run_identity_or_status_invalid"
    assert result["evidence"] == {}


def test_nonrecord_run_entries_are_ignored_as_ambiguous():
    result = ingest_check_runs(document(["not a record"]), REQUEST, BINDINGS)
    assert result["results"]["unit-tests"]["reason"] == "check_run_missing_or_ambiguous"


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("bad repo", 7, HEAD), "repository identity is invalid"),
        (("owner/repo", True, HEAD), "pull request number is invalid"),
        (("owner/repo", 0, HEAD), "pull request number is invalid"),
        (("owner/repo", 7, "bad"), "head SHA is invalid"),
    ],
)
def test_document_factory_refuses_invalid_identity(args, message):
    with pytest.raises(CheckEvidenceError, match=message):
        make_check_runs_document(*args, [], captured_at="2026-09-26T12:01:00Z")


def test_document_factory_refuses_invalid_completeness_and_timestamp():
    with pytest.raises(CheckEvidenceError, match="completeness flag is invalid"):
        make_check_runs_document("owner/repo", 7, HEAD, [], complete="yes")
    with pytest.raises(CheckEvidenceError, match="capture timestamp is invalid"):
        make_check_runs_document("owner/repo", 7, HEAD, [], captured_at="2026-09-26T12:01:00")
