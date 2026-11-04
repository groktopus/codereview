"""Error/refusal branch coverage for the read-only GitHub adapter.

These tests assert the typed refusal reason and that no request is attempted
where the adapter can reject the input or response before acting.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess

import pytest

from pr_review_harness.github import (
    GitHubFreshnessCheck,
    GitHubPRAdapter,
    GitHubReadError,
    GitHubReviewPublisher,
)

BASE = "a" * 40
HEAD = "b" * 40


class Runner:
    def __init__(self, responses=(), *, stdout=None, returncode=0, raises=None):
        self.responses = list(responses)
        self.stdout = stdout
        self.returncode = returncode
        self.raises = raises
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.raises is not None:
            raise self.raises
        value = self.responses.pop(0) if self.responses else self.stdout
        text = value if isinstance(value, str) else json.dumps(value)
        return subprocess.CompletedProcess(argv, self.returncode, text, "stderr")


def make_pr(repository="owner/repo", number=7, *, url="https://github.example/owner/repo", state="open"):
    return {
        "number": number,
        "state": state,
        "base": {"sha": BASE, "repo": {"full_name": repository, "html_url": url}},
        "head": {"sha": HEAD},
    }


def test_deadline_is_checked_before_any_runner_call():
    adapter = GitHubPRAdapter(Runner([make_pr()]), deadline_at=0.0)
    with pytest.raises(GitHubReadError, match="deadline exceeded"):
        adapter.pull_request("owner/repo", 7)


@pytest.mark.parametrize(
    "runner",
    [
        Runner(raises=OSError("boom")),
        Runner(raises=subprocess.TimeoutExpired(["gh"], 1)),
        Runner([make_pr()], returncode=1),
        Runner(stdout="x" * 200),
    ],
)
def test_injected_runner_failures_are_typed(runner):
    adapter = GitHubPRAdapter(runner, max_response_bytes=100)
    with pytest.raises(GitHubReadError, match="GitHub read request failed|byte limit"):
        adapter.pull_request("owner/repo", 7)


def _fake_gh(tmp_path, body: str, *, exit_code: int = 0, sleep: float = 0.0):
    script = tmp_path / "gh"
    script.write_text(
        f"#!/bin/sh\nsleep {sleep if sleep else 0.1}\nprintf '%s' '{body}'\nexit {exit_code}\n",
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return tmp_path


def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")


def test_real_subprocess_transport_reads_get_and_post(tmp_path, monkeypatch):
    _env(_fake_gh(tmp_path, json.dumps({"login": "review-bot"})), monkeypatch)
    adapter = GitHubPRAdapter(timeout_seconds=5)
    assert adapter.authenticated_actor() == "review-bot"
    _env(_fake_gh(tmp_path, json.dumps({"id": 1})), monkeypatch)
    assert adapter._api_json("user", method="POST", payload={"x": 1}) == {"id": 1}


def test_real_subprocess_transport_rejects_oversized_response(tmp_path, monkeypatch):
    _env(_fake_gh(tmp_path, "x" * 500), monkeypatch)
    with pytest.raises(GitHubReadError, match="byte limit"):
        GitHubPRAdapter(timeout_seconds=5, max_response_bytes=64)._api_output("user")


def test_real_subprocess_transport_kills_a_process_that_ignores_termination(tmp_path, monkeypatch):
    script = tmp_path / "gh"
    script.write_text("#!/bin/sh\ntrap '' TERM\nprintf 'xxxxxxxx'\nsleep 5\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    _env(tmp_path, monkeypatch)
    with pytest.raises(GitHubReadError, match="byte limit"):
        GitHubPRAdapter(timeout_seconds=5, max_response_bytes=2)._api_output("user")


def test_real_subprocess_transport_rejects_nonzero_exit(tmp_path, monkeypatch):
    _env(_fake_gh(tmp_path, "{}", exit_code=1), monkeypatch)
    with pytest.raises(GitHubReadError, match="GitHub read request failed"):
        GitHubPRAdapter(timeout_seconds=5)._api_output("user")


def test_real_subprocess_transport_rejects_invalid_utf8(tmp_path, monkeypatch):
    script = tmp_path / "gh"
    script.write_text("#!/bin/sh\nprintf '\\377'\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    _env(tmp_path, monkeypatch)
    with pytest.raises(GitHubReadError, match="invalid JSON"):
        GitHubPRAdapter(timeout_seconds=5)._api_output("user")


def test_real_subprocess_transport_times_out(tmp_path, monkeypatch):
    _env(_fake_gh(tmp_path, "{}", sleep=2), monkeypatch)
    with pytest.raises(GitHubReadError, match="GitHub read request failed"):
        GitHubPRAdapter(timeout_seconds=1)._api_output("user")


@pytest.mark.parametrize("output", ["not json", "[]", "null"])
def test_json_object_contract_rejects_non_object_payloads(output):
    adapter = GitHubPRAdapter(Runner(stdout=output))
    with pytest.raises(GitHubReadError, match="invalid JSON|invalid record"):
        adapter._api_json("user")


def test_authenticated_actor_rejects_invalid_login():
    with pytest.raises(GitHubReadError, match="actor is invalid"):
        GitHubPRAdapter(Runner([{"login": "bad login"}])).authenticated_actor()


@pytest.mark.parametrize("output", ["not json", "{}", "null"])
def test_json_array_contract_rejects_non_array_payloads(output):
    adapter = GitHubPRAdapter(Runner(stdout=output))
    with pytest.raises(GitHubReadError, match="invalid JSON|invalid list"):
        adapter._api_array("repos/owner/repo/pulls/7/reviews")


def test_pull_request_rejects_invalid_number_before_any_call():
    runner = Runner([])
    with pytest.raises(GitHubReadError, match="number is invalid"):
        GitHubPRAdapter(runner).pull_request("owner/repo", True)
    assert runner.calls == []


@pytest.mark.parametrize(
    "data",
    [
        {"number": 7, "base": {"sha": "bad", "repo": {"full_name": "owner/repo"}}, "head": {"sha": HEAD}},
        {"number": 7, "base": {"sha": BASE, "repo": {"full_name": "owner/repo"}}, "head": {}},
        {
            "number": 7,
            "base": {"sha": BASE, "repo": {"full_name": "owner/repo", "html_url": "http://[bad"}},
            "head": {"sha": HEAD},
        },
        {
            "number": 7,
            "base": {"sha": BASE, "repo": {"full_name": "owner/repo", "html_url": None}},
            "head": {"sha": HEAD},
        },
        {
            "number": 7,
            "base": {
                "sha": BASE,
                "repo": {"full_name": "owner/repo", "html_url": "https://user:pass@github.example/owner/repo"},
            },
            "head": {"sha": HEAD},
        },
    ],
)
def test_pull_request_rejects_invalid_revisions_and_repository_urls(data):
    with pytest.raises(GitHubReadError, match="revisions are invalid|repository URL is invalid"):
        GitHubPRAdapter(Runner([data])).pull_request("owner/repo", 7)


@pytest.mark.parametrize(
    ("repository", "base_sha", "head_sha"),
    [("bad repo", BASE, HEAD), ("owner/repo", "nope", HEAD), ("owner/repo", BASE, "nope")],
)
def test_comparison_rejects_invalid_identity_before_any_call(repository, base_sha, head_sha):
    runner = Runner([])
    with pytest.raises(GitHubReadError, match="comparison identity is invalid"):
        GitHubPRAdapter(runner).compare_revisions(repository, base_sha, head_sha)
    assert runner.calls == []


@pytest.mark.parametrize(
    ("method", "args", "message"),
    [
        ("check_runs", ("bad repo", HEAD), "repository identity is invalid"),
        ("check_runs", ("owner/repo", "nope"), "head SHA is invalid"),
    ],
)
def test_check_runs_rejects_invalid_identity(method, args, message):
    with pytest.raises(GitHubReadError, match=message):
        getattr(GitHubPRAdapter(Runner([])), method)(*args)


def test_check_runs_rejects_invalid_page_and_changed_total_count():
    with pytest.raises(GitHubReadError, match="response is invalid"):
        GitHubPRAdapter(Runner([{"total_count": True, "check_runs": []}])).check_runs("owner/repo", HEAD)
    pages = [
        {"total_count": 150, "check_runs": [{"id": index, "name": f"run-{index}"} for index in range(100)]},
        {"total_count": 151, "check_runs": [{"id": 101, "name": "run-101"}]},
    ]
    with pytest.raises(GitHubReadError, match="count changed"):
        GitHubPRAdapter(Runner(pages)).check_runs("owner/repo", HEAD)


def test_check_runs_skips_non_record_entries_and_reports_incomplete():
    page = {"total_count": 2, "check_runs": ["not a record", {"id": 1, "name": "run"}]}
    result = GitHubPRAdapter(Runner([page])).check_runs("owner/repo", HEAD)
    assert len(result["runs"]) == 1
    assert result["complete"] is False


@pytest.mark.parametrize(
    ("observed", "expected"),
    [(HEAD, "CURRENT"), ("c" * 40, "STALE"), ("not-a-sha", "UNKNOWN")],
)
def test_freshness_check_classifies_observed_head(monkeypatch, observed, expected):
    class Adapter:
        def __init__(self, *args, **kwargs):
            pass

        def pull_request(self, repository, number):
            return {"head_sha": observed}

    monkeypatch.setattr("pr_review_harness.github.GitHubPRAdapter", Adapter)
    value = GitHubFreshnessCheck("owner/repo", 7, HEAD)()
    assert value["freshness"] == expected


def test_freshness_check_returns_unknown_when_read_fails(monkeypatch):
    class Adapter:
        def __init__(self, *args, **kwargs):
            pass

        def pull_request(self, repository, number):
            raise GitHubReadError("boom")

    monkeypatch.setattr("pr_review_harness.github.GitHubPRAdapter", Adapter)
    value = GitHubFreshnessCheck("owner/repo", 7, HEAD)()
    assert value["freshness"] == "UNKNOWN"
    assert value["observed_head_sha"] is None


@pytest.mark.parametrize(
    ("repository", "number", "head_sha", "actor", "message"),
    [
        ("bad repo", 7, HEAD, "bot", "repository identity is invalid"),
        ("owner/repo", True, HEAD, "bot", "pull request number is invalid"),
        ("owner/repo", 7, "nope", "bot", "publisher identity is invalid"),
        ("owner/repo", 7, HEAD, "", "publisher identity is invalid"),
    ],
)
def test_review_publisher_rejects_invalid_identity(repository, number, head_sha, actor, message):
    with pytest.raises(GitHubReadError, match=message):
        GitHubReviewPublisher(repository, number, head_sha, actor, GitHubPRAdapter(Runner([])))


def test_lookup_effect_skips_non_records_and_classifies_multiplicity():
    key = "effect-key"
    marker = f"<!-- pr-review-harness:{key} -->"
    matching = {"body": marker, "commit_id": HEAD, "user": {"login": "bot"}}
    runner = Runner([[matching]])
    assert (
        GitHubReviewPublisher("owner/repo", 7, HEAD, "bot", GitHubPRAdapter(runner)).lookup_effect(key) == "confirmed"
    )
    runner = Runner([[matching, matching]])
    assert GitHubReviewPublisher("owner/repo", 7, HEAD, "bot", GitHubPRAdapter(runner)).lookup_effect(key) == "unknown"
    runner = Runner([[{"body": marker, "commit_id": HEAD, "user": {"login": "other"}}]])
    assert (
        GitHubReviewPublisher("owner/repo", 7, HEAD, "bot", GitHubPRAdapter(runner)).lookup_effect(key) == "not_found"
    )
    runner = Runner([["not a record"]])
    assert (
        GitHubReviewPublisher("owner/repo", 7, HEAD, "bot", GitHubPRAdapter(runner)).lookup_effect(key) == "not_found"
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"commit_id": "c" * 40, "event": "COMMENT", "body": "x"},
        {"commit_id": HEAD, "event": "MERGE", "body": "x"},
        {"commit_id": HEAD, "event": "COMMENT", "body": 5},
    ],
)
def test_submit_review_rejects_out_of_scope_or_unbounded_payloads(payload):
    runner = Runner([])
    publisher = GitHubReviewPublisher("owner/repo", 7, HEAD, "bot", GitHubPRAdapter(runner))
    with pytest.raises(GitHubReadError, match="authorized scope|API bound"):
        publisher.submit_review(payload, "key")
    assert runner.calls == []


def test_submit_review_rejects_response_identity_mismatch():
    response = {"id": 1, "commit_id": HEAD, "user": {"login": "other"}}
    publisher = GitHubReviewPublisher("owner/repo", 7, HEAD, "bot", GitHubPRAdapter(Runner([response])))
    with pytest.raises(GitHubReadError, match="identity did not match"):
        publisher.submit_review({"commit_id": HEAD, "event": "COMMENT", "body": "x"}, "key")
