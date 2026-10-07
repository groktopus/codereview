import json
import pickle
import subprocess

import pytest

from pr_review_harness.github import GitHubFreshnessCheck, GitHubPRAdapter, GitHubReadError, GitHubReviewPublisher

BASE = "a" * 40
HEAD = "b" * 40


def test_freshness_adapter_is_picklable_and_binds_expected_identity():
    check = pickle.loads(pickle.dumps(GitHubFreshnessCheck("owner/repo", 7, HEAD)))
    assert check.repository == "owner/repo"
    assert check.pull_request_number == 7
    assert check.expected_head_sha == HEAD


class Runner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        response = self.responses.pop(0)
        return subprocess.CompletedProcess(argv, 0, json.dumps(response), "")


def test_github_pr_metadata_is_bound_to_requested_repository_and_number():
    runner = Runner(
        [
            {
                "number": 7,
                "state": "open",
                "draft": False,
                "html_url": "https://github.example/owner/repo/pull/7",
                "base": {
                    "sha": BASE,
                    "repo": {"full_name": "owner/repo", "html_url": "https://github.example/owner/repo"},
                },
                "head": {"sha": HEAD},
            }
        ]
    )
    result = GitHubPRAdapter(runner).pull_request("owner/repo", 7)
    assert result["base_sha"] == BASE and result["head_sha"] == HEAD
    assert result["repository_url"] == "https://github.example/owner/repo"
    assert result["event_id"] == f"github-pr:owner/repo#7:{HEAD}"
    assert runner.calls[0][0] == ["gh", "api", "repos/owner/repo/pulls/7"]


def test_github_comparison_returns_only_bound_merge_base_metadata():
    runner = Runner([{"base_commit": {"sha": "a" * 40}, "merge_base_commit": {"sha": BASE}, "ahead_by": 3, "behind_by": 2}])
    result = GitHubPRAdapter(runner).compare_revisions("owner/repo", "a" * 40, "b" * 40)
    assert result == {"merge_base_sha": BASE, "ahead_by": 3, "behind_by": 2}
    assert runner.calls[0][0] == ["gh", "api", f"repos/owner/repo/compare/{'a' * 40}...{'b' * 40}?per_page=1"]


@pytest.mark.parametrize(
    "response",
    [
        {"base_commit": {"sha": "a" * 40}, "merge_base_commit": {"sha": "not-a-sha"}, "ahead_by": 1, "behind_by": 1},
        {"base_commit": {"sha": "a" * 40}, "merge_base_commit": {"sha": BASE}, "ahead_by": True, "behind_by": 1},
        {"base_commit": {"sha": "a" * 40}, "merge_base_commit": {"sha": BASE}, "ahead_by": 10_000, "behind_by": 0},
        {"base_commit": {"sha": "c" * 40}, "merge_base_commit": {"sha": BASE}, "ahead_by": 1, "behind_by": 1},
    ],
)
def test_github_comparison_rejects_invalid_or_unbounded_metadata(response):
    with pytest.raises(GitHubReadError):
        GitHubPRAdapter(Runner([response])).compare_revisions("owner/repo", BASE, HEAD)


def test_github_adapter_rejects_injection_and_identity_mismatch():
    adapter = GitHubPRAdapter(Runner([]))
    with pytest.raises(GitHubReadError):
        adapter.pull_request("owner/repo;delete", 7)
    runner = Runner(
        [
            {
                "number": 8,
                "base": {
                    "sha": BASE,
                    "repo": {"full_name": "owner/repo", "html_url": "https://github.example/owner/repo"},
                },
                "head": {"sha": HEAD},
            }
        ]
    )
    with pytest.raises(GitHubReadError):
        GitHubPRAdapter(runner).pull_request("owner/repo", 7)


def test_check_runs_adapter_projects_only_bounded_provenance_fields():
    runner = Runner(
        [
            {
                "total_count": 1,
                "check_runs": [
                    {
                        "id": 4,
                        "name": "unit",
                        "status": "completed",
                        "conclusion": "success",
                        "head_sha": HEAD,
                        "app": {"id": 12, "name": "CI"},
                        "completed_at": "2026-09-26T10:00:00Z",
                        "output": {"text": "secret-like arbitrary output excluded"},
                    }
                ],
            }
        ]
    )
    value = GitHubPRAdapter(runner).check_runs("owner/repo", HEAD)
    assert value["runs"][0]["app_id"] == 12
    assert "output" not in value["runs"][0]
    assert "check-runs" in runner.calls[0][0][2]


def test_review_api_adapter_binds_lookup_and_submission_to_actor_and_sha():
    key = "effect-" + "c" * 64
    runner = Runner(
        [
            [
                {
                    "body": f"review text\n<!-- pr-review-harness:{key} -->",
                    "commit_id": HEAD,
                    "user": {"login": "review-bot"},
                }
            ],
            {"id": 123, "commit_id": HEAD, "user": {"login": "review-bot"}},
        ]
    )
    publisher = GitHubReviewPublisher("owner/repo", 7, HEAD, "review-bot", GitHubPRAdapter(runner))
    assert publisher.lookup_effect(key) == "confirmed"
    response = publisher.submit_review({"commit_id": HEAD, "event": "COMMENT", "body": "advisory"}, key)
    assert response["review_id"] == 123
    argv, kwargs = runner.calls[1]
    assert argv == ["gh", "api", "repos/owner/repo/pulls/7/reviews", "--method", "POST", "--input", "-"]
    assert key in kwargs["input"]
    assert "token" not in kwargs["input"].lower()
