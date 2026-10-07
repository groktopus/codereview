"""Read-only GitHub pull request metadata adapter using the `gh` CLI."""

from __future__ import annotations

import json
import os
import re
import select
import subprocess
import time
from typing import Callable
from urllib.parse import urlsplit, urlunsplit


class GitHubReadError(ValueError):
    """GitHub metadata could not be read or did not match the request."""


_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-f]{40,64}$")


class GitHubPRAdapter:
    """Fetch read-only PR metadata and check runs without exposing credentials.

    Tests may inject a runner. Production uses `gh api` with argument arrays;
    authentication remains owned by `gh` and is never read or logged here.
    """

    def __init__(
        self,
        runner: Callable | None = None,
        timeout_seconds: int = 15,
        max_response_bytes: int = 8_000_000,
        deadline_at: float | None = None,
    ):
        self._runner = runner or subprocess.run
        self._timeout = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._deadline_at = deadline_at

    def _remaining_timeout(self) -> float:
        remaining = self._timeout
        if self._deadline_at is not None:
            remaining = min(remaining, self._deadline_at - time.monotonic())
        if remaining <= 0:
            raise GitHubReadError("GitHub operation deadline exceeded")
        return remaining

    def _api_output(self, endpoint: str, method: str = "GET", payload: dict | None = None) -> str:
        timeout = self._remaining_timeout()
        argv = ["gh", "api", endpoint]
        input_data = None
        if method != "GET":
            argv.extend(["--method", method, "--input", "-"])
            input_data = json.dumps(payload or {}, sort_keys=True, separators=(",", ":"))
        if self._runner is not subprocess.run:
            try:
                result = self._runner(
                    argv,
                    input=input_data,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise GitHubReadError("GitHub read request failed") from exc
            if result.returncode:
                raise GitHubReadError("GitHub read request failed")
            if len(result.stdout.encode("utf-8")) > self._max_response_bytes:
                raise GitHubReadError("GitHub response exceeded configured byte limit")
            return result.stdout
        process = None
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            assert process.stdout is not None
            if input_data is not None:
                assert process.stdin is not None
                process.stdin.write(input_data.encode("utf-8"))
                process.stdin.close()
            output = bytearray()
            deadline = time.monotonic() + timeout
            while len(output) <= self._max_response_bytes:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                    raise subprocess.TimeoutExpired(argv, self._timeout)
                block = os.read(process.stdout.fileno(), min(65536, self._max_response_bytes + 1 - len(output)))
                if not block:
                    break
                output.extend(block)
            if len(output) > self._max_response_bytes:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1)
                raise GitHubReadError("GitHub response exceeded configured byte limit")
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired) as exc:
            if process is not None:
                process.kill()
                process.wait(timeout=1)
            raise GitHubReadError("GitHub read request failed") from exc
        if process.returncode:
            raise GitHubReadError("GitHub read request failed")
        try:
            return output.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GitHubReadError("GitHub returned invalid JSON") from exc

    def _api_json(self, endpoint: str, method: str = "GET", payload: dict | None = None) -> dict:
        output = self._api_output(endpoint, method, payload)
        try:
            value = json.loads(output)
        except (TypeError, json.JSONDecodeError) as exc:
            raise GitHubReadError("GitHub returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise GitHubReadError("GitHub returned an invalid record")
        return value

    def authenticated_actor(self) -> str:
        """Return the authenticated gh account's bounded login identifier."""
        data = self._api_json("user")
        login = data.get("login")
        if not isinstance(login, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,39}(?:\[bot\])?", login):
            raise GitHubReadError("authenticated GitHub actor is invalid")
        return login

    def _api_array(self, endpoint: str) -> list:
        output = self._api_output(endpoint)
        try:
            value = json.loads(output)
        except (TypeError, json.JSONDecodeError) as exc:
            raise GitHubReadError("GitHub returned invalid JSON") from exc
        if not isinstance(value, list):
            raise GitHubReadError("GitHub returned an invalid list")
        return value

    def pull_request(self, repository: str, number: int) -> dict:
        if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
            raise GitHubReadError("repository identity is invalid")
        if isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise GitHubReadError("pull request number is invalid")
        data = self._api_json(f"repos/{repository}/pulls/{number}")
        base = data.get("base", {}).get("sha") if isinstance(data.get("base"), dict) else None
        head = data.get("head", {}).get("sha") if isinstance(data.get("head"), dict) else None
        if (
            not isinstance(base, str)
            or not _SHA.fullmatch(base)
            or not isinstance(head, str)
            or not _SHA.fullmatch(head)
        ):
            raise GitHubReadError("GitHub PR revisions are invalid")
        returned_repo = data.get("base", {}).get("repo", {})
        full_name = returned_repo.get("full_name") if isinstance(returned_repo, dict) else None
        if full_name != repository or data.get("number") != number:
            raise GitHubReadError("GitHub PR identity does not match request")
        source_url = returned_repo.get("html_url") if isinstance(returned_repo, dict) else None
        try:
            if not isinstance(source_url, str):
                raise ValueError
            source_parts = urlsplit(source_url)
            port = source_parts.port
            if (
                source_parts.scheme != "https"
                or not source_parts.hostname
                or source_parts.username
                or source_parts.password
                or source_parts.query
                or source_parts.fragment
                or source_parts.path.rstrip("/").lower() != "/" + repository.lower()
                or (port is not None and not 1 <= port <= 65535)
            ):
                raise ValueError
            repository_url = urlunsplit(("https", source_parts.netloc.lower(), source_parts.path.rstrip("/"), "", ""))
        except ValueError as exc:
            raise GitHubReadError("GitHub PR repository URL is invalid") from exc
        return {
            "repository": repository,
            "pull_request_number": number,
            "base_sha": base,
            "head_sha": head,
            "repository_url": repository_url,
            "event_id": f"github-pr:{repository}#{number}:{head}",
            "state": data.get("state"),
            "draft": data.get("draft"),
            "url": data.get("html_url"),
        }

    def compare_revisions(self, repository: str, base_sha: str, head_sha: str) -> dict:
        """Return bounded metadata from GitHub's BASE...HEAD comparison."""
        if (
            not isinstance(repository, str)
            or not _REPOSITORY.fullmatch(repository)
            or not isinstance(base_sha, str)
            or not _SHA.fullmatch(base_sha)
            or not isinstance(head_sha, str)
            or not _SHA.fullmatch(head_sha)
        ):
            raise GitHubReadError("comparison identity is invalid")
        data = self._api_json(f"repos/{repository}/compare/{base_sha}...{head_sha}?per_page=1")
        returned_base = data.get("base_commit", {}).get("sha") if isinstance(data.get("base_commit"), dict) else None
        merge_base = data.get("merge_base_commit", {}).get("sha") if isinstance(data.get("merge_base_commit"), dict) else None
        ahead_by, behind_by = data.get("ahead_by"), data.get("behind_by")
        if (
            not isinstance(merge_base, str)
            or not _SHA.fullmatch(merge_base)
            or returned_base != base_sha
            or isinstance(ahead_by, bool)
            or not isinstance(ahead_by, int)
            or ahead_by < 0
            or isinstance(behind_by, bool)
            or not isinstance(behind_by, int)
            or behind_by < 0
            or ahead_by > 9_999
            or behind_by > 9_999
            or ahead_by + behind_by > 19_998
        ):
            raise GitHubReadError("GitHub comparison metadata is invalid")
        return {"merge_base_sha": merge_base, "ahead_by": ahead_by, "behind_by": behind_by}

    def check_runs(self, repository: str, head_sha: str) -> dict:
        if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
            raise GitHubReadError("repository identity is invalid")
        if not isinstance(head_sha, str) or not _SHA.fullmatch(head_sha):
            raise GitHubReadError("head SHA is invalid")
        runs = []
        total_count = None
        complete = False
        for page in range(1, 11):
            data = self._api_json(f"repos/{repository}/commits/{head_sha}/check-runs?per_page=100&page={page}")
            if (
                isinstance(data.get("total_count"), bool)
                or not isinstance(data.get("total_count"), int)
                or not isinstance(data.get("check_runs"), list)
            ):
                raise GitHubReadError("GitHub check runs response is invalid")
            if total_count is None:
                total_count = data["total_count"]
            elif total_count != data["total_count"]:
                raise GitHubReadError("GitHub check run count changed during pagination")
            for item in data["check_runs"]:
                if not isinstance(item, dict):
                    continue
                app = item.get("app") if isinstance(item.get("app"), dict) else {}
                runs.append(
                    {
                        "id": item.get("id"),
                        "name": item.get("name"),
                        "status": item.get("status"),
                        "conclusion": item.get("conclusion"),
                        "head_sha": item.get("head_sha"),
                        "app_id": app.get("id"),
                        "completed_at": item.get("completed_at"),
                        "external_id": item.get("external_id"),
                        "details_url": item.get("details_url"),
                    }
                )
            if len(runs) >= total_count or len(data["check_runs"]) < 100:
                complete = len(runs) >= total_count
                break
        return {"head_sha": head_sha, "runs": runs, "total_count": total_count, "complete": complete}


class GitHubFreshnessCheck:
    """Picklable, bounded current-head check for controller isolation."""

    def __init__(self, repository: str, pull_request_number: int, expected_head_sha: str):
        self.repository = repository
        self.pull_request_number = pull_request_number
        self.expected_head_sha = expected_head_sha

    def __call__(self) -> dict:
        try:
            observed = (
                GitHubPRAdapter(timeout_seconds=5)
                .pull_request(self.repository, self.pull_request_number)
                .get("head_sha")
            )
        except Exception:
            return {
                "freshness": "UNKNOWN",
                "freshness_basis": "GITHUB_API",
                "expected_head_sha": self.expected_head_sha,
                "observed_head_sha": None,
            }
        if not isinstance(observed, str) or len(observed) != 40 or any(c not in "0123456789abcdef" for c in observed):
            observed = None
        return {
            "freshness": "CURRENT" if observed == self.expected_head_sha else ("STALE" if observed else "UNKNOWN"),
            "freshness_basis": "GITHUB_API",
            "expected_head_sha": self.expected_head_sha,
            "observed_head_sha": observed,
        }


class GitHubReviewPublisher:
    """Narrow GitHub PR-review API capability for the guarded publisher module."""

    def __init__(
        self, repository: str, number: int, head_sha: str, actor_login: str, adapter: GitHubPRAdapter | None = None
    ):
        if not _REPOSITORY.fullmatch(repository):
            raise GitHubReadError("repository identity is invalid")
        if isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise GitHubReadError("pull request number is invalid")
        if not _SHA.fullmatch(head_sha) or not isinstance(actor_login, str) or not actor_login:
            raise GitHubReadError("publisher identity is invalid")
        self.repository = repository
        self.number = number
        self.head_sha = head_sha
        self.actor_login = actor_login
        self.adapter = adapter or GitHubPRAdapter()

    def lookup_effect(self, key: str) -> str:
        marker = f"<!-- pr-review-harness:{key} -->"
        matching = []
        complete = False
        for page in range(1, 11):
            reviews = self.adapter._api_array(
                f"repos/{self.repository}/pulls/{self.number}/reviews?per_page=100&page={page}"
            )
            for review in reviews:
                if not isinstance(review, dict):
                    continue
                user = review.get("user") if isinstance(review.get("user"), dict) else {}
                if (
                    marker in str(review.get("body", ""))
                    and review.get("commit_id") == self.head_sha
                    and user.get("login") == self.actor_login
                ):
                    matching.append(review)
            if len(reviews) < 100:
                complete = True
                break
        if len(matching) == 1:
            return "confirmed"
        if len(matching) > 1:
            return "unknown"
        return "not_found" if complete else "unknown"

    def submit_review(self, payload: dict, key: str) -> dict:
        if payload.get("commit_id") != self.head_sha or payload.get("event") not in {
            "APPROVE",
            "REQUEST_CHANGES",
            "COMMENT",
        }:
            raise GitHubReadError("review request does not match authorized scope")
        body = payload.get("body", "")
        if not isinstance(body, str) or len(body.encode("utf-8")) > 60000:
            raise GitHubReadError("review body exceeds the API bound")
        body = f"{body}\n\n<!-- pr-review-harness:{key} -->"
        review = self.adapter._api_json(
            f"repos/{self.repository}/pulls/{self.number}/reviews",
            method="POST",
            payload={"commit_id": self.head_sha, "event": payload["event"], "body": body},
        )
        user = review.get("user") if isinstance(review.get("user"), dict) else {}
        if review.get("commit_id") != self.head_sha or user.get("login") != self.actor_login:
            raise GitHubReadError("GitHub review response identity did not match")
        return {"review_id": review.get("id"), "commit_id": self.head_sha, "actor_login": self.actor_login}
