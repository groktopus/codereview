"""Focused tests for the one-shot canary review publisher.

Every test uses an in-memory transport. No test reads a real credential,
contacts GitHub, or publishes anything.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import canary_publish_review as canary  # noqa: E402

HEAD = "a" * 40
OTHER_HEAD = "b" * 40
TOKEN = "ghs_canary_installation_token_secret_value"
RECEIPT_URL = "https://github.com/magnus919/SlopSearX/pull/1097#pullrequestreview-9001"
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
REPO = "magnus919/SlopSearX"
PR = 1097


@dataclass
class Call:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes


def _response(status: int, payload: object) -> canary.HTTPResponse:
    return canary.HTTPResponse(status=status, body=json.dumps(payload).encode("utf-8"))


def _pull_request(*, state: str = "open", head: str = HEAD) -> dict[str, object]:
    return {
        "number": PR,
        "state": state,
        "head": {"sha": head},
        "base": {"repo": {"full_name": REPO}},
    }


def _review(
    review_id: int,
    *,
    head: str = HEAD,
    state: str = "COMMENTED",
    submitted_at: str = "2026-11-04T12:01:00Z",
) -> dict[str, object]:
    return {
        "id": review_id,
        "commit_id": head,
        "state": state,
        "html_url": RECEIPT_URL if review_id == 9001 else f"https://github.com/reviews/{review_id}",
        "body": f"Canary review body.\n\n{canary.MARKER}\n",
        "submitted_at": submitted_at,
    }


class FakeGitHub:
    """Route-only fake; asserts on unexpected calls instead of hitting the network."""

    def __init__(
        self,
        *,
        pull_request: dict[str, object] | None = None,
        reviews_before: dict[int, list[dict[str, object]]] | None = None,
        post_response: dict[str, object] | None = None,
        reviews_after: dict[int, list[dict[str, object]]] | None = None,
    ) -> None:
        self.pull_request = pull_request if pull_request is not None else _pull_request()
        self.reviews_before = reviews_before if reviews_before is not None else {1: []}
        self.post_response = post_response
        self.reviews_after = reviews_after if reviews_after is not None else {1: []}
        self.calls: list[Call] = []
        self.posted = False

    def request(self, method: str, url: str, headers: dict[str, str], body: bytes) -> canary.HTTPResponse:
        self.calls.append(Call(method, url, dict(headers), body))
        parsed = urlparse(url)
        path = parsed.path
        if method == "POST" and path.endswith(f"/app/installations/{canary.CANARY_INSTALLATION_ID}/access_tokens"):
            return _response(
                201,
                {
                    "token": TOKEN,
                    "permissions": {"actions": "read", "metadata": "read", "pull_requests": "write"},
                },
            )
        if method == "GET" and path.endswith(f"/repos/{REPO}/pulls/{PR}"):
            return _response(200, self.pull_request)
        if method == "GET" and path.endswith(f"/repos/{REPO}/pulls/{PR}/reviews"):
            page = int(parse_qs(parsed.query)["page"][0])
            pages = self.reviews_after if self.posted else self.reviews_before
            return _response(200, pages.get(page, []))
        if method == "POST" and path.endswith(f"/repos/{REPO}/pulls/{PR}/reviews"):
            if self.post_response is None:
                raise AssertionError("unexpected review POST")
            self.posted = True
            return _response(200, self.post_response)
        raise AssertionError(f"unexpected call: {method} {url}")


@pytest.fixture(scope="session")
def private_key_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path_factory.mktemp("credential") / "github-app.pem"
    path.write_bytes(pem)
    os.chmod(path, 0o600)
    return path


@pytest.fixture
def environ(private_key_path: Path) -> dict[str, str]:
    return {canary.ENV_KEY_PATH: str(private_key_path)}


def _args(tmp_path: Path, *extra: str, authorize: bool = True) -> list[str]:
    body = tmp_path / "body.md"
    body.write_text("Canary review body.\n", encoding="utf-8")
    values = [
        "--repo",
        REPO,
        "--pr",
        str(PR),
        "--expected-head",
        HEAD,
        "--body-file",
        str(body),
        "--receipt-out",
        str(tmp_path / "receipt.json"),
    ]
    if authorize:
        values.append("--authorize-publish")
    values.extend(extra)
    return values


def _review_posts(fake: FakeGitHub) -> list[Call]:
    return [
        call for call in fake.calls if call.method == "POST" and call.url.endswith(f"/repos/{REPO}/pulls/{PR}/reviews")
    ]


def test_success_posts_one_review_and_writes_verified_receipt(
    tmp_path: Path, environ: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    created = _review(9001)
    fake = FakeGitHub(
        reviews_before={1: []},
        post_response=created,
        reviews_after={1: [created]},
    )

    code = canary.run(_args(tmp_path), transport=fake, environ=environ, now=NOW)

    assert code == canary.EXIT_VERIFIED
    receipt = json.loads((tmp_path / "receipt.json").read_text(encoding="utf-8"))
    assert receipt == {
        "repo": REPO,
        "pr": PR,
        "head": HEAD,
        "review_id": 9001,
        "html_url": RECEIPT_URL,
        "published_at": "2026-11-04T12:01:00Z",
        "status": "VERIFIED",
    }

    posts = _review_posts(fake)
    assert len(posts) == 1
    payload = json.loads(posts[0].body)
    assert payload["event"] == "COMMENT"
    assert payload["commit_id"] == HEAD
    assert canary.MARKER in payload["body"]
    assert payload["body"].count(canary.MARKER) == 1

    mint_calls = [call for call in fake.calls if call.url.endswith("/access_tokens")]
    assert len(mint_calls) == 1
    assert json.loads(mint_calls[0].body) == {
        "repository_ids": [canary.CANARY_REPOSITORY_ID],
        "permissions": {"actions": "read", "pull_requests": "write"},
    }

    token_headers = [call.headers["Authorization"] for call in fake.calls if not call.url.endswith("/access_tokens")]
    assert token_headers and all(value == f"Bearer {TOKEN}" for value in token_headers)

    captured = capsys.readouterr()
    assert "status=VERIFIED" in captured.out
    assert TOKEN not in captured.out + captured.err


def test_duplicate_marker_returns_already_published_without_posting(
    tmp_path: Path, environ: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeGitHub(reviews_before={1: [_review(9001)]}, post_response=None)

    code = canary.run(_args(tmp_path), transport=fake, environ=environ, now=NOW)

    assert code == canary.EXIT_VERIFIED
    assert _review_posts(fake) == []
    assert not (tmp_path / "receipt.json").exists()
    captured = capsys.readouterr()
    assert "status=ALREADY_PUBLISHED" in captured.out
    assert "review_id=9001" in captured.out


def test_duplicate_marker_at_other_head_is_refused(
    tmp_path: Path, environ: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeGitHub(reviews_before={1: [_review(9001, head=OTHER_HEAD)]}, post_response=None)

    code = canary.run(_args(tmp_path), transport=fake, environ=environ, now=NOW)

    assert code == canary.EXIT_REFUSED
    assert _review_posts(fake) == []
    assert not (tmp_path / "receipt.json").exists()
    assert "error=existing_review_head_mismatch" in capsys.readouterr().err


def test_head_mismatch_is_refused_before_posting(
    tmp_path: Path, environ: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeGitHub(pull_request=_pull_request(head=OTHER_HEAD), post_response=_review(9001))

    code = canary.run(_args(tmp_path), transport=fake, environ=environ, now=NOW)

    assert code == canary.EXIT_REFUSED
    assert _review_posts(fake) == []
    assert not (tmp_path / "receipt.json").exists()
    assert "error=pull_request_head_mismatch" in capsys.readouterr().err


def test_closed_pull_request_is_refused_before_posting(
    tmp_path: Path, environ: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeGitHub(pull_request=_pull_request(state="closed"), post_response=_review(9001))

    code = canary.run(_args(tmp_path), transport=fake, environ=environ, now=NOW)

    assert code == canary.EXIT_REFUSED
    assert _review_posts(fake) == []
    assert not (tmp_path / "receipt.json").exists()
    assert "error=pull_request_not_open" in capsys.readouterr().err


def test_missing_authorize_publish_flag_refuses_without_io(
    tmp_path: Path, environ: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeGitHub()

    code = canary.run(_args(tmp_path, authorize=False), transport=fake, environ=environ, now=NOW)

    assert code == canary.EXIT_REFUSED
    assert fake.calls == []
    assert not (tmp_path / "receipt.json").exists()
    assert "error=publish_not_authorized" in capsys.readouterr().err


def test_verification_mismatch_exits_unknown_without_receipt(
    tmp_path: Path, environ: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    created = _review(9001)
    readback = _review(9001, state="PENDING")
    fake = FakeGitHub(
        reviews_before={1: []},
        post_response=created,
        reviews_after={1: [readback]},
    )

    code = canary.run(_args(tmp_path), transport=fake, environ=environ, now=NOW)

    assert code == canary.EXIT_UNKNOWN
    assert len(_review_posts(fake)) == 1
    assert not (tmp_path / "receipt.json").exists()
    assert "error=review_verification_failed" in capsys.readouterr().err


def test_bounded_pagination_finds_marker_on_second_page(
    tmp_path: Path, environ: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    first_page = [
        {
            "id": 1000 + index,
            "commit_id": HEAD,
            "state": "COMMENTED",
            "body": "unrelated review",
            "html_url": f"https://github.com/reviews/{1000 + index}",
            "submitted_at": "2026-11-04T12:00:00Z",
        }
        for index in range(canary.REVIEWS_PER_PAGE)
    ]
    fake = FakeGitHub(reviews_before={1: first_page, 2: [_review(9001)]}, post_response=None)

    code = canary.run(_args(tmp_path), transport=fake, environ=environ, now=NOW)

    assert code == canary.EXIT_VERIFIED
    assert _review_posts(fake) == []
    review_gets = [call.url for call in fake.calls if "/reviews?" in call.url]
    assert any("page=2" in url for url in review_gets)
    assert "status=ALREADY_PUBLISHED" in capsys.readouterr().out
