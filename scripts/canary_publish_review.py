#!/usr/bin/env python3
"""Publish one canary review to magnus919/SlopSearX pull request 1097.

This is a deliberately narrow, one-shot adapter, not a general publisher. It
mints a GitHub App installation token with only ``actions:read`` and
``pull_requests:write``, verifies that the pull request is open at the exact
expected head, refuses to post unless ``--authorize-publish`` is present,
posts exactly one ``COMMENT`` review, then reads the review back and writes a
verification receipt.

There are no retries. Every failure is projected to a fixed code so credential
material, tokens, API bodies, and pull request content are never printed.

Exit codes
----------
0   review verified (``VERIFIED``) or an existing marker review matched
    (``ALREADY_PUBLISHED``, nothing posted)
2   refused by a local or server-side precondition; nothing was posted
3   unknown transport/verification failure; publication state is not verified

Environment
-----------
``PR_REVIEW_GITHUB_APP_PRIVATE_KEY_FILE``
    PEM path; defaults to ``~/.config/codereview-credentials/github-app.pem``.
``PR_REVIEW_GITHUB_APP_ID``
    App id; defaults to the canary App (5605904).
``PR_REVIEW_GITHUB_APP_INSTALLATION_ID``
    Installation id; defaults to the canary installation (178426239).

The private key is read only to sign an RS256 App JWT. The installation token
lives only in process memory and is never written, logged, or included in a
receipt.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

CANARY_REPO = "magnus919/SlopSearX"
CANARY_PR = 1097
CANARY_APP_ID = 5_605_904
CANARY_INSTALLATION_ID = 178_426_239
CANARY_REPOSITORY_ID = 1_263_452_316
CANARY_APP_SLUG = "codereview-canary"

MARKER = "<!-- codereview-canary:v1 -->"
API_ROOT = "https://api.github.com"
DEFAULT_KEY_PATH = "~/.config/codereview-credentials/github-app.pem"
ENV_KEY_PATH = "PR_REVIEW_GITHUB_APP_PRIVATE_KEY_FILE"
ENV_APP_ID = "PR_REVIEW_GITHUB_APP_ID"
ENV_INSTALLATION_ID = "PR_REVIEW_GITHUB_APP_INSTALLATION_ID"

MAX_BODY_BYTES = 65_536
MAX_BODY_CHARS = 65_536
MAX_PRIVATE_KEY_BYTES = 16_384
MAX_RESPONSE_BYTES = 1_048_576
MAX_TOKEN_BYTES = 16_384
REVIEWS_PER_PAGE = 100
MAX_REVIEW_PAGES = 10
REQUEST_TIMEOUT_SECONDS = 20.0

EXIT_VERIFIED = 0
EXIT_REFUSED = 2
EXIT_UNKNOWN = 3

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class CanaryError(Exception):
    """Base class for a sanitized canary failure."""

    exit_code = EXIT_UNKNOWN

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Refused(CanaryError):
    """A precondition failed; nothing was published."""

    exit_code = EXIT_REFUSED


class Unknown(CanaryError):
    """Transport or verification state is unknown; publication is unverified."""

    exit_code = EXIT_UNKNOWN


class TransportError(RuntimeError):
    """Raised by a transport when no HTTP response is available."""


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    body: bytes


class Transport(Protocol):
    def request(self, method: str, url: str, headers: Mapping[str, str], body: bytes) -> HTTPResponse: ...


class _NoRedirect(HTTPRedirectHandler):
    """Refuse redirects so a token-bearing request cannot be replayed elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class UrllibTransport:
    """Minimal HTTPS transport with no redirects and a bounded response."""

    def request(self, method: str, url: str, headers: Mapping[str, str], body: bytes) -> HTTPResponse:
        request = Request(url, data=body or None, headers=dict(headers), method=method)
        opener = build_opener(_NoRedirect())
        try:
            with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                status = response.status
                payload = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            status = error.code
            payload = error.read(MAX_RESPONSE_BYTES + 1)
        except (URLError, TimeoutError, OSError, ValueError):
            raise TransportError("github_transport_unavailable") from None
        if len(payload) > MAX_RESPONSE_BYTES:
            raise Unknown("github_response_too_large")
        return HTTPResponse(status=status, body=payload)


def _headers(*, token: str | None = None, app_jwt: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": f"codereview-canary-publish/1 ({CANARY_APP_SLUG})",
    }
    if app_jwt is not None:
        headers["Authorization"] = f"Bearer {app_jwt}"
    elif token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _parse_json(response: HTTPResponse, *, allowed: frozenset[int]) -> Any:
    if response.status not in allowed:
        raise Unknown("github_http_status")
    if not isinstance(response.body, bytes) or len(response.body) > MAX_RESPONSE_BYTES:
        raise Unknown("github_response_too_large")
    try:
        return json.loads(response.body, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise Unknown("github_response_invalid") from None


def _object(response: HTTPResponse, *, allowed: frozenset[int]) -> dict[str, Any]:
    value = _parse_json(response, allowed=allowed)
    if not isinstance(value, dict):
        raise Unknown("github_response_invalid")
    return value


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _int_env(environ: Mapping[str, str], name: str, default: int) -> int:
    raw = environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw, 10)
    except ValueError:
        raise Refused("app_identity_invalid") from None
    if not _positive_int(value):
        raise Refused("app_identity_invalid")
    return value


def _read_body_file(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError:
        raise Refused("body_file_unreadable") from None
    if len(raw) > MAX_BODY_BYTES:
        raise Refused("body_too_large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("body_file_not_utf8") from None
    if not text.strip():
        raise Refused("body_empty")
    if MARKER in text:
        raise Refused("body_contains_marker")
    composed = f"{text.rstrip()}\n\n{MARKER}\n"
    if len(composed) > MAX_BODY_CHARS:
        raise Refused("body_too_large")
    return composed


def _load_private_key(path: Path) -> str:
    try:
        info = path.stat()
    except OSError:
        raise Refused("private_key_unreadable") from None
    if not stat.S_ISREG(info.st_mode):
        raise Refused("private_key_unreadable")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise Refused("private_key_permissions")
    if info.st_size > MAX_PRIVATE_KEY_BYTES:
        raise Refused("private_key_too_large")
    try:
        pem = path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        raise Refused("private_key_unreadable") from None
    if "PRIVATE KEY" not in pem:
        raise Refused("private_key_invalid")
    return pem


def _sign_app_jwt(private_key_pem: str, app_id: int, now: datetime) -> str:
    try:
        import jwt
    except ImportError:
        raise Unknown("jwt_unavailable") from None
    issued_at = int(now.timestamp()) - 60
    payload = {"iat": issued_at, "exp": issued_at + 600, "iss": str(app_id)}
    try:
        token = jwt.encode(payload, private_key_pem, algorithm="RS256")
    except Exception:
        raise Unknown("jwt_signing_failed") from None
    if not isinstance(token, str) or not token or len(token) > 32_768:
        raise Unknown("jwt_signing_failed")
    return token


def _mint_installation_token(transport: Transport, app_jwt: str, installation_id: int) -> str:
    url = f"{API_ROOT}/app/installations/{installation_id}/access_tokens"
    body = json.dumps(
        {
            "repository_ids": [CANARY_REPOSITORY_ID],
            "permissions": {"actions": "read", "pull_requests": "write"},
        }
    ).encode("utf-8")
    try:
        response = transport.request("POST", url, _headers(app_jwt=app_jwt), body)
    except TransportError:
        raise Unknown("token_mint_transport_failed") from None
    value = _object(response, allowed=frozenset({200, 201}))
    token = value.get("token")
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_BYTES:
        raise Unknown("token_response_invalid")
    permissions = value.get("permissions")
    if (
        not isinstance(permissions, dict)
        or permissions.get("actions") != "read"
        or permissions.get("pull_requests") != "write"
    ):
        raise Unknown("token_permissions_insufficient")
    return token


def _get_pull_request(transport: Transport, token: str, repo: str, pr: int) -> dict[str, Any]:
    url = f"{API_ROOT}/repos/{repo}/pulls/{pr}"
    try:
        response = transport.request("GET", url, _headers(token=token), b"")
    except TransportError:
        raise Unknown("pull_request_transport_failed") from None
    return _object(response, allowed=frozenset({200}))


def _fetch_reviews(transport: Transport, token: str, repo: str, pr: int) -> list[dict[str, Any]]:
    reviews: list[dict[str, Any]] = []
    for page in range(1, MAX_REVIEW_PAGES + 1):
        query = urlencode({"per_page": REVIEWS_PER_PAGE, "page": page})
        url = f"{API_ROOT}/repos/{repo}/pulls/{pr}/reviews?{query}"
        try:
            response = transport.request("GET", url, _headers(token=token), b"")
        except TransportError:
            raise Unknown("reviews_transport_failed") from None
        value = _parse_json(response, allowed=frozenset({200}))
        if not isinstance(value, list) or len(value) > REVIEWS_PER_PAGE:
            raise Unknown("reviews_response_invalid")
        for review in value:
            if not isinstance(review, dict):
                raise Unknown("reviews_response_invalid")
            reviews.append(review)
        if len(value) < REVIEWS_PER_PAGE:
            return reviews
    raise Unknown("reviews_pagination_exhausted")


def _marker_reviews(reviews: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [review for review in reviews if isinstance(review.get("body"), str) and MARKER in review["body"]]


def _post_review(transport: Transport, token: str, repo: str, pr: int, head: str, body: str) -> dict[str, Any]:
    url = f"{API_ROOT}/repos/{repo}/pulls/{pr}/reviews"
    payload = json.dumps({"body": body, "commit_id": head, "event": "COMMENT"}).encode("utf-8")
    try:
        response = transport.request("POST", url, _headers(token=token), payload)
    except TransportError:
        raise Unknown("review_post_transport_failed") from None
    value = _object(response, allowed=frozenset({200, 201}))
    if not _positive_int(value.get("id")):
        raise Unknown("review_post_response_invalid")
    if value.get("commit_id") != head:
        raise Unknown("review_post_response_invalid")
    if not isinstance(value.get("html_url"), str) or not value["html_url"]:
        raise Unknown("review_post_response_invalid")
    return value


def _parse_submitted_at(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise Unknown("review_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Unknown("review_timestamp_invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise Unknown("review_timestamp_invalid")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _verify_readback(reviews: list[dict[str, Any]], *, review_id: int, head: str) -> tuple[str, str]:
    matches = [review for review in reviews if review.get("id") == review_id]
    if len(matches) != 1:
        raise Unknown("review_readback_missing")
    review = matches[0]
    body = review.get("body")
    if (
        review.get("commit_id") != head
        or review.get("state") != "COMMENTED"
        or not isinstance(body, str)
        or MARKER not in body
    ):
        raise Unknown("review_verification_failed")
    html_url = review.get("html_url")
    if not isinstance(html_url, str) or not html_url:
        raise Unknown("review_verification_failed")
    return html_url, _parse_submitted_at(review.get("submitted_at"))


def _write_receipt(path: Path, receipt: Mapping[str, object]) -> None:
    data = json.dumps(dict(receipt), indent=2, sort_keys=True) + "\n"
    directory = path.parent if str(path.parent) else Path(".")
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        raise Unknown("receipt_write_failed") from None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Publish the pinned canary review after explicit authorization.")
    parser.add_argument("--repo", required=True, help="owner/name; only magnus919/SlopSearX is accepted")
    parser.add_argument("--pr", required=True, type=int, help="pull request number; only 1097 is accepted")
    parser.add_argument("--expected-head", required=True, help="exact 40-character pull request head SHA")
    parser.add_argument("--body-file", required=True, type=Path, help="UTF-8 review body without the marker")
    parser.add_argument("--receipt-out", required=True, type=Path, help="verification receipt path")
    parser.add_argument(
        "--authorize-publish",
        action="store_true",
        help="required explicit authorization to create one review",
    )
    return parser


def run(
    argv: list[str],
    *,
    transport: Transport | None = None,
    environ: Mapping[str, str] | None = None,
    now: datetime | None = None,
    signer: Callable[[str, int, datetime], str] | None = None,
) -> int:
    """Run the adapter once. Returns the documented exit code."""
    try:
        return _run(argv, transport=transport, environ=environ, now=now, signer=signer)
    except CanaryError as error:
        print(f"canary_publish_review error={error.code}", file=sys.stderr)
        return error.exit_code


def _run(
    argv: list[str],
    *,
    transport: Transport | None,
    environ: Mapping[str, str] | None,
    now: datetime | None,
    signer: Callable[[str, int, datetime], str] | None,
) -> int:
    args = _build_parser().parse_args(argv)
    env = os.environ if environ is None else environ
    current = now if now is not None else datetime.now(timezone.utc)

    if not args.authorize_publish:
        raise Refused("publish_not_authorized")
    if args.repo != CANARY_REPO:
        raise Refused("repository_not_allowed")
    if args.pr != CANARY_PR:
        raise Refused("pull_request_not_allowed")
    if not isinstance(args.expected_head, str) or not _SHA.fullmatch(args.expected_head):
        raise Refused("expected_head_invalid")
    if not _REPO.fullmatch(args.repo):
        raise Refused("repository_not_allowed")

    app_id = _int_env(env, ENV_APP_ID, CANARY_APP_ID)
    installation_id = _int_env(env, ENV_INSTALLATION_ID, CANARY_INSTALLATION_ID)
    review_body = _read_body_file(args.body_file)
    key_path = Path(env.get(ENV_KEY_PATH, DEFAULT_KEY_PATH)).expanduser()
    private_key_pem = _load_private_key(key_path)
    if signer is not None:
        app_jwt = signer(private_key_pem, app_id, current)
    else:
        app_jwt = _sign_app_jwt(private_key_pem, app_id, current)
    http = transport if transport is not None else UrllibTransport()

    token = _mint_installation_token(http, app_jwt, installation_id)
    pull_request = _get_pull_request(http, token, args.repo, args.pr)
    if pull_request.get("number") != args.pr:
        raise Refused("pull_request_identity_mismatch")
    if pull_request.get("state") != "open":
        raise Refused("pull_request_not_open")
    head = pull_request.get("head")
    if not isinstance(head, dict) or head.get("sha") != args.expected_head:
        raise Refused("pull_request_head_mismatch")

    existing = _marker_reviews(_fetch_reviews(http, token, args.repo, args.pr))
    if len(existing) > 1:
        raise Unknown("duplicate_marker_ambiguous")
    if existing:
        review = existing[0]
        if review.get("commit_id") != args.expected_head:
            raise Refused("existing_review_head_mismatch")
        review_id = review.get("id")
        if not _positive_int(review_id):
            raise Unknown("duplicate_marker_invalid")
        print(f"canary_publish_review status=ALREADY_PUBLISHED review_id={review_id}")
        return EXIT_VERIFIED

    created = _post_review(http, token, args.repo, args.pr, args.expected_head, review_body)
    review_id = created["id"]

    reviewed = _fetch_reviews(http, token, args.repo, args.pr)
    html_url, published_at = _verify_readback(reviewed, review_id=review_id, head=args.expected_head)
    receipt = {
        "repo": args.repo,
        "pr": args.pr,
        "head": args.expected_head,
        "review_id": review_id,
        "html_url": html_url,
        "published_at": published_at,
        "status": "VERIFIED",
    }
    _write_receipt(args.receipt_out, receipt)
    print(f"canary_publish_review status=VERIFIED review_id={review_id} receipt={args.receipt_out}")
    return EXIT_VERIFIED


def main(argv: list[str] | None = None) -> int:
    try:
        return run(sys.argv[1:] if argv is None else argv)
    except Exception:
        print("canary_publish_review error=internal_error", file=sys.stderr)
        return EXIT_UNKNOWN


if __name__ == "__main__":
    raise SystemExit(main())
