"""In-memory boundary tests for the Actions GitHub HTTP transport."""

from __future__ import annotations

import io
import urllib.error
import urllib.request

import pytest

import pr_review_harness.actions_publication as actions_publication
from pr_review_harness.actions_publication import GitHubPublicationError, UrllibGitHubTransport


class FakeResponse:
    def __init__(self, body: bytes, *, status: int = 200, headers: dict | None = None):
        self.status = status
        self.headers = headers or {"Content-Type": "application/json"}
        self._body = body
        self.read_sizes: list[int] = []
        self.closed = False

    def read1(self, size: int) -> bytes:
        self.read_sizes.append(size)
        chunk, self._body = self._body[:size], self._body[size:]
        return chunk

    def read(self, size: int = -1) -> bytes:
        return self.read1(len(self._body) if size < 0 else size)

    def close(self) -> None:
        self.closed = True


class FakeOpener:
    def __init__(self, response=None, *, error=None):
        self.response = response
        self.error = error
        self.calls: list[tuple[object, float]] = []

    def open(self, request, timeout: float):
        self.calls.append((request, timeout))
        if self.error is not None:
            raise self.error
        return self.response


def _transport_with(opener: FakeOpener) -> UrllibGitHubTransport:
    transport = UrllibGitHubTransport()
    transport._opener = opener
    return transport


def test_open_enforces_absolute_deadline_across_slow_drip_reads(monkeypatch):
    now = [100.0]

    class SlowDrip(FakeResponse):
        def read1(self, size: int) -> bytes:
            now[0] += 0.06
            return super().read1(size) or b"x"

    response = SlowDrip(b"abcdef")
    opener = FakeOpener(response)
    monkeypatch.setattr(actions_publication.time, "monotonic", lambda: now[0])

    with pytest.raises(GitHubPublicationError, match="github_transport_deadline_exhausted"):
        _transport_with(opener)._open(object(), 0.1, 20)

    assert opener.calls[0][1] == 0.1
    assert response.closed
    assert len(response.read_sizes) == 2


def test_open_reads_at_most_cap_plus_one_and_closes_when_body_exceeds_cap():
    response = FakeResponse(b"1234")

    with pytest.raises(GitHubPublicationError, match="github_response_too_large"):
        _transport_with(FakeOpener(response))._open(object(), 1.0, 3)

    assert response.read_sizes == [4]
    assert response.closed


def test_open_accepts_body_at_exact_cap_and_closes_response():
    response = FakeResponse(b"123")

    result = _transport_with(FakeOpener(response))._open(object(), 1.0, 3)

    assert result.body == b"123"
    assert result.status == 200
    assert response.closed


def test_open_closes_response_when_read_raises():
    class BrokenResponse(FakeResponse):
        def read1(self, _size: int) -> bytes:
            raise OSError("fixture read failure")

    response = BrokenResponse(b"")
    with pytest.raises(GitHubPublicationError, match="github_transport_failed"):
        _transport_with(FakeOpener(response))._open(object(), 1.0, 20)

    assert response.closed


def test_redirect_handler_refuses_redirect_and_http_error_is_returned_once():
    handler = actions_publication._NoRedirect()
    request = urllib.request.Request("https://api.example.test/repos/a/b")
    assert handler.redirect_request(request, None, 302, "Found", {}, "https://elsewhere.test/") is None

    body = io.BytesIO(b'{"message":"redirect refused"}')
    error = urllib.error.HTTPError(
        "https://api.example.test/repos/a/b", 302, "Found", {"Location": "https://elsewhere.test/"}, body
    )
    opener = FakeOpener(error=error)
    result = _transport_with(opener)._open(request, 1.0, 256)

    assert result.status == 302
    assert result.headers["location"] == "https://elsewhere.test/"
    assert result.body == b'{"message":"redirect refused"}'
    assert len(opener.calls) == 1
    assert body.closed
