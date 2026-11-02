#!/usr/bin/env python3
"""Fail-closed GA-2 enforcement: safety-invariant changes need decision records.

This script is the PR-diff half of the protocol documented in
``docs/adr/README.md`` and ``docs/REVIEW-EVIDENCE.md``. For a pull request it:

1. reads the pull request event JSON (``--event`` or ``GITHUB_EVENT_PATH``);
2. obtains the changed file list from the GitHub REST API
   (``GET /repos/{owner}/{repo}/pulls/{number}/files``) with a read-only token,
   or from a captured fixture supplied with ``--changed-files`` for tests;
3. reads ``docs/adr/safety-invariants.json``, ``docs/adr/README.md``, and the
   referenced records from the pull request **base** revision;
4. if any changed path matches a safety-invariant path or glob, requires a
   non-empty ``decision_records`` list in the review receipt, and requires every
   referenced record to exist on the base revision, be listed in the ADR index,
   and have Status ``Accepted``.

It never checks out or executes pull request code, never reads the pull request
working tree, never writes to GitHub, and never prints the token. Any missing,
partial, or malformed input fails closed. Diagnostics carry stable codes and are
emitted in a deterministic order.

The workflow that runs this check (``.github/workflows/decision-record-links.yml``)
checks out the base revision and passes it as ``--base-ref``, so record
existence is evaluated against the base commit object even if the working tree
differs. Without ``--base-ref`` the files are read from ``--repo-root``.

Exit codes
----------
0   no safety-invariant path changed, or every required decision record is
    accepted on the base revision
1   unexpected internal error
2   event unavailable or malformed
3   changed-file list unavailable (fixture or GitHub API)
4   base-revision content unavailable (manifest or index)
5   the review receipt is missing or did not validate
6   the validated receipt has no ``decision_records`` list
7   a referenced decision record is invalid (format, index, existence, status)

Usage
-----
    python3 scripts/check_decision_record_links.py --event pull_request.json
    python3 scripts/check_decision_record_links.py --event pull_request.json \\
        --changed-files changed-files.json --repo-root . --base-ref HEAD
    python3 scripts/check_decision_record_links.py --event pull_request.json --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_decision_records as adr  # noqa: E402
import check_review_receipt as receipt  # noqa: E402

SCHEMA_ID = "decision-record-links.v1"
MANIFEST_PATH = "docs/adr/safety-invariants.json"
INDEX_PATH = "docs/adr/README.md"
API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
USER_AGENT = "pr-review-harness-decision-record-links"
PER_PAGE = 100
MAX_PAGES = 10
MAX_CHANGED_FILES = MAX_PAGES * PER_PAGE
MAX_RESPONSE_BYTES = 4_000_000
MAX_FIXTURE_BYTES = 4_000_000
HTTP_TIMEOUT_SECONDS = 20
GIT_TIMEOUT_SECONDS = 60
MAX_REPORTED_MATCHES = 20
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
GLOB_CHARS = frozenset("*?[")

EXIT_INTERNAL = 1
EXIT_EVENT = 2
EXIT_CHANGED_FILES = 3
EXIT_BASE = 4
EXIT_RECEIPT = 5
EXIT_DECISION_RECORDS = 6
EXIT_RECORD = 7

# Insertion order is the stable priority used to sort failures and to choose the
# reported exit code, so identical input always produces identical output.
CODE_EXITS: dict[str, int] = {
    "EVENT_PATH_MISSING": EXIT_EVENT,
    "EVENT_PATH_UNREADABLE": EXIT_EVENT,
    "EVENT_TOO_LARGE": EXIT_EVENT,
    "EVENT_INVALID_JSON": EXIT_EVENT,
    "EVENT_INVALID_SHAPE": EXIT_EVENT,
    "EVENT_NUMBER_UNKNOWN": EXIT_EVENT,
    "EVENT_REPOSITORY_UNKNOWN": EXIT_EVENT,
    "CHANGED_FILES_FIXTURE_MISSING": EXIT_CHANGED_FILES,
    "CHANGED_FILES_FIXTURE_INVALID": EXIT_CHANGED_FILES,
    "CHANGED_FILES_TOKEN_MISSING": EXIT_CHANGED_FILES,
    "CHANGED_FILES_API_UNAVAILABLE": EXIT_CHANGED_FILES,
    "CHANGED_FILES_API_ERROR": EXIT_CHANGED_FILES,
    "CHANGED_FILES_API_INVALID": EXIT_CHANGED_FILES,
    "CHANGED_FILES_API_TRUNCATED": EXIT_CHANGED_FILES,
    "BASE_UNAVAILABLE": EXIT_BASE,
    "MANIFEST_MISSING": EXIT_BASE,
    "MANIFEST_INVALID": EXIT_BASE,
    "INDEX_MISSING": EXIT_BASE,
    "RECEIPT_NOT_VALID": EXIT_RECEIPT,
    "DECISION_RECORDS_MISSING": EXIT_DECISION_RECORDS,
    "RECORD_REFERENCE_INVALID": EXIT_RECORD,
    "RECORD_NOT_INDEXED": EXIT_RECORD,
    "RECORD_NOT_ACCEPTED": EXIT_RECORD,
    "RECORD_FILE_UNRESOLVED": EXIT_RECORD,
    "RECORD_PATH_MISMATCH": EXIT_RECORD,
    "RECORD_MISSING": EXIT_RECORD,
    "RECORD_INVALID": EXIT_RECORD,
}
_CODE_PRIORITY = {code: index for index, code in enumerate(CODE_EXITS)}


@dataclass(frozen=True)
class Failure:
    code: str
    message: str

    @property
    def exit_code(self) -> int:
        return CODE_EXITS.get(self.code, EXIT_INTERNAL)

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True)
class Report:
    failures: tuple[Failure, ...] = ()
    changed_files: int = 0
    changed_source: str | None = None
    matches: tuple[dict[str, str], ...] = ()
    decision_records: tuple[str, ...] | None = None
    base_ref: str | None = None

    @property
    def ok(self) -> bool:
        return not self.failures

    @property
    def exit_code(self) -> int:
        return self.failures[0].exit_code if self.failures else 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_ID,
            "status": "PASS" if self.ok else "FAIL",
            "exit_code": self.exit_code,
            "base_ref": self.base_ref,
            "changed_files": self.changed_files,
            "changed_source": self.changed_source,
            "safety_paths": [dict(item) for item in self.matches],
            "decision_records": list(self.decision_records) if self.decision_records is not None else None,
            "failures": [failure.as_dict() for failure in self.failures],
        }


def _failure(code: str, message: str) -> Failure:
    return Failure(code=code, message=message)


def _sorted_failures(failures: list[Failure]) -> tuple[Failure, ...]:
    return tuple(sorted(failures, key=lambda failure: (_CODE_PRIORITY.get(failure.code, 10_000), failure.message)))


class BaseSourceError(Exception):
    """The base revision content could not be read (tooling failure)."""


class ChangedFilesError(Exception):
    """The changed-file list could not be obtained."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def normalize_path(value: str) -> str:
    path = value.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _safe_relative(relative: str) -> str:
    """Return ``relative`` unchanged when it is a plain repository-relative path."""

    path = normalize_path(relative)
    if not path or path.startswith("/") or ".." in path.split("/"):
        raise BaseSourceError(f"refusing to read unsafe repository path {relative!r}")
    return path


class BaseSource:
    """Read files from the pull request base revision.

    With ``ref`` the content comes from the immutable Git object
    ``<ref>:<path>`` using fixed argument arrays; without it the files are read
    from ``root``, which the workflow keeps checked out at the base SHA.
    """

    def __init__(self, root: Path, ref: str | None = None) -> None:
        self._root = root
        self._ref = ref

    @property
    def ref(self) -> str | None:
        return self._ref

    def read_text(self, relative: str) -> str | None:
        path = _safe_relative(relative)
        if self._ref is None:
            target = self._root / path
            if not target.is_file():
                return None
            try:
                return target.read_text(encoding="utf-8")
            except OSError as exc:
                raise BaseSourceError(f"cannot read {path}: {exc}") from exc
        if not self._git_exists(path):
            return None
        completed = self._git(["show", f"{self._ref}:{path}"])
        if completed.returncode != 0:
            raise BaseSourceError(f"git show failed for {path}")
        try:
            return completed.stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BaseSourceError(f"{path} is not UTF-8 text") from exc

    def _git_exists(self, path: str) -> bool:
        completed = self._git(["cat-file", "-e", f"{self._ref}:{path}"])
        return completed.returncode == 0

    def _git(self, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
        command = ["git", "-C", str(self._root), *arguments]
        try:
            return subprocess.run(command, capture_output=True, timeout=GIT_TIMEOUT_SECONDS, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise BaseSourceError(f"cannot run git: {type(exc).__name__}") from exc


def parse_manifest(text: str) -> list[dict[str, str]]:
    """Return ``{invariant, pattern}`` entries from the safety-invariant manifest.

    A manifest path is either an exact repository-relative file path, a directory
    path ending in ``/``, or a glob using ``*``, ``?``, ``**``, and ``[...]``.
    """

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest is not valid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError("manifest must be a JSON object")
    invariants = data.get("invariants")
    if not isinstance(invariants, list) or not invariants:
        raise ValueError("manifest.invariants must be a non-empty list")
    entries: list[dict[str, str]] = []
    for index, invariant in enumerate(invariants):
        if not isinstance(invariant, dict):
            raise ValueError(f"manifest.invariants[{index}] must be an object")
        invariant_id = invariant.get("id")
        if not isinstance(invariant_id, str) or not invariant_id.strip():
            raise ValueError(f"manifest.invariants[{index}] has no id")
        paths = invariant.get("paths")
        if not isinstance(paths, list) or not paths:
            raise ValueError(f"manifest invariant {invariant_id!r} has no paths")
        for pattern in paths:
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError(f"manifest invariant {invariant_id!r} has an empty path")
            candidate = normalize_path(pattern)
            if candidate.startswith("/") or ".." in candidate.split("/"):
                raise ValueError(f"manifest invariant {invariant_id!r} has an absolute or escaping path")
            entries.append({"invariant": invariant_id.strip(), "pattern": candidate})
    # The manifest defines the protected surface, so changing the manifest is
    # itself a safety-invariant change.
    entries.append({"invariant": "safety-invariant-manifest", "pattern": MANIFEST_PATH})
    return entries


def _glob_regex(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "*":
            if pattern[index : index + 2] == "**":
                while index < length and pattern[index] == "*":
                    index += 1
                if index < length and pattern[index] == "/":
                    index += 1
                    out.append(r"(?:[^/]+/)*")
                else:
                    out.append(r".*")
                continue
            out.append(r"[^/]*")
        elif char == "?":
            out.append(r"[^/]")
        elif char == "[":
            cursor = index + 1
            if cursor < length and pattern[cursor] in "!^":
                cursor += 1
            if cursor < length and pattern[cursor] == "]":
                cursor += 1
            while cursor < length and pattern[cursor] != "]":
                cursor += 1
            if cursor >= length:
                out.append(re.escape(char))
            else:
                inner = pattern[index + 1 : cursor]
                if inner.startswith("!"):
                    inner = "^" + inner[1:]
                out.append("[" + inner + "]")
                index = cursor
        else:
            out.append(re.escape(char))
        index += 1
    return re.compile("".join(out) + r"\Z")


def pattern_matches(pattern: str, path: str) -> bool:
    """Match a repository path against a manifest path, directory, or glob."""

    path = normalize_path(path)
    if pattern.endswith("/"):
        prefix = pattern.rstrip("/")
        return path == prefix or path.startswith(f"{prefix}/")
    if not (GLOB_CHARS & set(pattern)):
        return path == pattern
    return _glob_regex(pattern).match(path) is not None


def safety_matches(changed: list[dict[str, str]], entries: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return deterministic matches between changed paths and manifest entries."""

    seen: set[tuple[str, str, str]] = set()
    matches: list[dict[str, str]] = []
    for item in changed:
        for path in {item["filename"], item.get("previous_filename", "")}:
            if not path:
                continue
            for entry in entries:
                if not pattern_matches(entry["pattern"], path):
                    continue
                key = (normalize_path(path), entry["invariant"], entry["pattern"])
                if key in seen:
                    continue
                seen.add(key)
                matches.append({"path": key[0], "invariant": key[1], "pattern": key[2]})
    return sorted(matches, key=lambda match: (match["path"], match["invariant"], match["pattern"]))


def _changed_items(value: Any, label: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ChangedFilesError("CHANGED_FILES_FIXTURE_INVALID", f"{label} must be a list")
    items: list[dict[str, str]] = []
    for index, entry in enumerate(value):
        if isinstance(entry, str):
            filename = entry
            previous = ""
            status = ""
        elif isinstance(entry, dict):
            filename = entry.get("filename")
            previous = entry.get("previous_filename") or ""
            status = entry.get("status") or ""
            if not isinstance(filename, str) or not isinstance(previous, str) or not isinstance(status, str):
                raise ChangedFilesError(
                    "CHANGED_FILES_FIXTURE_INVALID", f"{label}[{index}] has non-string filename/status fields"
                )
        else:
            raise ChangedFilesError(
                "CHANGED_FILES_FIXTURE_INVALID", f"{label}[{index}] must be a path string or an object"
            )
        if not isinstance(filename, str) or not filename.strip():
            raise ChangedFilesError("CHANGED_FILES_FIXTURE_INVALID", f"{label}[{index}] has no filename")
        item = {"filename": normalize_path(filename)}
        if previous:
            item["previous_filename"] = normalize_path(previous)
        if status:
            item["status"] = status
        items.append(item)
    return items


def load_changed_files_fixture(path: Path) -> list[dict[str, str]]:
    """Read a captured changed-file list: ``["a.py"]``, ``[{filename: ...}]``, or ``{"files": ...}``."""

    if not path.is_file():
        raise ChangedFilesError("CHANGED_FILES_FIXTURE_MISSING", f"changed-files fixture not found: {path.name}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ChangedFilesError("CHANGED_FILES_FIXTURE_MISSING", f"cannot read fixture: {exc}") from exc
    if len(raw) > MAX_FIXTURE_BYTES:
        raise ChangedFilesError("CHANGED_FILES_FIXTURE_INVALID", "changed-files fixture is too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChangedFilesError("CHANGED_FILES_FIXTURE_INVALID", f"fixture is not valid JSON: {exc}") from exc
    if isinstance(data, dict):
        if "files" not in data:
            raise ChangedFilesError("CHANGED_FILES_FIXTURE_INVALID", "fixture object must have a 'files' list")
        return _changed_items(data["files"], "files")
    return _changed_items(data, "fixture")


class _RefuseRedirects(HTTPRedirectHandler):
    """Refuse redirects so the Authorization header can never follow one."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, D401
        raise ChangedFilesError(
            "CHANGED_FILES_API_ERROR",
            f"GitHub API attempted an HTTP {code} redirect; refusing to follow it",
        )


_OPENER = build_opener(_RefuseRedirects())


def _build_request(url: str, token: str) -> Request:
    return Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )


def _open(request: Request) -> Any:
    """Open one API request; a separate function so tests can inject failures."""

    return _OPENER.open(request, timeout=HTTP_TIMEOUT_SECONDS)


def _request_page(url: str, token: str) -> bytes:
    request = _build_request(url, token)
    try:
        with _open(request) as response:
            return response.read(MAX_RESPONSE_BYTES + 1)
    except ChangedFilesError:
        raise
    except HTTPError as exc:
        raise ChangedFilesError(
            "CHANGED_FILES_API_ERROR", f"GitHub API returned HTTP {exc.code}; failing closed"
        ) from exc
    except URLError as exc:
        raise ChangedFilesError(
            "CHANGED_FILES_API_UNAVAILABLE",
            f"GitHub API request failed ({type(exc.reason).__name__}); failing closed",
        ) from exc
    except (TimeoutError, OSError) as exc:
        raise ChangedFilesError(
            "CHANGED_FILES_API_UNAVAILABLE", f"GitHub API request failed ({type(exc).__name__}); failing closed"
        ) from exc


def fetch_changed_files(repository: str, number: int, token: str) -> list[dict[str, str]]:
    """Page through the pull request files endpoint. Any doubt fails closed."""

    if not REPOSITORY_RE.match(repository):
        raise ChangedFilesError("CHANGED_FILES_API_INVALID", "repository identity is not owner/name")
    files: list[dict[str, str]] = []
    for page in range(1, MAX_PAGES + 1):
        url = f"{API_ROOT}/repos/{repository}/pulls/{number}/files?per_page={PER_PAGE}&page={page}"
        body = _request_page(url, token)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ChangedFilesError("CHANGED_FILES_API_INVALID", f"API page {page} response is too large")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ChangedFilesError(
                "CHANGED_FILES_API_INVALID", f"API page {page} is not valid JSON; failing closed"
            ) from exc
        if not isinstance(payload, list):
            raise ChangedFilesError("CHANGED_FILES_API_INVALID", f"API page {page} is not a JSON list")
        for index, entry in enumerate(payload):
            if not isinstance(entry, dict) or not isinstance(entry.get("filename"), str) or not entry["filename"].strip():
                raise ChangedFilesError(
                    "CHANGED_FILES_API_INVALID", f"API page {page} entry {index} has no filename"
                )
            item = {"filename": normalize_path(entry["filename"])}
            previous = entry.get("previous_filename")
            if isinstance(previous, str) and previous.strip():
                item["previous_filename"] = normalize_path(previous)
            status = entry.get("status")
            if isinstance(status, str) and status.strip():
                item["status"] = status.strip()
            files.append(item)
        if len(files) > MAX_CHANGED_FILES:
            raise ChangedFilesError("CHANGED_FILES_API_TRUNCATED", f"more than {MAX_CHANGED_FILES} changed files")
        if len(payload) < PER_PAGE:
            return files
    raise ChangedFilesError(
        "CHANGED_FILES_API_TRUNCATED",
        f"changed-file list exceeds {MAX_CHANGED_FILES} entries after {MAX_PAGES} pages; failing closed",
    )


def pull_request_number(event: dict[str, Any]) -> int | None:
    candidates = [event.get("number")]
    pull_request = event.get("pull_request")
    if isinstance(pull_request, dict):
        candidates.append(pull_request.get("number"))
    for candidate in candidates:
        if isinstance(candidate, int) and not isinstance(candidate, bool) and candidate > 0:
            return candidate
    return None


def repository_from_event(event: dict[str, Any]) -> str | None:
    repository = event.get("repository")
    if isinstance(repository, dict):
        full_name = repository.get("full_name")
        if isinstance(full_name, str) and REPOSITORY_RE.match(full_name.strip()):
            return full_name.strip()
    return None


def resolve_reference(reference: str) -> tuple[str, str | None] | None:
    """Return ``(record_id, named_path)`` for an ID, path, or repository link."""

    text = reference.strip()
    if receipt.DECISION_RECORD_ID_RE.match(text):
        return text, None
    if receipt.DECISION_RECORD_PATH_RE.match(text):
        name = text.rsplit("/", 1)[-1]
        return name[:4], text
    if receipt.DECISION_RECORD_URL_RE.match(text):
        marker = text.find("/docs/adr/")
        path = text[marker + 1 :]
        if receipt.DECISION_RECORD_PATH_RE.match(path):
            name = path.rsplit("/", 1)[-1]
            return name[:4], path
    return None


def _index_record_file(row: list[str], record_id: str) -> str | None:
    if len(row) < 2:
        return None
    for match in adr.LINK_RE.finditer(row[1]):
        name = Path(match.group("target")).name
        if adr.RECORD_RE.match(name) and name.startswith(f"{record_id}-"):
            return name
    return None


def verify_decision_records(
    base: BaseSource,
    references: tuple[str, ...],
) -> tuple[list[Failure], tuple[str, ...]]:
    """Check each referenced record against the base revision and ADR index."""

    failures: list[Failure] = []
    try:
        index_text = base.read_text(INDEX_PATH)
    except BaseSourceError as exc:
        return [_failure("BASE_UNAVAILABLE", f"cannot read the ADR index from the base revision: {exc}")], references
    if index_text is None:
        return [_failure("INDEX_MISSING", f"{INDEX_PATH} is missing on the base revision")], references
    rows = adr.parse_index_rows(index_text)

    checked: list[str] = []
    for reference in references:
        resolved = resolve_reference(reference)
        if resolved is None:
            failures.append(
                _failure(
                    "RECORD_REFERENCE_INVALID",
                    f"{reference!r} is not a four-digit record ID, a docs/adr/NNNN-*.md path, or a link to it",
                )
            )
            continue
        record_id, named_path = resolved
        if record_id in checked:
            continue
        checked.append(record_id)

        row = rows.get(record_id)
        if row is None:
            failures.append(_failure("RECORD_NOT_INDEXED", f"record {record_id} is not listed in {INDEX_PATH}"))
            continue
        if len(row) < 3 or row[2] != "Accepted":
            status = row[2] if len(row) >= 3 and row[2] else "unstated"
            failures.append(
                _failure(
                    "RECORD_NOT_ACCEPTED",
                    f"record {record_id} has ADR index status {status!r}; only Accepted can satisfy the check",
                )
            )
            continue

        filename = _index_record_file(row, record_id)
        if filename is None:
            failures.append(
                _failure("RECORD_FILE_UNRESOLVED", f"the {INDEX_PATH} row for {record_id} does not link its record file")
            )
            continue
        if named_path is not None and named_path != f"docs/adr/{filename}":
            failures.append(
                _failure(
                    "RECORD_PATH_MISMATCH",
                    f"reference {named_path!r} does not match the indexed record file docs/adr/{filename}",
                )
            )
            continue

        try:
            text = base.read_text(f"docs/adr/{filename}")
        except BaseSourceError as exc:
            failures.append(
                _failure("BASE_UNAVAILABLE", f"cannot read docs/adr/{filename} from the base revision: {exc}")
            )
            continue
        if text is None:
            failures.append(
                _failure("RECORD_MISSING", f"docs/adr/{filename} is missing on the base revision")
            )
            continue

        record = adr.parse_record_text(text, filename)
        fields = record["fields"]
        assert isinstance(fields, dict)
        status = str(fields.get("Status", "")).strip()
        if not status:
            failures.append(_failure("RECORD_INVALID", f"docs/adr/{filename} has no Status field"))
            continue
        if status != "Accepted":
            failures.append(
                _failure(
                    "RECORD_NOT_ACCEPTED",
                    f"docs/adr/{filename} has Status {status!r}; only Accepted can satisfy the check",
                )
            )
            continue
        title = str(record["title"])
        if not title.startswith(f"# {record_id}"):
            failures.append(
                _failure("RECORD_INVALID", f"docs/adr/{filename} title must start with '# {record_id}'")
            )
    return failures, tuple(checked)


def evaluate(
    *,
    event_path: Path | None,
    changed_files_path: Path | None,
    repo_root: Path,
    base_ref: str | None,
    token: str | None,
    repository: str | None,
) -> Report:
    """Run the check without network access when a changed-files fixture is given."""

    if base_ref is not None and (not base_ref.strip() or base_ref.startswith("-")):
        return Report((_failure("BASE_UNAVAILABLE", f"refusing invalid --base-ref value {base_ref!r}"),))

    event, event_failures = receipt.load_event(event_path)
    if event_failures:
        return Report(_sorted_failures(list(event_failures)))
    if not isinstance(event, dict):
        return Report((_failure("EVENT_INVALID_SHAPE", "event must be a JSON object"),))

    if changed_files_path is not None:
        try:
            changed = load_changed_files_fixture(changed_files_path)
        except ChangedFilesError as exc:
            return Report((_failure(exc.code, exc.message),))
        source = f"fixture:{changed_files_path.name}"
    else:
        number = pull_request_number(event)
        if number is None:
            return Report((_failure("EVENT_NUMBER_UNKNOWN", "the event has no pull request number"),))
        resolved_repository = repository or repository_from_event(event)
        if resolved_repository is None:
            return Report(
                (_failure("EVENT_REPOSITORY_UNKNOWN", "GITHUB_REPOSITORY or event.repository.full_name is required"),)
            )
        if not token:
            return Report(
                (_failure("CHANGED_FILES_TOKEN_MISSING", "GITHUB_TOKEN is required to read the changed-file list"),)
            )
        try:
            changed = fetch_changed_files(resolved_repository, number, token)
        except ChangedFilesError as exc:
            return Report((_failure(exc.code, exc.message),))
        source = "github-api"

    base = BaseSource(repo_root, base_ref)
    try:
        manifest_text = base.read_text(MANIFEST_PATH)
    except BaseSourceError as exc:
        return Report((_failure("BASE_UNAVAILABLE", f"cannot read {MANIFEST_PATH} from the base revision: {exc}"),))
    if manifest_text is None:
        return Report((_failure("MANIFEST_MISSING", f"{MANIFEST_PATH} is missing on the base revision"),))
    try:
        entries = parse_manifest(manifest_text)
    except ValueError as exc:
        return Report((_failure("MANIFEST_INVALID", f"{MANIFEST_PATH} is invalid: {exc}"),))

    matches = safety_matches(changed, entries)
    if not matches:
        return Report(
            changed_files=len(changed),
            changed_source=source,
            matches=(),
            decision_records=None,
            base_ref=base_ref,
        )

    receipt_report = receipt.validate_event(event)
    if not receipt_report.ok:
        codes = ", ".join(sorted({failure.code for failure in receipt_report.failures}))
        return Report(
            (
                _failure(
                    "RECEIPT_NOT_VALID",
                    f"the review receipt did not validate ({codes}); "
                    "run scripts/check_review_receipt.py for the detailed failure",
                ),
            ),
            changed_files=len(changed),
            changed_source=source,
            matches=tuple(matches),
            decision_records=receipt_report.decision_records,
            base_ref=base_ref,
        )
    if not receipt_report.decision_records:
        return Report(
            (
                _failure(
                    "DECISION_RECORDS_MISSING",
                    "a changed path matches docs/adr/safety-invariants.json but the review receipt has no "
                    "decision_records list; cite the accepted decision record that authorizes the change",
                ),
            ),
            changed_files=len(changed),
            changed_source=source,
            matches=tuple(matches),
            decision_records=None,
            base_ref=base_ref,
        )

    failures, checked = verify_decision_records(base, receipt_report.decision_records)
    return Report(
        _sorted_failures(failures),
        changed_files=len(changed),
        changed_source=source,
        matches=tuple(matches),
        decision_records=checked,
        base_ref=base_ref,
    )


def render_summary(report: Report) -> str:
    """Deterministic Markdown summary for the job summary; contains no token."""

    lines = ["## Decision record links", ""]
    lines.append(f"- Result: **{'PASS' if report.ok else 'FAIL'}** (exit {report.exit_code})")
    lines.append(f"- Base revision: `{report.base_ref}`" if report.base_ref else "- Base revision: working tree")
    if report.changed_source:
        lines.append(f"- Changed files examined: {report.changed_files} (source `{report.changed_source}`)")
    if report.matches:
        lines.append(f"- Safety-invariant paths changed: {len(report.matches)}")
        for match in report.matches[:MAX_REPORTED_MATCHES]:
            lines.append(f"  - `{match['path']}` ({match['invariant']}; pattern `{match['pattern']}`)")
        if len(report.matches) > MAX_REPORTED_MATCHES:
            lines.append(f"  - ... and {len(report.matches) - MAX_REPORTED_MATCHES} more")
    else:
        lines.append("- Safety-invariant paths changed: none; no decision record required")
    if report.decision_records is not None:
        records = ", ".join(f"`{record}`" for record in report.decision_records)
        lines.append(f"- Decision records cited: {records}")
    if report.failures:
        lines.append("- Failures:")
        for failure in report.failures:
            lines.append(f"  - `{failure.code}`: {failure.message}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed GA-2 decision-record enforcement.")
    parser.add_argument(
        "--event",
        type=Path,
        default=None,
        help="Path to the pull request event JSON (defaults to GITHUB_EVENT_PATH).",
    )
    parser.add_argument(
        "--changed-files",
        type=Path,
        default=None,
        help="Fixture changed-file list for tests; never contacts the GitHub API.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root holding the base revision (default: this checkout).",
    )
    parser.add_argument(
        "--base-ref",
        default=None,
        help="Git revision to read the manifest, index, and records from instead of the working tree.",
    )
    parser.add_argument("--json", action="store_true", help="Emit the machine-readable report on stdout.")
    parser.add_argument("--summary", type=Path, default=None, help="Append a Markdown summary to this file.")
    args = parser.parse_args(argv)

    event_path = args.event
    if event_path is None:
        env_path = os.environ.get("GITHUB_EVENT_PATH")
        event_path = Path(env_path) if env_path else None

    try:
        report = evaluate(
            event_path=event_path,
            changed_files_path=args.changed_files,
            repo_root=args.repo_root,
            base_ref=args.base_ref,
            token=os.environ.get("GITHUB_TOKEN"),
            repository=os.environ.get("GITHUB_REPOSITORY"),
        )
    except Exception as exc:  # noqa: BLE001 - fail closed on any unexpected error
        print(f"decision-record-links: ERROR {type(exc).__name__}: internal failure", file=sys.stderr)
        return EXIT_INTERNAL

    if args.json:
        print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
        if not report.ok:
            print(f"decision-record-links: FAIL ({len(report.failures)} problem(s))", file=sys.stderr)
    elif report.ok:
        print(
            "decision-record-links: PASS "
            f"changed_files={report.changed_files} safety_paths={len(report.matches)} "
            f"records={','.join(report.decision_records) if report.decision_records else '-'}"
        )
    else:
        for failure in report.failures:
            print(f"decision-record-links: ERROR {failure.code}: {failure.message}", file=sys.stderr)
        print(f"decision-record-links: FAIL ({len(report.failures)} problem(s))", file=sys.stderr)

    if args.summary is not None:
        try:
            with args.summary.open("a", encoding="utf-8") as handle:
                handle.write(render_summary(report) + "\n")
        except OSError as exc:
            print(f"decision-record-links: ERROR SUMMARY_WRITE_FAILED: {exc}", file=sys.stderr)
            return EXIT_INTERNAL

    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
