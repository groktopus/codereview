#!/usr/bin/env python3
"""Check evidence discipline in the living documentation set."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_relative_links import LINK_RE, REFERENCE_RE  # noqa: E402

TRUTH_SCHEMA = "documentation-evidence.v1"
SHA_SCHEMA = "documentation-sha-references.v1"
CONTRACT_SCHEMA = "documentation-contract-ids.v1"
INLINE_CODE_RE = re.compile(r"`([^`]+)`")
SHA_TOKEN_RE = re.compile(r"[0-9a-fA-F]{7,40}\Z")
HEX_TOKEN_RE = re.compile(r"[0-9a-fA-F]+\Z")
FENCE_RE = re.compile(r"^\s*(```+|~~~+)")
CLAIM_PATTERNS = (
    ("PRODUCTION_READY", re.compile(r"\bproduction[ -]ready\b", re.IGNORECASE)),
    (
        "REPLACES_REVIEWER",
        re.compile(
            r"\b(?:the\s+)?(?:harness|tool|system|product)\s+"
            r"(?:(?P<negative>does\s+not|doesn't|never)\s+)?(?:fully\s+)?replaces?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "ACCURACY_ASSERTION",
        re.compile(r"\b(?:is|are|was|were|remains?)\s+(?:(?P<negative>not|never)\s+)?accurate\b", re.IGNORECASE),
    ),
)
DIRECT_NEGATION = re.compile(
    r"(?:\bnot\s+(?:(?:yet|currently|established|accepted|considered)\s+)?|"
    r"\bnever\s+|\bisn't\s+|\baren't\s+|\bdoesn't\s+|\bdoes\s+not\s+)$",
    re.IGNORECASE,
)
EVIDENCE_LABEL = re.compile(
    r"\b(?:evidence|test(?:s)?|run|artifact|benchmark|result|verification|report|receipt|check|evaluation|measurement|trace|source|commit|workflow)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Finding:
    code: str
    file: str
    line: int
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "file": self.file, "line": self.line, "message": self.message}


def _links(line: str) -> list[str]:
    found = []
    for match in LINK_RE.finditer(line):
        target = match.group(1).strip()
        found.append(target[1:-1].strip() if target.startswith("<") and target.endswith(">") else target)
    reference = REFERENCE_RE.match(line)
    if reference:
        found.append(reference.group(1))
    return found


def current_documents(root: Path, index_path: Path | None = None) -> list[Path]:
    """Read the DT-2 Current section; include the root-facing README."""

    index_path = index_path or root / "docs" / "README.md"
    if not index_path.is_file():
        raise FileNotFoundError(f"documentation index not found: {index_path}")
    inside = False
    linked: list[Path] = []
    for line in index_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            inside = line[3:].strip().rstrip("#").strip().lower() == "current"
            continue
        if not inside or FENCE_RE.match(line):
            continue
        for target in _links(line):
            target = target.split("#", 1)[0].split("?", 1)[0]
            if not target.endswith(".md") or target.startswith(("http://", "https://", "/")):
                continue
            resolved = (index_path.parent / target).resolve()
            if resolved.is_relative_to(root.resolve()) and resolved.is_file():
                linked.append(resolved)
    return sorted({p.resolve() for p in [root / "README.md", index_path, *linked] if p.is_file()})


def _row_has_evidence_for_claim(row: str, claim_start: int, claim_end: int) -> bool:
    """Accept only an evidence link adjacent to the claim with a relevant label."""

    for match in re.finditer(r"\[([^\]]+)\]\(([^)]+)\)", row):
        label, target = match.group(1).strip(), match.group(2).strip()
        if not target or target.startswith(("#", "mailto:", "tel:")):
            continue
        # A link after the claim is considered evidence only when its link text
        # declares an evidence-bearing artifact. An unrelated navigation link
        # elsewhere in the same sentence or table row cannot waive the claim.
        if match.start() >= claim_end and match.start() - claim_end <= 48 and EVIDENCE_LABEL.search(label):
            intervening = row[claim_end : match.start()]
            if re.fullmatch(r"[\s\[\]\(\)]*", intervening):
                return True
    return False


def _is_directly_qualified(text: str, start: int) -> bool:
    prefix = text[max(0, start - 48) : start]
    return DIRECT_NEGATION.search(prefix) is not None


def check_claims(root: Path, paths: list[Path] | None = None) -> list[Finding]:
    """Check each claim occurrence independently, including Markdown table rows."""

    findings: list[Finding] = []
    for path in paths if paths is not None else current_documents(root):
        fenced = False
        for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if FENCE_RE.match(raw_line):
                fenced = not fenced
                continue
            if fenced or not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            # Treat each physical line/table row as an independent claim unit;
            # multi-line paragraphs are intentionally not merged for waivers.
            text = re.sub(r"`([^`]*)`", r"\1", raw_line)
            for code, pattern in CLAIM_PATTERNS:
                for match in pattern.finditer(text):
                    if match.groupdict().get("negative") or _is_directly_qualified(text, match.start()):
                        continue
                    if _row_has_evidence_for_claim(raw_line, match.start(), match.end()):
                        continue
                    findings.append(
                        Finding(
                            code,
                            path.relative_to(root).as_posix(),
                            number,
                            f"unqualified phrase {match.group(0)!r}; add a nearby same-claim evidence link (for example [test evidence](path)) or directly negate/qualify this occurrence",
                        )
                    )
    return findings


def _reference_candidates(line: str) -> list[tuple[str, int, int, bool]]:
    """Return full code tokens and context-labeled decimal run IDs."""

    candidates: list[tuple[str, int, int, bool]] = []
    for match in INLINE_CODE_RE.finditer(line):
        token = match.group(1)
        if HEX_TOKEN_RE.fullmatch(token) and len(token) >= 7:
            candidates.append((token, match.start(), match.end(), True))
    run_patterns = (
        re.compile(
            r"\b(?:actions\s+)?(?:run|job|check|artifact|review)(?:\s+(?:id|number))?\s*#\s*([0-9]{7,12})\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:actions\s+)?(?:run|job|check|artifact|review)(?:\s+(?:id|number))?\s+([0-9]{7,12})\b", re.IGNORECASE
        ),
        re.compile(
            r"\b(?:actions\s+)?(?:run|job|check|artifact|review)\s+(?:A|B|\d+)\s+`?([0-9]{7,12})`?\b", re.IGNORECASE
        ),
    )
    known = {token for token, _, _, _ in candidates}
    for pattern in run_patterns:
        for match in pattern.finditer(line):
            token = match.group(1)
            if token not in known:
                candidates.append((token, match.start(1), match.end(1), False))
                known.add(token)
    return candidates


def referenced_shas(root: Path, paths: list[Path] | None = None) -> list[tuple[Path, int, str]]:
    """Enumerate full inline hex tokens and context-labeled run identifiers."""

    result: list[tuple[Path, int, str]] = []
    for path in paths if paths is not None else current_documents(root):
        fenced = False
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if FENCE_RE.match(line):
                fenced = not fenced
                continue
            if fenced:
                continue
            result.extend((path, number, token.lower()) for token, _, _, _ in _reference_candidates(line))
    return result


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(root), *args], check=False, text=True, capture_output=True)


def _git_exists(root: Path, sha: str) -> bool:
    return (
        subprocess.run(
            ["git", "-C", str(root), "cat-file", "-e", f"{sha}^{{commit}}"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def _sha_reference_records(manifest_path: Path) -> dict[str, dict[str, str]]:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read SHA reference manifest {manifest_path}: {error}") from error
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != SHA_SCHEMA
        or not isinstance(data.get("references"), list)
    ):
        raise ValueError(f"SHA reference manifest must use schema_version {SHA_SCHEMA!r} and a references array")
    records: dict[str, dict[str, str]] = {}
    for index, row in enumerate(data["references"]):
        if not isinstance(row, dict) or not isinstance(row.get("value"), str):
            raise ValueError(f"references[{index}] must include a string value")
        kind = row.get("kind")
        value = row["value"]
        if kind == "commit":
            if not SHA_TOKEN_RE.fullmatch(value):
                raise ValueError(f"references[{index}] commit value must be a full-match 7-40 hexadecimal token")
            key = f"commit:{value.lower()}"
        elif kind == "run-id":
            if not re.fullmatch(r"[0-9]{7,12}", value):
                raise ValueError(f"references[{index}] run-id value must contain 7-12 decimal digits")
            key = f"run-id:{value}"
        elif kind == "artifact-digest":
            if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
                raise ValueError(
                    f"references[{index}] artifact-digest value must contain exactly 64 hexadecimal characters"
                )
            key = f"artifact-digest:{value.lower()}"
        else:
            raise ValueError(f"references[{index}].kind must be commit, run-id, or artifact-digest")
        repository, scope, evidence = row.get("repository"), row.get("scope"), row.get("evidence")
        if repository not in {"groktopus/codereview", "magnus919/SlopSearX", "unknown"}:
            raise ValueError(
                f"references[{index}].repository must be groktopus/codereview, magnus919/SlopSearX, or unknown"
            )
        if scope not in {
            "local",
            "foreign-target",
            "historical-local",
            "historical-not-retained",
            "unknown",
            "external-artifact",
        }:
            raise ValueError(f"references[{index}].scope is invalid")
        if kind == "commit":
            allowed = {
                "groktopus/codereview": {"local", "historical-local", "historical-not-retained"},
                "magnus919/SlopSearX": {"foreign-target"},
                "unknown": {"unknown"},
            }
            if scope not in allowed[repository]:
                raise ValueError(f"references[{index}] has invalid commit repository/scope pairing")
        elif kind == "run-id":
            allowed = {
                "groktopus/codereview": {"local"},
                "magnus919/SlopSearX": {"foreign-target"},
                "unknown": {"unknown"},
            }
            if scope not in allowed[repository]:
                raise ValueError(f"references[{index}] has invalid run-id repository/scope pairing")
        elif repository != "unknown" and scope != "external-artifact":
            raise ValueError(f"references[{index}] artifact-digest scope must be external-artifact")
        if not isinstance(evidence, str) or not evidence.strip():
            raise ValueError(f"references[{index}].evidence must explain source attribution")
        record = {"kind": kind, "repository": repository, "scope": scope, "evidence": evidence}
        if key in records and records[key] != record:
            raise ValueError(f"conflicting provenance for {key}")
        records[key] = record
    return records


def _reference_context(line: str, start: int, end: int) -> str:
    return line[max(0, start - 120) : min(len(line), end + 120)]


def _sha256_context(lines: list[str], line_index: int, start: int, end: int) -> bool:
    """Require an explicit SHA-256/digest label near this exact token."""

    line = lines[line_index]
    adjacent = line[max(0, start - 70) : min(len(line), end + 70)]
    if re.search(r"\b(?:sha[- ]?256|sha256|digest|hash)\b", adjacent, re.IGNORECASE):
        return True
    # Longer proximity is accepted only when the label has an explicit
    # artifact-kind noun and a SHA-256 marker, not a generic word like hash.
    nearby = line[max(0, start - 150) : min(len(line), end + 150)]
    labeled_digest = re.search(r"\b(?:sha[- ]?256|sha256|digest)\b", nearby, re.IGNORECASE)
    artifact_kind = re.search(
        r"\b(?:JSON|Markdown|report|profile|recovery|archive|wheel|sdist|source|output|summary|request|receipt|evidence)\b",
        nearby,
        re.IGNORECASE,
    )
    return bool(labeled_digest and artifact_kind)


def _reference_kind_and_value(line: str, start: int, end: int, token: str) -> tuple[str, str, str | None]:
    """Classify only explicit artifact digests and run IDs; otherwise SHA syntax."""

    context = _reference_context(line, start, end)
    if len(token) == 64 and (
        _sha256_context([line], 0, start, end)
        or re.search(r"artifact-digest|SHA-256|digest|hash", line[max(0, start - 160) : start], re.IGNORECASE)
    ):
        return "artifact-digest", token.lower(), None
    if (
        token.isdigit()
        and 7 <= len(token) <= 12
        and re.search(
            r"(?:\b(?:actions\s+)?(?:run|job|check|artifact|review)(?:\s+(?:id|number|#|A|B|\d+))?\s*(?:#\s*)?`?"
            + re.escape(token)
            + r"`?(?!\d)|"
            r"\b(?:actions\s+)?(?:run|job|check|artifact|review)\s+(?:A|B|\d+)\s+`?" + re.escape(token) + r"`?(?!\d))",
            context,
            re.IGNORECASE,
        )
    ):
        return "run-id", token, None
    if len(token) > 40:
        return (
            "malformed",
            token.lower(),
            f"hexadecimal token has {len(token)} characters, exceeding Git commit SHA length",
        )
    return "commit", token.lower(), None


def check_shas(root: Path, paths: list[Path] | None = None, manifest_path: Path | None = None) -> list[Finding]:
    if manifest_path is None:
        raise ValueError("SHA checking requires an explicit provenance manifest")
    records = _sha_reference_records(manifest_path)
    findings = []
    for path in paths if paths is not None else current_documents(root):
        lines = path.read_text(encoding="utf-8").splitlines()
        fenced = False
        for line_number, line in enumerate(lines, 1):
            if FENCE_RE.match(line):
                fenced = not fenced
                continue
            if fenced:
                continue
            for token, start, end, inline in _reference_candidates(line):
                if not HEX_TOKEN_RE.fullmatch(token) or len(token) < 7:
                    continue
                kind, value, malformed = _reference_kind_and_value(line, start, end, token)
                # A typed manifest record is the explicit classification for
                # ambiguous non-commit IDs and fixed-width digests.
                if f"artifact-digest:{token.lower()}" in records:
                    kind, value, malformed = "artifact-digest", token.lower(), None
                elif f"run-id:{token}" in records:
                    kind, value, malformed = "run-id", token, None
                if malformed and f"artifact-digest:{token.lower()}" in records:
                    kind, value, malformed = "artifact-digest", token.lower(), None
                if malformed:
                    findings.append(
                        Finding(
                            "MALFORMED_SHA",
                            path.relative_to(root).as_posix(),
                            line_number,
                            f"{malformed}: `{token}`; use a valid full commit SHA or identify a non-commit artifact explicitly",
                        )
                    )
                    continue
                key = f"{kind}:{value}"
                record = records.get(key)
                if record is None or record["repository"] == "unknown" or record["scope"] == "unknown":
                    findings.append(
                        Finding(
                            "UNSCOPED_SHA",
                            path.relative_to(root).as_posix(),
                            line_number,
                            f"{kind} `{value}` has no provenance; add it to {manifest_path.relative_to(root)} with kind, repository, scope, and attribution",
                        )
                    )
                    continue
                if kind == "commit":
                    sha = value
                    if (
                        record["repository"] == "groktopus/codereview"
                        and record["scope"] in {"local", "historical-local"}
                        and not _git_exists(root, sha)
                    ):
                        findings.append(
                            Finding(
                                "SHA_NOT_IN_REPOSITORY",
                                path.relative_to(root).as_posix(),
                                line_number,
                                f"local revision `{sha}` is not a commit in this repository; verify it or correct the manifest attribution",
                            )
                        )
                    elif record["scope"] == "historical-not-retained":
                        continue
                    elif record["repository"] == "groktopus/codereview" and record["scope"] == "foreign-target":
                        findings.append(
                            Finding(
                                "SHA_PROVENANCE_CONFLICT",
                                path.relative_to(root).as_posix(),
                                line_number,
                                f"local repository revision `{sha}` cannot use foreign-target scope",
                            )
                        )
                    elif record["repository"] == "groktopus/codereview" and record["scope"] not in {
                        "local",
                        "historical-local",
                        "historical-not-retained",
                    }:
                        findings.append(
                            Finding(
                                "SHA_PROVENANCE_CONFLICT",
                                path.relative_to(root).as_posix(),
                                line_number,
                                f"commit `{sha}` has invalid local scope {record['scope']!r}",
                            )
                        )
                    elif record["repository"] != "groktopus/codereview" and record["scope"] != "foreign-target":
                        findings.append(
                            Finding(
                                "SHA_PROVENANCE_CONFLICT",
                                path.relative_to(root).as_posix(),
                                line_number,
                                f"revision `{sha}` names repository {record['repository']!r} but scope {record['scope']!r}; reconcile attribution",
                            )
                        )
                elif kind == "run-id":
                    allowed_scopes = {"groktopus/codereview": "local", "magnus919/SlopSearX": "foreign-target"}
                    expected = allowed_scopes.get(record["repository"])
                    if record["repository"] != "unknown" and record["scope"] != expected:
                        findings.append(
                            Finding(
                                "SHA_PROVENANCE_CONFLICT",
                                path.relative_to(root).as_posix(),
                                line_number,
                                f"run ID `{value}` has invalid repository/scope pairing",
                            )
                        )
                    if not re.fullmatch(r"[0-9]{7,12}", value):
                        findings.append(
                            Finding(
                                "MALFORMED_RUN_ID",
                                path.relative_to(root).as_posix(),
                                line_number,
                                f"run identifier `{value}` must contain 7-12 decimal digits",
                            )
                        )
                elif kind == "artifact-digest" and record["scope"] != "external-artifact":
                    findings.append(
                        Finding(
                            "SHA_PROVENANCE_CONFLICT",
                            path.relative_to(root).as_posix(),
                            line_number,
                            f"artifact digest `{value}` must use external-artifact scope",
                        )
                    )
                    findings.append(
                        Finding(
                            "MALFORMED_RUN_ID",
                            path.relative_to(root).as_posix(),
                            line_number,
                            f"run identifier `{value}` must contain 7-12 decimal digits",
                        )
                    )
    present_keys: set[str] = set()
    for path in paths if paths is not None else current_documents(root):
        fenced = False
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if FENCE_RE.match(line):
                fenced = not fenced
                continue
            if fenced:
                continue
            for token, start, end, inline in _reference_candidates(line):
                if not HEX_TOKEN_RE.fullmatch(token) or len(token) < 7:
                    continue
                kind, value, malformed = _reference_kind_and_value(line, start, end, token)
                if not inline and token.isdigit():
                    kind, value, malformed = "run-id", token, None
                if not inline and token.isdigit():
                    kind, value, malformed = "run-id", token, None
                key = f"{kind}:{value}"
                if malformed and f"artifact-digest:{token.lower()}" in records:
                    key = f"artifact-digest:{token.lower()}"
                elif malformed:
                    continue
                if key in records:
                    present_keys.add(key)
                elif not malformed and token.isdigit() and 7 <= len(token) <= 12 and f"run-id:{token}" in records:
                    present_keys.add(f"run-id:{token}")
                elif not malformed and f"commit:{token.lower()}" in records:
                    present_keys.add(f"commit:{token.lower()}")
                elif not malformed and len(token) == 64 and f"artifact-digest:{token.lower()}" in records:
                    present_keys.add(f"artifact-digest:{token.lower()}")
    for key in sorted(set(records) - present_keys):
        findings.append(
            Finding(
                "SHA_MANIFEST_UNUSED",
                "<manifest>",
                1,
                f"manifest entry {key!r} has no matching token in the living documentation set; remove it or correct the reference",
            )
        )
    for key, record in records.items():
        kind, value = key.split(":", 1)
        if (
            kind == "commit"
            and record["repository"] == "groktopus/codereview"
            and record["scope"] in {"local", "historical-local"}
            and not _git_exists(root, value)
        ):
            if not any(f.code == "SHA_NOT_IN_REPOSITORY" and value in f.message for f in findings):
                findings.append(
                    Finding(
                        "SHA_NOT_IN_REPOSITORY",
                        "<manifest>",
                        1,
                        f"manifest local revision `{value}` is not a commit in this repository",
                    )
                )
    return findings


def _read_freshness_manifest(root: Path, path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read freshness evidence manifest {path}: {error}") from error
    if not isinstance(data, dict) or data.get("schema_version") != TRUTH_SCHEMA:
        raise ValueError(f"freshness manifest must use schema_version {TRUTH_SCHEMA!r}")
    return data


def check_status_freshness(root: Path, manifest_path: Path, head: str = "HEAD") -> list[Finding]:
    """Compare evidence revisions against declared relevant source paths."""

    manifest_path = manifest_path.resolve()
    if not manifest_path.is_relative_to(root.resolve()):
        raise ValueError("freshness manifest must be inside the repository")
    records = _read_freshness_manifest(root, manifest_path).get("documents")
    if not isinstance(records, list):
        raise ValueError("freshness manifest must contain a documents array")
    findings: list[Finding] = []
    for index, record in enumerate(records):
        prefix = f"documents[{index}]"
        if not isinstance(record, dict):
            findings.append(
                Finding(
                    "FRESHNESS_RECORD_INVALID",
                    manifest_path.relative_to(root).as_posix(),
                    1,
                    f"{prefix} must be an object",
                )
            )
            continue
        document, revision, evidence_date = (
            record.get("document"),
            record.get("evidence_revision"),
            record.get("evidence_date"),
        )
        sources, evidence_links = record.get("source_paths"), record.get("evidence_links")
        problems = []
        if not isinstance(document, str) or not (root / document).is_file():
            problems.append("document must name an existing repository-relative file")
        if (
            not isinstance(revision, str)
            or not re.fullmatch(r"[0-9a-fA-F]{40}", revision)
            or not _git_exists(root, revision)
        ):
            problems.append("evidence_revision must be an existing full 40-character commit SHA")
        try:
            date.fromisoformat(evidence_date)
        except (TypeError, ValueError):
            problems.append("evidence_date must be an ISO-8601 calendar date")
        if not isinstance(sources, list) or not sources or any(not isinstance(s, str) for s in sources):
            problems.append("source_paths must be a non-empty array of repository-relative paths")
        if (
            not isinstance(evidence_links, list)
            or not evidence_links
            or any(not isinstance(link, str) for link in evidence_links)
        ):
            problems.append("evidence_links must be a non-empty array of evidence link strings")
        if problems:
            findings.append(
                Finding(
                    "FRESHNESS_RECORD_INVALID",
                    manifest_path.relative_to(root).as_posix(),
                    1,
                    f"{prefix}: {'; '.join(problems)}",
                )
            )
            continue
        doc_path = (root / document).resolve()
        if not doc_path.is_relative_to(root.resolve()):
            findings.append(Finding("FRESHNESS_RECORD_INVALID", document, 1, "document path escapes repository"))
            continue
        doc_lines = doc_path.read_text(encoding="utf-8").splitlines()
        line = next((i for i, text in enumerate(doc_lines, 1) if revision.lower() in text.lower()), 1)
        for source in sources:
            source_path = (root / source).resolve()
            if not source_path.is_relative_to(root.resolve()) or not source_path.exists():
                findings.append(
                    Finding(
                        "FRESHNESS_RECORD_INVALID",
                        document,
                        line,
                        f"source path is missing or escapes repository: {source!r}",
                    )
                )
                continue
            latest_result = _git(root, "log", "-1", "--format=%H", head, "--", source)
            if latest_result.returncode:
                findings.append(
                    Finding(
                        "FRESHNESS_CHECK_ERROR",
                        document,
                        line,
                        f"cannot inspect latest source revision for {source!r}: {latest_result.stderr.strip()}",
                    )
                )
                continue
            latest = latest_result.stdout.strip()
            if latest and _git(root, "merge-base", "--is-ancestor", latest, revision).returncode != 0:
                findings.append(
                    Finding(
                        "STATUS_STALE",
                        document,
                        line,
                        f"evidence revision {revision[:12]} predates source {source!r} at {latest[:12]}; refresh the evidence or narrow source_paths to the documented claim",
                    )
                )
        for link in evidence_links:
            if link.startswith(("http://", "https://", "mailto:", "#")):
                continue
            destination = (doc_path.parent / link.split("#", 1)[0].split("?", 1)[0]).resolve()
            if not destination.is_relative_to(root.resolve()):
                findings.append(
                    Finding("FRESHNESS_RECORD_INVALID", document, line, f"evidence link escapes repository: {link!r}")
                )
            elif not destination.exists():
                findings.append(
                    Finding("FRESHNESS_EVIDENCE_MISSING", document, line, f"evidence link does not resolve: {link!r}")
                )
    return findings


def check_superseded_contracts(
    root: Path, paths: list[Path] | None = None, registry_path: Path | None = None, contract_ids: set[str] | None = None
) -> list[Finding]:
    registry_path = registry_path or root / "src" / "pr_review_harness" / "contract_registry.json"
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [
            Finding(
                "CONTRACT_REGISTRY_INVALID",
                registry_path.relative_to(root).as_posix(),
                1,
                f"cannot read contract registry: {error}",
            )
        ]
    deprecated = [entry.get("name") for entry in registry.get("contracts", []) if entry.get("status") == "deprecated"]
    findings: list[Finding] = []
    if contract_ids is not None:
        missing = sorted(set(deprecated) - contract_ids)
        extra = sorted(contract_ids - set(deprecated))
        if missing or extra:
            details = []
            if missing:
                details.append(f"missing deprecated IDs: {', '.join(missing)}")
            if extra:
                details.append(f"IDs no longer deprecated: {', '.join(extra)}")
            findings.append(
                Finding(
                    "CONTRACT_ID_SCOPE_DRIFT",
                    "scripts/documentation-contract-ids.v1.json",
                    1,
                    "; ".join(details) + "; regenerate the reviewed scope list",
                )
            )
        deprecated = [name for name in deprecated if name in contract_ids]
    for path in paths if paths is not None else current_documents(root):
        fenced = False
        in_deprecated_section = False
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.startswith("### "):
                in_deprecated_section = line[4:].strip().lower().startswith("deprecated contracts")
            elif line.startswith("## "):
                in_deprecated_section = False
            if FENCE_RE.match(line):
                fenced = not fenced
                continue
            if fenced:
                continue
            for name in deprecated:
                if not isinstance(name, str) or not re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", line):
                    continue
                # Dated historical subsections inside a current index target
                # remain records, not unqualified present-tense guidance.
                if in_deprecated_section or re.search(r"\b(?:deprecated|archived)\b", line, re.IGNORECASE):
                    continue
                findings.append(
                    Finding(
                        "SUPERSEDED_CONTRACT_UNMARKED",
                        path.relative_to(root).as_posix(),
                        number,
                        f"contract identifier `{name}` is deprecated in the registry; mark this reference as deprecated or archived",
                    )
                )
    return findings


def _read_contract_ids(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read contract identifier list {path}: {error}") from error
    ids = data.get("contract_ids") if isinstance(data, dict) else None
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != CONTRACT_SCHEMA
        or not isinstance(ids, list)
        or any(not isinstance(item, str) for item in ids)
    ):
        raise ValueError(
            f"contract identifier list must use schema_version {CONTRACT_SCHEMA!r} and a string contract_ids array"
        )
    return set(ids)


def run_checks(
    root: Path,
    sha_manifest: Path,
    contract_ids_path: Path,
    freshness_manifest: Path | None = None,
    document_paths: list[Path] | None = None,
) -> dict[str, Any]:
    paths = [path.resolve() for path in document_paths] if document_paths is not None else current_documents(root)
    for path in paths:
        if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"document path must be an existing repository file: {path}")
    findings = check_claims(root, paths)
    findings += check_shas(root, paths, sha_manifest)
    findings += check_superseded_contracts(root, paths, contract_ids=_read_contract_ids(contract_ids_path))
    if freshness_manifest is not None:
        findings += check_status_freshness(root, freshness_manifest)
    return {
        "schema_version": "docs-truth-report.v1",
        "documents_checked": [p.relative_to(root).as_posix() for p in paths],
        "findings": [f.as_dict() for f in findings],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--sha-manifest", type=Path, required=True, help="required provenance manifest for commit references"
    )
    parser.add_argument("--contract-ids", type=Path, required=True, help="versioned deprecated contract identifier set")
    parser.add_argument("--freshness-manifest", type=Path, help="optional OE-3-compatible document evidence records")
    parser.add_argument(
        "--document",
        action="append",
        type=Path,
        help="additional repository Markdown file to lint (repeatable; default: indexed living set)",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    paths = (args.sha_manifest, args.contract_ids, args.freshness_manifest)
    resolved = [root / item if item is not None and not item.is_absolute() else item for item in paths]
    sha_manifest, contract_ids, freshness = resolved
    documents = [root / item if not item.is_absolute() else item for item in (args.document or [])]
    try:
        result = run_checks(root, sha_manifest, contract_ids, freshness, documents or None)
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            f"Documentation truth: {len(result['documents_checked'])} living documents, {len(result['findings'])} finding(s)"
        )
        for finding in result["findings"]:
            print(f"  {finding['file']}:{finding['line']}: [{finding['code']}] {finding['message']}")
        if not result["findings"]:
            print("OK: no documentation truth findings")
    return 1 if result["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
