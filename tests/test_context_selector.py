from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from pr_review_harness.context_selector import ContextSelectionError, select_policy_section
from pr_review_harness.snapshot import collect_snapshot


def _git(path: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(path), *args], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout.strip()


@pytest.fixture
def policy_snapshot(tmp_path: Path):
    source = (
        "# Guide 🛡️\r\n\r\n"
        "## Access\r\n\r\n"
        "First policy paragraph.\r\n\r\n"
        "### Exceptions\r\n\r\n"
        "Nested policy α.\r\n\r\n"
        "## Access\r\n\r\n"
        "Second policy paragraph.\r\n"
    ).encode("utf-8")
    return _make_snapshot(tmp_path, source)


def _make_snapshot(tmp_path: Path, source: bytes):
    bare = tmp_path / "policy.git"
    work = tmp_path / "work"
    subprocess.run(["git", "init", "--bare", str(bare)], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "init", str(work)], check=True, stdout=subprocess.DEVNULL)
    _git(work, "config", "user.email", "fixture@example.invalid")
    _git(work, "config", "user.name", "Selector fixture")
    (work / "AGENTS.md").write_bytes(source)
    (work / "changed.py").write_text("value = 1\n", encoding="utf-8")
    _git(work, "add", "AGENTS.md", "changed.py")
    _git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = _git(work, "rev-parse", "HEAD")
    _git(work, "remote", "add", "origin", str(bare))
    _git(work, "push", "origin", "HEAD:refs/heads/main")
    (work / "changed.py").write_text("value = 2\n", encoding="utf-8")
    _git(work, "add", "changed.py")
    _git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "head")
    head = _git(work, "rev-parse", "HEAD")
    _git(work, "push", "origin", "HEAD:refs/heads/main")
    profile = {
        "version": "context-selector-test-v1",
        "context_paths": ["AGENTS.md"],
        "trusted_policy_paths": ["AGENTS.md"],
    }
    snapshot = collect_snapshot(str(bare), base, head, profile, {"max_context_bytes": 100_000})
    evidence_id = next(eid for eid, item in snapshot["evidence"].items() if item["path"] == "AGENTS.md")
    return snapshot, profile, evidence_id, source


def _selector(*parts: str, occurrence: int = 1, include_subsections: bool = True):
    return {
        "schema_version": "policy-section-selector.v1",
        "heading_path": list(parts),
        "occurrence": occurrence,
        "include_subsections": include_subsections,
    }


def test_section_selection_preserves_exact_unicode_crlf_bytes_and_provenance(policy_snapshot):
    snapshot, profile, evidence_id, source = policy_snapshot

    result = select_policy_section(snapshot, profile, evidence_id, _selector("Guide 🛡️", "Access"))

    assert result["status"] == "SELECTED"
    assert result["content"].encode("utf-8") == (
        b"## Access\r\n\r\nFirst policy paragraph.\r\n\r\n### Exceptions\r\n\r\nNested policy \xce\xb1.\r\n\r\n"
    )
    start = result["byte_range"]["start_inclusive"]
    end = result["byte_range"]["end_exclusive"]
    assert source[start:end] == result["content"].encode("utf-8")
    assert result["provenance"]["source_revision"] == snapshot["base_sha"]
    assert result["provenance"]["git_object_id"] == snapshot["evidence"][evidence_id]["source_object_id"]
    assert result["provenance"]["full_source_sha256"] == hashlib.sha256(source).hexdigest()
    assert result["line_range"] == {"start_inclusive": 3, "end_inclusive": 10}


def test_duplicate_heading_uses_explicit_occurrence_and_exact_path(policy_snapshot):
    snapshot, profile, evidence_id, _ = policy_snapshot

    result = select_policy_section(
        snapshot,
        profile,
        evidence_id,
        _selector("Guide 🛡️", "Access", occurrence=2),
    )

    assert result["status"] == "SELECTED"
    assert result["occurrence"] == 2
    assert result["content"] == "## Access\r\n\r\nSecond policy paragraph.\r\n"


def test_section_without_subsections_stops_at_first_nested_heading(policy_snapshot):
    snapshot, profile, evidence_id, _ = policy_snapshot

    result = select_policy_section(
        snapshot,
        profile,
        evidence_id,
        _selector("Guide 🛡️", "Access", include_subsections=False),
    )

    assert result["status"] == "SELECTED"
    assert "First policy paragraph." in result["content"]
    assert "### Exceptions" not in result["content"]


@pytest.mark.parametrize(
    ("source", "expected_reason"),
    [
        (b"# Guide\n\n```md\n## Access\n```\n", "heading_occurrence_not_found"),
        (b"Guide\n=====\n\n## Access\n", "unsupported_setext_heading"),
        (b"# Guide\n<h2>Access</h2>\n", "unsupported_html_block"),
        (b"# Guide\n\n```\n## Access\n", "unclosed_fence_unsupported"),
    ],
)
def test_unsupported_or_fenced_markdown_requests_full_source(tmp_path, source, expected_reason):
    snapshot, profile, evidence_id, _ = _make_snapshot(tmp_path, source)
    result = select_policy_section(snapshot, profile, evidence_id, _selector("Guide", "Access"))
    assert result["status"] == "FULL_SOURCE_REQUIRED"
    assert result["reason"] == expected_reason


def test_mixed_fence_markers_cannot_close_a_fence(tmp_path):
    snapshot, profile, evidence_id, _ = _make_snapshot(tmp_path, b"# Guide\n```md\n## Access\n~~~\n## Access\n")

    result = select_policy_section(snapshot, profile, evidence_id, _selector("Guide", "Access"))

    assert result["status"] == "FULL_SOURCE_REQUIRED"
    assert result["reason"] == "unclosed_fence_unsupported"


def test_selector_metadata_is_bounded_before_hashing(policy_snapshot):
    snapshot, profile, evidence_id, _ = policy_snapshot
    too_deep = _selector(*(["x"] * 7))
    too_large = _selector("x" * 513)
    too_many_matches = _selector("Guide 🛡️", "Access", occurrence=1001)

    for selector in (too_deep, too_large, too_many_matches):
        with pytest.raises(ContextSelectionError):
            select_policy_section(snapshot, profile, evidence_id, selector)


def test_exact_trusted_path_required_even_when_wildcard_matches(policy_snapshot):
    snapshot, profile, evidence_id, _ = policy_snapshot
    profile["trusted_policy_paths"] = ["*.md"]

    result = select_policy_section(snapshot, profile, evidence_id, _selector("Guide 🛡️", "Access"))

    assert result["status"] == "FULL_SOURCE_REQUIRED"
    assert result["reason"] == "source_not_bound_by_exact_trusted_policy_path"


def test_section_and_heading_limits_fail_closed_to_full_source(policy_snapshot):
    snapshot, profile, evidence_id, _ = policy_snapshot
    section = select_policy_section(
        snapshot,
        profile,
        evidence_id,
        _selector("Guide 🛡️", "Access"),
        {"max_section_bytes": 8},
    )
    headings = select_policy_section(
        snapshot,
        profile,
        evidence_id,
        _selector("Guide 🛡️", "Access"),
        {"max_headings": 1},
    )

    assert section["reason"] == "section_byte_limit_exceeded"
    assert headings["reason"] == "heading_count_limit_exceeded"
    with pytest.raises(ContextSelectionError, match="max_source_bytes_invalid"):
        select_policy_section(snapshot, profile, evidence_id, _selector("Guide 🛡️", "Access"), {"max_source_bytes": 0})
    with pytest.raises(ContextSelectionError, match="limits_invalid"):
        select_policy_section(snapshot, profile, evidence_id, _selector("Guide 🛡️", "Access"), [])
