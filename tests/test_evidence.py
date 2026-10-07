import hashlib
import pickle
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from pr_review_harness.budget import _canonical as ipc_canonical
from pr_review_harness.evidence import ContextRetriever, EvidenceError, retrieve_context_gap


def git(path: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(path), *args], check=True, text=True, stdout=subprocess.PIPE)
    return result.stdout.strip()


def repository(tmp_path: Path):
    path = tmp_path / "repo"
    subprocess.run(["git", "init", str(path)], check=True, stdout=subprocess.DEVNULL)
    git(path, "config", "user.email", "fixture@example.invalid")
    git(path, "config", "user.name", "Fixture")
    (path / "src").mkdir()
    (path / "src" / "callers.py").write_text("def caller():\n    return target()\n")
    (path / "AGENTS.md").write_text("trusted rule\n")
    git(path, "add", "AGENTS.md", "src/callers.py")
    git(path, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git(path, "rev-parse", "HEAD")
    (path / "src" / "callers.py").write_text("def caller():\n    return target(1)\n")
    git(path, "add", "src/callers.py")
    git(path, "-c", "core.hooksPath=/dev/null", "commit", "-m", "head")
    head = git(path, "rev-parse", "HEAD")
    return path, base, head


def test_retrieval_reads_allowlisted_base_object_and_hashes_it(tmp_path):
    repo, base, head = repository(tmp_path)
    snapshot = {
        "snapshot_id": "snap-test",
        "base_sha": base,
        "head_sha": head,
        "inventory": [{"unit_id": "u1", "path": "src/callers.py"}],
    }
    proposal = {
        "evidence_kind": "caller",
        "target_path": "src/callers.py",
        "rationale": "Confirm base caller behavior",
        "required_lens": "correctness",
    }
    result = retrieve_context_gap(
        str(repo), snapshot, {"context_paths": ["src/*.py"]}, proposal, {"max_context_bytes": 1000}
    )
    assert result["status"] == "RESOLVED"
    assert "target()" in result["evidence"]["content"]
    assert result["evidence"]["source_revision"] == base
    assert result["evidence"]["source_object_id"]
    assert result["evidence"]["content_hash"]
    assert result["evidence"]["trust"] == "repository_evidence"


def test_retrieval_accepts_normalized_gap_and_binds_engine_proposal_identity(tmp_path):
    repo, base, head = repository(tmp_path)
    snapshot = {
        "snapshot_id": "snap-test",
        "base_sha": base,
        "head_sha": head,
        "inventory": [{"unit_id": "u1", "path": "src/callers.py"}],
    }
    proposal = {
        "_proposal_id": "task-1:gap:0",
        "_task_id": "task-1",
        "evidence_kind": "caller",
        "target": {"target_unit_id": "u1", "target_path": None, "target_symbol": None},
        "rationale": "Confirm base caller behavior",
        "required_lens": "correctness",
    }
    result = retrieve_context_gap(
        str(repo),
        snapshot,
        {"retrieval_context_patterns": ["src/*.py"]},
        proposal,
        {"max_context_bytes": 1000},
    )
    assert result["status"] == "RESOLVED"
    assert result["evidence"]["proposal_id"] == "task-1:gap:0"
    assert result["evidence"]["task_id"] == "task-1"
    assert result["evidence"]["path"] == "src/callers.py"


def test_manifest_bound_retrieval_requires_exact_source_revision_and_blob(tmp_path):
    repo, base, head = repository(tmp_path)
    snapshot = {
        "snapshot_id": "snap-test",
        "base_sha": base,
        "head_sha": head,
        "inventory": [{"unit_id": "u1", "path": "src/callers.py"}],
    }
    base_blob = git(repo, "rev-parse", f"{base}:src/callers.py")
    proposal = {
        "evidence_kind": "caller",
        "target_path": "src/callers.py",
        "rationale": "Confirm base caller behavior",
        "required_lens": "correctness",
        "_context_target_binding": {
            "choice_id": "a" * 24,
            "target_kind": "path",
            "target_value": "src/callers.py",
            "evidence_kind": "caller",
            "path": "src/callers.py",
            "source_sha": base,
            "source_object_id": base_blob,
            "source_object_format": "sha1",
            "snapshot_id": "snap-test",
        },
    }
    profile = {"retrieval_context_patterns": ["src/*.py"]}
    result = retrieve_context_gap(str(repo), snapshot, profile, proposal, {"max_context_bytes": 1000})
    assert result["status"] == "RESOLVED"
    assert result["evidence"]["source_revision"] == base
    assert result["evidence"]["source_object_id"] == base_blob

    mismatch = {
        **proposal,
        "_context_target_binding": {**proposal["_context_target_binding"], "source_object_id": "0" * 40},
    }
    rejected = retrieve_context_gap(str(repo), snapshot, profile, mismatch, {"max_context_bytes": 1000})
    assert rejected == {
        "status": "UNRESOLVED",
        "reason": "context_target_source_identity_mismatch",
        "evidence": None,
    }


def test_cli_retrieval_adapter_is_picklable_and_keeps_binding_out_of_identity():
    adapter = ContextRetriever("/private/local/object-store.git")
    restored = pickle.loads(pickle.dumps(adapter))
    assert restored._repo == "/private/local/object-store.git"


def test_retrieval_rejects_unallowlisted_traversal_and_bad_proposals(tmp_path):
    repo, base, head = repository(tmp_path)
    snapshot = {"snapshot_id": "snap-test", "base_sha": base, "head_sha": head, "inventory": []}
    profile = {"context_paths": ["AGENTS.md"]}
    limits = {"max_context_bytes": 100}
    proposal = {
        "evidence_kind": "contract",
        "target_path": "src/callers.py",
        "rationale": "Need context",
        "required_lens": "correctness",
    }
    result = retrieve_context_gap(str(repo), snapshot, profile, proposal, limits)
    assert result == {"status": "UNRESOLVED", "reason": "target_path_not_allowlisted", "evidence": None}
    proposal["target_path"] = "../AGENTS.md"
    assert retrieve_context_gap(str(repo), snapshot, profile, proposal, limits)["reason"] == "target_path_invalid"
    proposal["target_path"] = "AGENTS.md"
    with pytest.raises(EvidenceError):
        retrieve_context_gap(str(repo), snapshot, profile, {**proposal, "target_unit_id": "u"}, limits)


def test_retrieval_is_bounded_and_marks_partial_evidence(tmp_path):
    repo, base, head = repository(tmp_path)
    snapshot = {"snapshot_id": "snap-test", "base_sha": base, "head_sha": head, "inventory": []}
    proposal = {
        "evidence_kind": "contract",
        "target_path": "AGENTS.md",
        "rationale": "Need trusted rule",
        "required_lens": "project_specific",
    }
    result = retrieve_context_gap(
        str(repo), snapshot, {"context_paths": ["AGENTS.md"]}, proposal, {"max_context_bytes": 3}
    )
    assert result["status"] == "PARTIAL"
    assert result["evidence"]["content"] == "tru"
    assert result["evidence"]["truncated"] is True
    assert result["evidence"]["captured_bytes"] == 3


def test_byte_cap_ending_inside_valid_utf8_codepoint_keeps_complete_prefix(tmp_path):
    repo, base, head = repository(tmp_path)
    (repo / "AGENTS.md").write_bytes("AπB".encode("utf-8"))
    git(repo, "add", "AGENTS.md")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "unicode context")
    revision = git(repo, "rev-parse", "HEAD")
    result = retrieve_context_gap(
        str(repo),
        {"snapshot_id": "snap-test", "base_sha": revision, "head_sha": revision, "inventory": []},
        {"context_paths": ["AGENTS.md"]},
        {
            "evidence_kind": "contract",
            "target_path": "AGENTS.md",
            "rationale": "Need trusted context",
            "required_lens": "project_specific",
        },
        {"max_bytes": 2},
    )
    evidence = result["evidence"]
    assert result["status"] == "PARTIAL"
    assert evidence["content"] == "A"
    assert evidence["captured_bytes"] == 1
    assert evidence["content_hash"] == hashlib.sha256(b"A").hexdigest()


def test_invalid_utf8_context_fails_closed(tmp_path):
    repo, base, head = repository(tmp_path)
    (repo / "AGENTS.md").write_bytes(b"valid\xffinvalid")
    git(repo, "add", "AGENTS.md")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "invalid encoding")
    revision = git(repo, "rev-parse", "HEAD")
    result = retrieve_context_gap(
        str(repo),
        {"snapshot_id": "snap-test", "base_sha": revision, "head_sha": revision, "inventory": []},
        {"context_paths": ["AGENTS.md"]},
        {
            "evidence_kind": "contract",
            "target_path": "AGENTS.md",
            "rationale": "Need trusted context",
            "required_lens": "project_specific",
        },
        {"max_bytes": 100},
    )
    assert result == {"status": "UNRESOLVED", "reason": "retrieval_evidence_encoding_invalid", "evidence": None}


def test_only_explicit_policy_paths_receive_policy_trust(tmp_path):
    repo, base, head = repository(tmp_path)
    snapshot = {"snapshot_id": "snap-test", "base_sha": base, "head_sha": head, "inventory": []}
    proposal = {
        "evidence_kind": "contract",
        "target_path": "AGENTS.md",
        "rationale": "Need trusted repository policy",
        "required_lens": "project_specific",
    }
    result = retrieve_context_gap(
        str(repo),
        snapshot,
        {"retrieval_context_patterns": ["AGENTS.md"], "trusted_policy_paths": ["AGENTS.md"]},
        proposal,
        {"max_context_bytes": 100},
    )
    assert result["evidence"]["trust"] == "trusted_policy"


def test_retrieval_fits_complete_ipc_envelope_and_rebinds_multibyte_content(tmp_path, monkeypatch):
    import pr_review_harness.evidence as evidence_module

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 9, 27, tzinfo=timezone.utc)

    monkeypatch.setattr(evidence_module, "datetime", FrozenDatetime)
    repo, base, head = repository(tmp_path)
    payload = ("π and 漢字\n" * 5000)
    (repo / "AGENTS.md").write_text(payload, encoding="utf-8")
    git(repo, "add", "AGENTS.md")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "large trusted context")
    base = head = git(repo, "rev-parse", "HEAD")
    snapshot = {
        "snapshot_id": "snap-test",
        "base_sha": base,
        "head_sha": head,
        "repository_url": "https://example.invalid/repo",
        "inventory": [],
    }
    proposal = {
        "_proposal_id": "task-1:gap:0",
        "_task_id": "task-1",
        "evidence_kind": "contract",
        "target_path": "AGENTS.md",
        "rationale": "Need bounded trusted context",
        "required_lens": "project_specific",
    }
    limits = {"max_bytes": 100_000, "max_retrieval_bytes": 100_000, "context_bytes_remaining": 100_000}
    unbounded = retrieve_context_gap(str(repo), snapshot, {"context_paths": ["AGENTS.md"]}, proposal, limits)
    exact_boundary = retrieve_context_gap(
        str(repo),
        snapshot,
        {"context_paths": ["AGENTS.md"]},
        proposal,
        {**limits, "max_result_bytes": len(ipc_canonical(unbounded))},
    )
    cap = len(ipc_canonical(unbounded)) - 73
    first = retrieve_context_gap(
        str(repo), snapshot, {"context_paths": ["AGENTS.md"]}, proposal, {**limits, "max_result_bytes": cap}
    )
    second = retrieve_context_gap(
        str(repo), snapshot, {"context_paths": ["AGENTS.md"]}, proposal, {**limits, "max_result_bytes": cap}
    )

    assert first == second
    assert exact_boundary == unbounded
    assert len(ipc_canonical(exact_boundary)) == len(ipc_canonical(unbounded))
    assert first["status"] == "PARTIAL"
    assert first["reason"] == "ipc_envelope_truncated"
    assert len(ipc_canonical(first)) <= cap
    evidence = first["evidence"]
    raw = evidence["content"].encode("utf-8")
    assert raw.decode("utf-8") == evidence["content"]
    assert len(raw) == evidence["captured_bytes"] < len(payload.encode("utf-8"))
    assert evidence["truncated"] is True
    assert evidence["content_hash"] == hashlib.sha256(raw).hexdigest()
    expected_id = "ev-" + hashlib.sha256(
        ipc_canonical(
            {"snapshot_id": "snap-test", "revision": base, "path": "AGENTS.md", "hash": evidence["content_hash"]}
        )
    ).hexdigest()[:24]
    assert evidence["evidence_id"] == expected_id
    assert evidence["source_url"].endswith(f"#L1-L{max(len(evidence['content'].splitlines()), 1)}")


def test_retrieval_metadata_that_cannot_fit_fails_closed_without_trimming_fields(tmp_path):
    repo, base, head = repository(tmp_path)
    snapshot = {
        "snapshot_id": "snap-test",
        "base_sha": base,
        "head_sha": head,
        "repository_url": "https://example.invalid/" + ("x" * 2000),
        "inventory": [],
    }
    proposal = {
        "evidence_kind": "contract",
        "target_path": "AGENTS.md",
        "rationale": "Need trusted context",
        "required_lens": "project_specific",
    }
    result = retrieve_context_gap(
        str(repo),
        snapshot,
        {"context_paths": ["AGENTS.md"]},
        proposal,
        {"max_bytes": 1000, "max_result_bytes": 512},
    )
    assert result == {
        "status": "UNRESOLVED",
        "reason": "retrieval_metadata_exceeds_ipc_limit",
        "evidence": None,
    }
    assert len(ipc_canonical(result)) <= 512
