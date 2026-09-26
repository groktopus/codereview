import pickle
import subprocess
from pathlib import Path

import pytest

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
