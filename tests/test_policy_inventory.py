import copy
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from pr_review_harness.policy_inventory import PolicyInventoryError, build_policy_inventory
from pr_review_harness.snapshot import collect_snapshot


def _git(path: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(path), *args], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout.strip()


@pytest.fixture
def frozen_policy(tmp_path: Path):
    bare = tmp_path / "policy.git"
    work = tmp_path / "work"
    subprocess.run(["git", "init", "--bare", str(bare)], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "init", str(work)], check=True, stdout=subprocess.DEVNULL)
    _git(work, "config", "user.email", "fixture@example.invalid")
    _git(work, "config", "user.name", "Policy fixture")

    policy_bytes = "# Review 🛡️\r\n\r\n- Rule α\r\n  continuation\r\n\r\n## Child\r\nDo not omit.\r\n".encode()
    (work / "AGENTS.md").write_bytes(policy_bytes)
    (work / "ordinary.md").write_text("repository guidance is not profile policy\n")
    _git(work, "add", "AGENTS.md", "ordinary.md")
    _git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = _git(work, "rev-parse", "HEAD")
    _git(work, "remote", "add", "origin", str(bare))
    _git(work, "push", "origin", "HEAD:refs/heads/main")
    (work / "changed.py").write_text("value = 1\n")
    _git(work, "add", "changed.py")
    _git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "head")
    head = _git(work, "rev-parse", "HEAD")
    _git(work, "push", "origin", "HEAD:refs/heads/main")

    profile = {
        "version": "policy-inventory-test-v1",
        "context_paths": ["AGENTS.md", "ordinary.md"],
        "trusted_policy_paths": ["AGENTS.md"],
    }
    snapshot = collect_snapshot(str(bare), base, head, profile, {"max_context_bytes": 100_000})
    obligations = [
        {
            "obligation_id": "lens:security",
            "obligation_kind": "CHANGED_UNIT_LENS",
            "required": True,
            "scope_unit_ids": ["unit-1"],
            "lens": "security",
        },
        {
            "obligation_id": "check:policy",
            "obligation_kind": "PROJECT_CHECK",
            "required": True,
            "scope_unit_ids": [],
            "check_binding_id": "policy-check",
        },
    ]
    return bare, base, head, profile, snapshot, obligations, policy_bytes


def _reseal(snapshot):
    payload = {key: value for key, value in snapshot.items() if key not in {"snapshot_id", "snapshot_hash"}}
    snapshot["snapshot_hash"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return snapshot


def test_inventory_uses_only_profile_bound_policy_and_exactly_partitions_collector_bytes(frozen_policy):
    bare, base, _head, profile, snapshot, obligations, policy_bytes = frozen_policy

    inventory = build_policy_inventory(snapshot, profile, obligations, {})

    assert inventory["status"] == "COMPLETE"
    assert inventory["policy_sources"] and [source["path"] for source in inventory["policy_sources"]] == ["AGENTS.md"]
    source = inventory["policy_sources"][0]
    assert source["source_kind"] == "profile_context"
    assert source["source_revision"] == base
    assert source["git_object_format"] == "sha1"
    assert source["git_object_id"] == _git(bare, "rev-parse", f"{base}:AGENTS.md")
    assert source["full_source_sha256"] == hashlib.sha256(policy_bytes).hexdigest()

    clauses = inventory["clauses"]
    assert b"".join(clause["content"].encode("utf-8") for clause in clauses) == policy_bytes
    assert clauses[0]["byte_range"]["start_inclusive"] == 0
    assert clauses[-1]["byte_range"]["end_exclusive"] == len(policy_bytes)
    assert clauses[0]["line_range"] == {"start_inclusive": 1, "end_inclusive": 2}
    assert clauses[-1]["line_range"] == {"start_inclusive": 6, "end_inclusive": 7}
    assert all(
        clause["clause_bytes_sha256"] == hashlib.sha256(clause["content"].encode("utf-8")).hexdigest()
        for clause in clauses
    )
    assert all(clause["source_id"] == source["source_id"] for clause in clauses)

    trace = inventory["applicability_trace"]
    assert len(trace) == len(clauses) * len(obligations)
    assert {row["state"] for row in trace} == {"UNRESOLVED"}
    assert inventory["trace_summary"]["complete"] is True
    assert inventory["trace_summary"]["applicability_complete"] is False
    assert inventory["trace_summary"]["state_counts"]["UNRESOLVED"] == len(trace)


def test_absent_explicit_policy_source_is_a_gap_even_without_snapshot_gap_record(frozen_policy):
    _bare, _base, _head, profile, snapshot, obligations, _bytes = frozen_policy
    policy_id = next(eid for eid, item in snapshot["evidence"].items() if item["path"] == "AGENTS.md")
    snapshot["trusted_context_refs"].remove(policy_id)
    del snapshot["evidence"][policy_id]
    snapshot["gaps"] = []
    _reseal(snapshot)

    inventory = build_policy_inventory(snapshot, profile, obligations, {})

    assert inventory["status"] == "GAP"
    assert inventory["trace_summary"]["expected_rows"] == 0
    assert inventory["trace_summary"]["complete"] is False
    assert inventory["trace_summary"]["applicability_complete"] is False
    assert any(
        gap["reason"] == "trusted_policy_source_not_captured" and gap["path"] == "AGENTS.md"
        for gap in inventory["gaps"]
    )


def test_repository_evidence_cannot_self_promote_with_trust_label(frozen_policy):
    _bare, _base, _head, profile, snapshot, obligations, _bytes = frozen_policy
    ordinary_id = next(eid for eid, item in snapshot["evidence"].items() if item["path"] == "ordinary.md")
    ordinary = snapshot["evidence"][ordinary_id]
    ordinary["trust"] = "trusted_policy"
    profile["trusted_policy_paths"] = ["AGENTS.md"]
    _reseal(snapshot)
    # The profile hash still binds its policy path; only the snapshot's bound
    # trust label for ordinary evidence was changed and resealed.
    inventory = build_policy_inventory(snapshot, profile, obligations, {})

    assert all(source["path"] != "ordinary.md" for source in inventory["policy_sources"])
    assert inventory["status"] == "COMPLETE"
    assert inventory["trace_summary"]["applicability_complete"] is False


def test_snapshot_or_profile_mutation_is_rejected(frozen_policy):
    _bare, _base, _head, profile, snapshot, obligations, _bytes = frozen_policy
    changed = dict(profile)
    changed["trusted_policy_paths"] = ["ordinary.md"]
    with pytest.raises(PolicyInventoryError, match="profile_hash_mismatch"):
        build_policy_inventory(snapshot, changed, obligations, {})

    snapshot["snapshot_hash"] = "0" * 64
    with pytest.raises(PolicyInventoryError, match="snapshot_hash_mismatch"):
        build_policy_inventory(snapshot, profile, obligations, {})


def test_wrong_git_object_identity_and_truncated_source_fail_closed(frozen_policy):
    _bare, _base, _head, profile, snapshot, obligations, _bytes = frozen_policy
    policy_id = next(eid for eid, item in snapshot["evidence"].items() if item["path"] == "AGENTS.md")
    snapshot["evidence"][policy_id]["source_object_id"] = "0" * 40
    _reseal(snapshot)

    inventory = build_policy_inventory(snapshot, profile, obligations, {})

    assert inventory["status"] == "GAP"
    assert not inventory["policy_sources"]
    assert any(gap["reason"] == "source_git_object_mismatch" for gap in inventory["gaps"])


def test_clause_and_trace_caps_report_incomplete_denominators(frozen_policy):
    _bare, _base, _head, profile, snapshot, obligations, _bytes = frozen_policy
    capped_clauses = build_policy_inventory(snapshot, profile, obligations, {"max_clauses": 1})
    assert capped_clauses["status"] == "COMPLETE"
    assert len(capped_clauses["clauses"]) == 1
    assert capped_clauses["clauses"][0]["byte_range"] == {"start_inclusive": 0, "end_exclusive": len(_bytes)}
    assert capped_clauses["clauses"][0]["extract_kind"] == "whole_blob"
    assert b"".join(clause["content"].encode() for clause in capped_clauses["clauses"]) == _bytes

    capped_trace = build_policy_inventory(snapshot, profile, obligations, {"max_trace_rows": 1})
    assert capped_trace["status"] == "GAP"
    assert capped_trace["trace_summary"]["expected_rows"] == len(capped_trace["clauses"]) * len(obligations)
    assert capped_trace["trace_summary"]["emitted_rows"] == 0
    assert capped_trace["trace_summary"]["complete"] is False
    assert capped_trace["trace_summary"]["applicability_complete"] is False

    byte_capped_trace = build_policy_inventory(snapshot, profile, obligations, {"max_trace_bytes": 1})
    assert byte_capped_trace["status"] == "GAP"
    assert byte_capped_trace["trace_summary"]["expected_rows"] == len(byte_capped_trace["clauses"]) * len(obligations)
    assert byte_capped_trace["trace_summary"]["emitted_rows"] == 0
    assert any(gap["reason"] == "trace_output_limit_exceeded" for gap in byte_capped_trace["gaps"])


def test_source_count_and_input_byte_caps_surface_typed_gaps(frozen_policy):
    bare, base, head, _profile, _snapshot, obligations, _bytes = frozen_policy
    profile = {
        "version": "two-policy-source-v1",
        "context_paths": ["AGENTS.md", "ordinary.md"],
        "trusted_policy_paths": ["AGENTS.md", "ordinary.md"],
    }
    snapshot = collect_snapshot(str(bare), base, head, profile, {"max_context_bytes": 100_000})

    source_limited = build_policy_inventory(snapshot, profile, obligations, {"max_sources": 1})
    assert source_limited["status"] == "GAP"
    assert any(gap["reason"] == "source_count_limit_exceeded" for gap in source_limited["gaps"])
    assert source_limited["trace_summary"]["complete"] is False

    byte_limited = build_policy_inventory(snapshot, profile, obligations, {"max_input_bytes": 4})
    assert byte_limited["status"] == "GAP"
    assert any(
        gap["reason"] in {"source_byte_limit_exceeded", "aggregate_input_byte_limit_exceeded"}
        for gap in byte_limited["gaps"]
    )
    assert byte_limited["trace_summary"]["applicability_complete"] is False


def test_explicit_profile_rule_resolves_only_its_exact_clause_obligation_pair(frozen_policy):
    bare, base, head, profile, snapshot, obligations, _bytes = frozen_policy
    initial = build_policy_inventory(snapshot, profile, obligations, {})
    clause = initial["clauses"][0]
    policy_oid = clause["source_object_id"]
    profile["policy_applicability_rules"] = [
        {
            "rule_id": "security-policy-v1",
            "rule_version": "1",
            "reviewed": True,
            "source_path": clause["path"],
            "source_revision": clause["source_revision"],
            "source_git_object_id": policy_oid,
            "clause_bytes_sha256": clause["clause_bytes_sha256"],
            "obligation_id": obligations[0]["obligation_id"],
            "state": "APPLICABLE",
            "basis_git_object_ids": [policy_oid],
        }
    ]
    snapshot = collect_snapshot(str(bare), base, head, profile, {"max_context_bytes": 100_000})

    inventory = build_policy_inventory(snapshot, profile, obligations, {})

    new_clause = next(
        item for item in inventory["clauses"] if item["clause_bytes_sha256"] == clause["clause_bytes_sha256"]
    )
    matching = next(
        row
        for row in inventory["applicability_trace"]
        if row["clause_id"] == new_clause["clause_id"] and row["obligation_id"] == obligations[0]["obligation_id"]
    )
    other = next(
        row
        for row in inventory["applicability_trace"]
        if row["clause_id"] == new_clause["clause_id"] and row["obligation_id"] == obligations[1]["obligation_id"]
    )
    assert matching["state"] == "APPLICABLE"
    assert matching["rule_id"] == "security-policy-v1"
    assert matching["basis_evidence_ids"]
    assert other["state"] == "UNRESOLVED"


def test_conflicting_rules_remain_unresolved(frozen_policy):
    bare, base, head, profile, snapshot, obligations, _bytes = frozen_policy
    initial = build_policy_inventory(snapshot, profile, obligations, {})
    clause = initial["clauses"][0]
    shared = {
        "reviewed": True,
        "source_path": clause["path"],
        "source_revision": clause["source_revision"],
        "source_git_object_id": clause["source_object_id"],
        "clause_bytes_sha256": clause["clause_bytes_sha256"],
        "obligation_id": obligations[0]["obligation_id"],
        "basis_git_object_ids": [clause["source_object_id"]],
    }
    profile["policy_applicability_rules"] = [
        {**shared, "rule_id": "rule-a", "rule_version": "1", "state": "APPLICABLE"},
        {**shared, "rule_id": "rule-b", "rule_version": "1", "state": "NOT_APPLICABLE"},
    ]
    snapshot = collect_snapshot(str(bare), base, head, profile, {"max_context_bytes": 100_000})

    inventory = build_policy_inventory(snapshot, profile, obligations, {})
    new_clause = next(
        item for item in inventory["clauses"] if item["clause_bytes_sha256"] == clause["clause_bytes_sha256"]
    )
    matching = next(
        row
        for row in inventory["applicability_trace"]
        if row["clause_id"] == new_clause["clause_id"] and row["obligation_id"] == obligations[0]["obligation_id"]
    )
    assert matching["state"] == "UNRESOLVED"
    assert matching["reason_code"] == "multiple_matching_rules"


def test_wildcard_trust_binding_does_not_claim_complete_source_inventory(frozen_policy):
    bare, base, head, _profile, _snapshot, obligations, _bytes = frozen_policy
    profile = {
        "version": "wildcard-policy-v1",
        "context_paths": ["AGENTS.md", "ordinary.md"],
        "trusted_policy_paths": ["*.md"],
    }
    snapshot = collect_snapshot(str(bare), base, head, profile, {"max_context_bytes": 100_000})

    inventory = build_policy_inventory(snapshot, profile, obligations, {})

    assert inventory["status"] == "GAP"
    assert any(gap["reason"] == "trusted_policy_pattern_source_coverage_unresolved" for gap in inventory["gaps"])


def test_shared_json_alias_is_allowed_but_cycles_are_rejected(frozen_policy):
    _bare, _base, _head, profile, _snapshot, obligations, _bytes = frozen_policy
    shared = {"value": "allowed"}
    profile["metadata"] = [shared, shared]
    # Rebuild through collector, which also updates IDs bound to the snapshot.
    bare, base, head, *_ = frozen_policy
    snapshot = collect_snapshot(str(bare), base, head, profile, {"max_context_bytes": 100_000})
    assert build_policy_inventory(snapshot, profile, obligations, {})["status"] == "COMPLETE"

    cycle = []
    cycle.append(cycle)
    profile["cycle"] = cycle
    with pytest.raises(PolicyInventoryError, match="cyclic_input"):
        build_policy_inventory(snapshot, profile, obligations, {})


def test_inventory_accepts_only_valid_event_wrapped_snapshot_identity(frozen_policy):
    _bare, _base, _head, profile, snapshot, obligations, _policy_bytes = frozen_policy
    wrapped = copy.deepcopy(snapshot)
    event_identity = {
        "base_snapshot_id": wrapped["snapshot_id"],
        "repository": "owner/project",
        "pull_request_number": 7,
        "event_id": "github-pr:owner/project#7:head-sha",
    }
    wrapped["snapshot_id"] = "snap-" + hashlib.sha256(json.dumps(event_identity, sort_keys=True).encode()).hexdigest()[:24]
    old_to_new = {}
    for evidence_id, item in wrapped["evidence"].items():
        new_id = "ev-" + hashlib.sha256(
            json.dumps(
                {"snapshot": wrapped["snapshot_id"], "old_evidence_id": evidence_id, "content_hash": item["content_hash"]},
                sort_keys=True,
            ).encode()
        ).hexdigest()[:24]
        item["evidence_id"] = new_id
        item["snapshot_id"] = wrapped["snapshot_id"]
        old_to_new[evidence_id] = new_id
    wrapped["evidence"] = {old_to_new[key]: value for key, value in wrapped["evidence"].items()}
    from pr_review_harness.cli import _rebind_snapshot_evidence_references

    _rebind_snapshot_evidence_references(wrapped, old_to_new)
    wrapped.update({key: event_identity[key] for key in ("repository", "pull_request_number", "event_id")})
    _reseal(wrapped)
    assert build_policy_inventory(wrapped, profile, obligations, {"max_sources": 20})["policy_sources"]

    forged = copy.deepcopy(wrapped)
    forged["snapshot_id"] = "snap-" + "0" * 24
    _reseal(forged)
    with pytest.raises(PolicyInventoryError, match="snapshot_id_mismatch"):
        build_policy_inventory(forged, profile, obligations, {"max_sources": 20})
