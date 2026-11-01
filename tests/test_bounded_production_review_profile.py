"""Keep the bounded v16 capacity candidate separate from frozen trial policy."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

from pr_review_harness.claim_assessment import ClaimAssessmentAdapter
from pr_review_harness.claim_reconciliation import validate_claim_reconciliation_policy
from pr_review_harness.claim_transport import ClaimTransport
from pr_review_harness.cli import _limits
from pr_review_harness.engine import (
    _evidence_for,
    effective_task_input_ceiling,
    prepare_plan_tasks,
    validate_limits,
)
from pr_review_harness.evidence import ContextRetriever
from pr_review_harness.planner import plan_review, validate_context_selection, validate_profile_lenses
from pr_review_harness.providers import make_provider
from pr_review_harness.snapshot import collect_snapshot

ROOT = Path(__file__).resolve().parents[1]
V14 = ROOT / "profiles/slopsearx-v14-jev-reconciliation-candidate.json"
V16 = ROOT / "profiles/slopsearx-v16-bounded-production-candidate.json"
LIMITS_V3 = ROOT / "profiles/ordinary-review-limits-v3.json"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, text=True, stdout=subprocess.PIPE
    ).stdout.strip()


def _native_candidate() -> dict:
    return {
        "candidate_id": "capacity-candidate",
        "title": "A bounded candidate",
        "observation": "The handler forwards an unchecked value.",
        "consequence": "A malformed value may raise an exception.",
        "rule_or_contract": "The input contract requires validation.",
        "evidence_refs": ["ev-head"],
    }


def _native_evidence() -> dict:
    content = "The handler forwards the value without validation."
    return {
        "evidence_id": "ev-head",
        "source_kind": "repository_file",
        "content": content,
        "content_hash": hashlib.sha256(content.encode()).hexdigest(),
        "trust": "repository_evidence",
        "path": "src/handler.py",
        "source_revision": "b" * 40,
        "snapshot_id": "snapshot-v16",
        "line": 12,
    }


def _native_identity() -> dict:
    return {
        "snapshot_id": "snapshot-v16",
        "snapshot_hash": "1" * 64,
        "profile_id": "profile-v16",
        "profile_hash": "2" * 64,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "change_base_sha": "a" * 40,
    }


def _primary_assessment() -> dict:
    return {
        "contract_version": "semantic-adjudication.v3",
        "source_contract_version": "semantic-adjudication.v3",
        "outcome": "SUPPORTED",
        "observation_support": "SUPPORTED",
        "consequence_support": "NOT_ESTABLISHED",
        "rule_connection_support": "SUPPORTED",
        "introducedness": "INTRODUCED",
        "evidence_refs": ["ev-head"],
        "assumptions": [],
        "uncertainties": [],
        "summary": "Provider-free sizing fixture only.",
        "material_consequence": False,
        "causal_roles": {
            role: {
                "support": "SUPPORTED",
                "assessment": f"Assessment of {role}.",
                "evidence_refs": ["ev-head"],
            }
            for role in ("behavior", "consumer", "impact")
        },
    }


def test_v16_profile_changes_only_the_approved_capacity_and_retrieval_fields() -> None:
    prior = json.loads(V14.read_text())
    candidate = json.loads(V16.read_text())
    expected = copy.deepcopy(prior)
    expected["version"] = "slopsearx-production-v16-bounded-production-candidate"
    expected["profile_status"] = "bounded_production_capacity_candidate_not_quality_validated"
    expected["context_selection"]["version"] = "context-selection.v3"
    expected["context_selection"]["max_total_context_bytes"] = 128_000
    expected["retrieval_revisions"] = {"implementation": "head", "test": "head"}
    expected["claim_reconciliation"]["max_assessments"] = 4
    expected["risk_rules"].insert(
        0,
        {
            "lenses": ["security", "correctness", "tests"],
            "min_mode": "FOCUSED",
            "patterns": ["engines/*.py"],
            "reason": (
                "Network-client adapters cross credential, upstream-input, and remote-service trust boundaries "
                "and need explicit security, correctness, and test review."
            ),
        }
    )
    assert candidate == expected
    for field in (
        "rules",
        "required_lenses",
        "required_checks",
        "trusted_policy_paths",
        "context_paths",
        "classifications",
    ):
        assert candidate[field] == prior[field]
    assert validate_claim_reconciliation_policy(candidate)["max_assessments"] == 4
    validate_profile_lenses(candidate)
    assert validate_context_selection(candidate) == candidate["context_selection"]


def test_limits_v3_preserves_defaults_and_sets_explicit_bounded_capacity() -> None:
    limits = json.loads(LIMITS_V3.read_text())
    expected = _limits()
    expected.update(
        {
            "max_provider_calls": 32,
            "max_context_bytes": 2_500_000,
            "max_input_bytes_per_task": 96_000,
            "max_output_bytes_per_task": 16_000,
            "max_output_bytes": 512_000,
            "max_snapshot_context_bytes": 600_000,
        }
    )
    assert limits == {"schema_version": "1.0", **expected}
    validate_limits({key: value for key, value in limits.items() if key != "schema_version"})
    assert limits["max_retries_per_task"] == 0
    assert limits["deadline_seconds"] == 300
    assert limits["max_concurrent_scopes"] == 3


def test_head_retrieval_never_promotes_a_policy_path_to_trusted_policy(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "config", "user.name", "Fixture")
    (repo / "AGENTS.md").write_text("Trusted baseline policy.\n", encoding="utf-8")
    (repo / "slopsearx").mkdir()
    (repo / "slopsearx" / "config.py").write_text("def request(): return 'base'\n", encoding="utf-8")
    _git(repo, "add", "AGENTS.md", "slopsearx/config.py")
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    (repo / "AGENTS.md").write_text("Untrusted PR policy replacement.\n", encoding="utf-8")
    (repo / "slopsearx" / "config.py").write_text("def request(): return 'head'\n", encoding="utf-8")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_config.py").write_text("def test_request(): assert request()\n", encoding="utf-8")
    _git(repo, "add", "AGENTS.md", "slopsearx/config.py", "tests/test_config.py")
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")

    profile = json.loads(V16.read_text())
    snapshot = {
        "snapshot_id": "snap-v16-policy-boundary",
        "base_sha": base,
        "head_sha": head,
        "inventory": [
            {"unit_id": "adapter", "path": "slopsearx/config.py"},
            {"unit_id": "adapter-test", "path": "tests/test_config.py"},
        ],
    }
    retriever = ContextRetriever(str(repo))
    for kind, path, revision, expected_text, expected_trust in (
        ("implementation", "slopsearx/config.py", head, "'head'", "repository_evidence"),
        ("test", "tests/test_config.py", head, "test_request", "repository_evidence"),
        ("contract", "AGENTS.md", base, "Trusted baseline policy.", "trusted_policy"),
        # Model-proposed evidence kind cannot confer trusted-policy status.
        ("implementation", "AGENTS.md", head, "Untrusted PR policy", "repository_evidence"),
    ):
        result = retriever(
            snapshot,
            profile,
            {
                "evidence_kind": kind,
                "target_path": path,
                "rationale": "Resolve bounded source context",
                "required_lens": "correctness",
            },
            {
                "max_bytes": 4096,
                "max_retrieval_bytes": 4096,
                "context_bytes_remaining": 4096,
                "deadline_seconds": 5,
            },
        )
        assert result["status"] == "RESOLVED", result
        evidence = result["evidence"]
        assert evidence["source_revision"] == revision
        assert evidence["path"] == path
        assert evidence["source_object_id"] == _git(repo, "rev-parse", f"{revision}:{path}")
        assert evidence["content_hash"] == hashlib.sha256(evidence["content"].encode("utf-8")).hexdigest()
        assert expected_text in evidence["content"]
        assert evidence["trust"] == expected_trust


def test_native_choice_quote_is_clamped_to_the_v16_task_output_limit() -> None:
    limits = json.loads(LIMITS_V3.read_text())
    request_limits = {
        "max_input_bytes_per_task": limits["max_input_bytes_per_task"],
        "max_output_bytes_per_task": limits["max_output_bytes_per_task"],
        # The engine gives each native quote a fresh bounded sub-deadline.
        "deadline_seconds": 8,
    }
    candidate = _native_candidate()
    evidence = [_native_evidence()]
    identity = _native_identity()

    bounded_transport = ClaimTransport(
        {
            "model": "jev-latest",
            "api_key_env": "UNUSED_CAPACITY_TEST_KEY",
            "max_request_bytes": 64_000,
            "max_response_bytes": 16_000,
        }
    )
    bounded = ClaimAssessmentAdapter(bounded_transport, "jev-latest")
    prepared = bounded.prepare(
        candidate,
        evidence,
        identity,
        request_limits,
        primary_assessment=_primary_assessment(),
    )
    quote = bounded.estimate_prepared(prepared, request_limits)
    assert quote["provider_calls"] == 1
    assert quote["input_bytes"] == len(prepared.request_bytes) <= 64_000
    assert quote["provider_response_bytes"] == 16_000
    assert quote["max_output_bytes"] == limits["max_output_bytes_per_task"]

    oversized_transport = ClaimTransport(
        {
            "model": "jev-latest",
            "api_key_env": "UNUSED_CAPACITY_TEST_KEY",
            "max_request_bytes": 64_000,
            "max_response_bytes": 64_000,
        }
    )
    oversized = ClaimAssessmentAdapter(oversized_transport, "jev-latest")
    oversized_prepared = oversized.prepare(
        candidate,
        evidence,
        identity,
        request_limits,
        primary_assessment=_primary_assessment(),
    )
    oversized_quote = oversized.estimate_prepared(oversized_prepared, request_limits)
    assert oversized_quote["provider_response_bytes"] == limits["max_output_bytes_per_task"]
    assert oversized_quote["max_output_bytes"] == limits["max_output_bytes_per_task"]


def test_small_and_deep_added_sources_use_v16_splitter_with_bounded_preparation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "config", "user.name", "Fixture")
    (repo / "AGENTS.md").write_text("Baseline policy.\n", encoding="utf-8")
    (repo / "CONTRIBUTING.md").write_text("Baseline guide.\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'fixture'\n", encoding="utf-8")
    _git(repo, "add", "AGENTS.md", "CONTRIBUTING.md", "pyproject.toml")
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    (repo / "engines").mkdir()
    small = "VALUE = 1\n" * 8
    deep = "VALUE = 1  # bounded source line for the large added file\n" * 520
    (repo / "engines" / "small.py").write_text(small, encoding="utf-8")
    (repo / "engines" / "deep.py").write_text(deep, encoding="utf-8")
    _git(repo, "add", "engines/small.py", "engines/deep.py")
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "add source")
    head = _git(repo, "rev-parse", "HEAD")

    profile = json.loads(V16.read_text())
    limits = json.loads(LIMITS_V3.read_text())
    limits.pop("schema_version")
    snapshot = collect_snapshot(str(repo), base, head, profile, limits, pr_diff=True)
    for path, expected in (("engines/small.py", small), ("engines/deep.py", deep)):
        rows = sorted(
            (
                item
                for item in snapshot["evidence"].values()
                if item.get("source_kind") == "source_window" and item.get("path") == path
            ),
            key=lambda item: item["line_start"],
        )
        assert rows
        assert "".join(item["content"] for item in rows) == expected
        assert all(len(item["content"].encode("utf-8")) <= 12_000 for item in rows)
        assert all(item["source_revision"] == head for item in rows)
        assert all(item["source_object_id"] == _git(repo, "rev-parse", f"{head}:{path}") for item in rows)
        assert all(
            item["content_hash"] == hashlib.sha256(item["content"].encode("utf-8")).hexdigest()
            for item in rows
        )

    required_source_gaps = [
        gap for gap in snapshot["gaps"] if gap.get("required") and gap.get("source_kind") == "source_window"
    ]
    assert not required_source_gaps
    plan = plan_review(snapshot, profile, "AUTO")
    obligations = plan["coverage_obligations"]
    for path in ("engines/small.py", "engines/deep.py"):
        unit_id = next(unit["unit_id"] for unit in snapshot["inventory"] if unit["path"] == path)
        assert any(
            obligation.get("lens") == "security" and unit_id in obligation.get("scope_unit_ids", [])
            for obligation in obligations
        )
    provider = make_provider(
        {
            "kind": "openai_compatible",
            "base_url": "https://example.invalid/v1",
            "model": "prepare-only-fixture",
            "api_key_env": "PREPARE_ONLY_NO_CREDENTIAL",
            "max_request_bytes": limits["max_input_bytes_per_task"],
        }
    )
    tasks, skipped = prepare_plan_tasks(snapshot, plan, profile, limits, provider)
    ceiling = effective_task_input_ceiling(limits, provider)
    assert ceiling == limits["max_input_bytes_per_task"]
    assert not any(row.get("error_code") == "REQUIRED_CONTEXT_MISSING" for row in skipped.values())
    assert all(
        provider.estimate_call(
            "SPECIALIST_FINDINGS", task, _evidence_for(task, snapshot, ceiling), limits
        )["input_bytes"]
        <= ceiling
        for task in tasks
        if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS"
    )
