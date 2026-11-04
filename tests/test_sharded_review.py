"""Tests for the lens-sharded review wrapper (fake shard results only)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import sharded_review  # noqa: E402

LENSES = ("correctness", "tests", "maintainability")

PROFILE = {
    "version": "test-profile-v1",
    "required_lenses": list(LENSES),
    "docs_lenses": ["correctness"],
    "security_lenses": ["correctness", "security"],
    "default_lenses": ["design"],
    "review_criteria": {
        "correctness": "correctness criteria",
        "tests": "tests criteria",
        "maintainability": "maintainability criteria",
        "security": "security criteria",
        "design": "design criteria",
    },
    "risk_rules": [
        {"patterns": ["*auth*"], "lenses": ["security"], "min_mode": "FOCUSED"},
        {"patterns": ["src/*"], "lenses": ["tests"], "min_mode": "DEEP"},
    ],
}


def make_entry(
    lens: str,
    disposition: str = "APPROVE",
    *,
    coverage: str = "COMPLETE",
    findings: list[dict] | None = None,
    gaps: list[dict] | None = None,
    error: str | None = None,
) -> dict:
    result = {
        "disposition": disposition,
        "coverage_state": coverage,
        "findings": findings or [],
        "context_gaps": gaps or [],
        "provider_identity": {"provider": {"provider_id": "test-provider"}},
        "budget": {
            "provider_calls_reserved": 2,
            "cost_billing_known": True,
            "cost_billed_microunits": 10,
            "cost_estimate_known": True,
            "cost_estimated_microunits": 20,
        },
        "completeness_summary": {
            "reason_distribution": [] if coverage == "COMPLETE" else [{"canonical_code": "CONTEXT_MISSING"}]
        },
    }
    return {
        "lens": lens,
        "exit_code": None if error else 0,
        "error": error,
        "result": None if error else result,
        "result_sha256": None if error else "a" * 64,
    }


def merge(entries: dict[str, dict], lenses=LENSES) -> dict:
    return sharded_review.merge_shards(
        lenses,
        entries,
        repo="owner/repo",
        base="b" * 40,
        head="c" * 40,
        mode="FOCUSED",
    )


def test_all_complete_approve_merges_to_approve() -> None:
    entries = {lens: make_entry(lens) for lens in LENSES}

    combined = merge(entries)

    assert combined["schema"] == "review-sharded-result.v1"
    assert combined["disposition"] == "APPROVE"
    assert combined["completeness"] == "COMPLETE"
    assert [shard["lens"] for shard in combined["shards"]] == list(LENSES)
    assert all(shard["coverage"] == "COMPLETE" for shard in combined["shards"])
    assert combined["provider"]["provider_calls_reserved"] == 6
    assert combined["cost"]["billed_microunits"] == 30


def test_one_request_changes_wins_over_approve() -> None:
    entries = {lens: make_entry(lens) for lens in LENSES}
    entries["tests"] = make_entry("tests", "REQUEST_CHANGES")

    combined = merge(entries)

    assert combined["disposition"] == "REQUEST_CHANGES"
    assert combined["completeness"] == "COMPLETE"


def test_one_incomplete_shard_makes_the_combined_result_incomplete() -> None:
    entries = {lens: make_entry(lens) for lens in LENSES}
    entries["maintainability"] = make_entry("maintainability", "INCOMPLETE", coverage="PARTIAL")

    combined = merge(entries)

    assert combined["disposition"] == "INCOMPLETE"
    assert combined["completeness"] == "INCOMPLETE"
    shard = next(item for item in combined["shards"] if item["lens"] == "maintainability")
    assert shard["coverage"] == "PARTIAL"
    assert "shard_disposition_incomplete" in shard["reasons"]
    assert "shard_coverage_partial" in shard["reasons"]
    assert "coverage:CONTEXT_MISSING" in shard["reasons"]
    assert {reason["lens"] for reason in combined["incomplete_reasons"]} == {"maintainability"}


def test_duplicate_findings_are_deduped_preserving_the_first() -> None:
    duplicate = {
        "path": "src/app.py",
        "title": "Unchecked error path",
        "observation": "from correctness",
        "finding_id": "finding-1",
    }
    same_issue = dict(duplicate, observation="from tests", finding_id="finding-2")
    unique = {"path": "src/other.py", "title": "Missing boundary test", "finding_id": "finding-3"}
    entries = {
        "correctness": make_entry("correctness", "COMMENT", findings=[duplicate]),
        "tests": make_entry("tests", "COMMENT", findings=[same_issue, unique]),
        "maintainability": make_entry("maintainability"),
    }

    combined = merge(entries)

    assert len(combined["findings"]) == 2
    assert combined["findings"][0]["observation"] == "from correctness"
    assert combined["findings"][1]["title"] == "Missing boundary test"
    assert len(combined["shards"][1]["findings"]) == 2


def test_context_gaps_are_unioned_and_deduped() -> None:
    gap = {"proposal_id": "gap-1", "reason_code": "MISSING_CONTEXT"}
    entries = {
        "correctness": make_entry("correctness", gaps=[gap]),
        "tests": make_entry("tests", gaps=[dict(gap), {"proposal_id": "gap-2"}]),
        "maintainability": make_entry("maintainability"),
    }

    combined = merge(entries)

    assert [item["proposal_id"] for item in combined["context_gaps"]] == ["gap-1", "gap-2"]


def test_build_lens_profile_filters_every_lens_field_and_risk_rule() -> None:
    shard = sharded_review.build_lens_profile(PROFILE, "tests")

    assert shard["required_lenses"] == ["tests"]
    assert shard["docs_lenses"] == []
    assert shard["security_lenses"] == []
    assert shard["default_lenses"] == []
    assert list(shard["review_criteria"]) == ["tests"]
    assert shard["risk_rules"] == [{"patterns": ["src/*"], "lenses": ["tests"], "min_mode": "DEEP"}]
    assert PROFILE["required_lenses"] == list(LENSES)


def test_resolve_lenses_defaults_and_csv_override() -> None:
    assert sharded_review.resolve_lenses({}) == list(sharded_review.DEFAULT_LENSES)
    assert sharded_review.resolve_lenses(PROFILE) == list(LENSES)
    assert sharded_review.resolve_lenses(PROFILE, "security, tests,security") == ["security", "tests"]
    with pytest.raises(sharded_review.ShardedReviewError):
        sharded_review.resolve_lenses(PROFILE, "unknown-lens")


def test_missing_shard_is_an_explicit_failure_not_a_dropped_lens() -> None:
    entries = {"correctness": make_entry("correctness")}

    combined = merge(entries)

    assert len(combined["shards"]) == len(LENSES)
    missing = {shard["lens"]: shard for shard in combined["shards"]}
    assert missing["tests"]["disposition"] == "FAILED"
    assert missing["tests"]["coverage"] == "UNKNOWN"
    assert "missing_shard_result" in missing["tests"]["reasons"]
    assert combined["disposition"] == "INCOMPLETE"
    assert combined["completeness"] == "INCOMPLETE"
    assert {reason["lens"] for reason in combined["incomplete_reasons"]} == {"tests", "maintainability"}


def test_failed_shard_exit_is_preserved_with_its_reason() -> None:
    entries = {lens: make_entry(lens) for lens in LENSES}
    entries["tests"] = make_entry("tests", error="shard_exit_2")

    combined = merge(entries)

    shard = next(item for item in combined["shards"] if item["lens"] == "tests")
    assert shard["disposition"] == "FAILED"
    assert shard["exit_code"] is None
    assert "shard_exit_2" in shard["reasons"]
    assert combined["disposition"] == "INCOMPLETE"


def test_run_sharded_uses_single_lens_profiles_and_writes_combined_json(tmp_path: Path) -> None:
    seen: list[tuple[str, dict]] = []

    def fake_runner(lens: str, **kwargs) -> dict:
        seen.append((lens, json.loads(kwargs["profile_path"].read_text(encoding="utf-8"))))
        assert kwargs["output_dir"].is_dir()
        assert kwargs["repo_root"] == ROOT
        return make_entry(lens)

    output = tmp_path / "combined.json"
    combined = sharded_review.run_sharded(
        {
            "repo": str(tmp_path / "repo"),
            "base": "b" * 40,
            "head": "c" * 40,
            "profile": PROFILE,
            "provider_config": None,
            "limits": None,
            "output": str(output),
            "lenses": "correctness,tests",
            "mode": "LIGHT",
        },
        shard_runner=fake_runner,
    )

    assert [lens for lens, _ in seen] == ["correctness", "tests"]
    assert all(profile["required_lenses"] == [lens] for lens, profile in seen)
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["schema"] == "review-sharded-result.v1"
    assert written["disposition"] == "APPROVE"
    assert combined["output_path"] == str(output)


def test_run_sharded_turns_a_raising_runner_into_a_failed_shard(tmp_path: Path) -> None:
    def exploding_runner(lens: str, **kwargs) -> dict:
        raise RuntimeError("boom")

    combined = sharded_review.run_sharded(
        {
            "repo": str(tmp_path / "repo"),
            "base": "b" * 40,
            "head": "c" * 40,
            "profile": PROFILE,
            "output": str(tmp_path / "combined.json"),
            "lenses": "correctness,tests",
        },
        shard_runner=exploding_runner,
    )

    assert [shard["disposition"] for shard in combined["shards"]] == ["FAILED", "FAILED"]
    assert combined["disposition"] == "INCOMPLETE"
    assert combined["incomplete_reasons"]
