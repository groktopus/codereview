"""Validate the QM-1 frozen evaluation corpus and dataset manifest."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from experiments.harness.evaluation import validate_corpus

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "examples/evaluation/frozen-corpus-v1"
CORPUS_PATH = DATASET / "corpus.json"
MANIFEST_PATH = DATASET / "manifest.json"
SOURCES_PATH = DATASET / "source-manifests.json"
REPORT_PATH = DATASET / "REPORT.md"
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SNAPSHOT = re.compile(r"^snap-[0-9a-f]{24}$")


def _load(path: Path) -> dict[str, Any]:
    with path.open("rb") as source:
        return json.loads(source.read())


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def test_corpus_validates_and_meets_size_and_split_floor() -> None:
    corpus = _load(CORPUS_PATH)
    assert validate_corpus(corpus) == corpus
    cases = corpus["cases"]
    assert len(cases) == 41
    repositories = Counter(
        f"{case['identity']['repository']['owner']}/{case['identity']['repository']['name']}" for case in cases
    )
    assert repositories == {"magnus919/SlopSearX": 20, "groktopus/codereview": 21}
    splits = Counter(case["identity"]["split"] for case in cases)
    assert splits == {"development": 18, "heldout": 13, "challenge": 10}
    assert len({case["identity"]["family_id"] for case in cases}) >= 30


def test_identity_fields_are_frozen_and_family_splits_do_not_leak() -> None:
    corpus = _load(CORPUS_PATH)
    family_splits: dict[str, set[str]] = {}
    for case in corpus["cases"]:
        identity = case["identity"]
        assert SHA1.fullmatch(identity["base_sha"])
        assert SHA1.fullmatch(identity["head_sha"])
        assert identity["base_sha"] != identity["head_sha"]
        assert SNAPSHOT.fullmatch(identity["snapshot_id"])
        assert SHA256.fullmatch(identity["profile"]["sha256"])
        assert SHA256.fullmatch(identity["source_manifest"]["sha256"])
        assert identity["profile"]["version"]
        family_splits.setdefault(identity["family_id"], set()).add(identity["split"])
        assert case["scenario"]["kind"] == "natural"
    assert all(len(splits) == 1 for splits in family_splits.values())


def test_source_manifest_hashes_bind_each_case_identity() -> None:
    corpus = _load(CORPUS_PATH)
    catalog = _load(SOURCES_PATH)
    assert catalog["schema_version"] == "qm1-source-manifests.v1"
    assert catalog["dataset_version"] == corpus["dataset_version"]
    assert set(catalog["manifests"]) == {case["identity"]["case_id"] for case in corpus["cases"]}
    for case in corpus["cases"]:
        identity = case["identity"]
        record = catalog["manifests"][identity["case_id"]]
        assert _digest(record) == identity["source_manifest"]["sha256"]
        assert record["manifest_id"] == identity["source_manifest"]["manifest_id"]
        assert record["case_id"] == identity["case_id"]
        assert record["base_sha"] == identity["base_sha"]
        assert record["head_sha"] == identity["head_sha"]
        assert record["snapshot_id"] == identity["snapshot_id"]
        assert record["profile"] == identity["profile"]
        assert record["snapshot_profile_hash"] == identity["profile"]["sha256"]
        assert record["snapshot_profile_version"] == identity["profile"]["version"]
        assert record["repository"] == identity["repository"]
        assert record["units"]
        assert all(SHA256.fullmatch(unit["diff_sha256"]) for unit in record["units"])
        assert SHA256.fullmatch(record["evidence_metadata_sha256"])


def test_manifest_content_hashes_and_counts_match_checked_in_files() -> None:
    corpus = _load(CORPUS_PATH)
    manifest = _load(MANIFEST_PATH)
    assert manifest["corpus_id"] == corpus["corpus_id"]
    assert manifest["dataset_version"] == corpus["dataset_version"]
    assert manifest["contract_version"] == corpus["contract_version"]
    assert manifest["corpus_sha256"] == hashlib.sha256(CORPUS_PATH.read_bytes()).hexdigest()
    assert manifest["source_manifests_sha256"] == hashlib.sha256(SOURCES_PATH.read_bytes()).hexdigest()
    cases = manifest["cases"]
    assert manifest["counts"]["total"] == len(corpus["cases"]) == len(cases)
    assert manifest["counts"]["by_repository"] == dict(sorted(Counter(case["repository"] for case in cases).items()))
    assert manifest["counts"]["by_split"] == {
        split: sum(1 for case in cases if case["split"] == split) for split in ("development", "heldout", "challenge")
    }
    assert manifest["counts"]["by_family"] == dict(sorted(Counter(case["family_id"] for case in cases).items()))
    assert sum(manifest["counts"]["by_repository_split"].values()) == len(cases)
    assert {case["case_id"] for case in cases} == {case["identity"]["case_id"] for case in corpus["cases"]}


def test_manifest_records_provenance_rights_retention_contamination_and_split_policy() -> None:
    manifest = _load(MANIFEST_PATH)
    assert manifest["changelog"] and manifest["changelog"][0]["version"] == manifest["dataset_version"]
    assert manifest["sampling"]["corpus_frame"] == "risk_enriched_challenge"
    assert manifest["provenance"]["source_copies"].startswith("No repository source files")
    assert manifest["rights"]["status"] == "rights_clear_public_mit"
    assert manifest["retention"]["policy"] == "Versioned and immutable."
    assert manifest["contamination"]["risk"] == "nonzero"
    assert set(manifest["split_policy"]) >= {"development", "heldout", "challenge", "assignment"}
    assert "must not be used to tune" in manifest["split_policy"]["heldout"].lower()
    assert manifest["limitations"]


def test_corpus_has_controls_incomplete_case_and_no_labels() -> None:
    manifest = _load(MANIFEST_PATH)
    cases = manifest["cases"]
    assert any(case["control_class"] == "documentation_only" for case in cases)
    assert sum(1 for case in cases if case["control_class"] == "documentation_only") >= 3
    assert any(case["evidence_completeness"] == "incomplete" for case in cases)
    assert any(case["sampling_basis"] == "risk_enriched_merged_pr" for case in cases)
    assert not any(name.startswith(("labels", "predictions")) for name in (path.name for path in DATASET.iterdir()))
    report = REPORT_PATH.read_text(encoding="utf-8")
    assert "| groktopus/codereview | 9 | 7 | 5 | 21 |" in report
    assert "| magnus919/SlopSearX | 9 | 6 | 5 | 20 |" in report
    assert "**41**" in report


def test_evidence_status_definitions_match_case_labels() -> None:
    manifest = _load(MANIFEST_PATH)
    definitions = manifest["evidence_status_definition"]
    assert set(definitions) == {"complete", "bounded", "incomplete"}
    for case in manifest["cases"]:
        gaps = case["snapshot_gap_counts"]
        status = case["evidence_completeness"]
        if status == "complete":
            assert gaps["total"] == 0, case["case_id"]
        elif status == "bounded":
            assert gaps["total"] > 0, case["case_id"]
            assert set(gaps["by_reason"]) <= {
                "window_count_limit",
                "changed_hunk_exceeds_window_limit",
                "not_bound_by_context_selection",
                "context_truncated",
            }, case["case_id"]
        else:
            assert status == "incomplete", case["case_id"]
            assert gaps["required"] > 0, case["case_id"]
            assert set(gaps["by_reason"]) & {
                "diff_truncated",
                "context_selection_budget_exhausted",
                "changed_source_unavailable",
            }, case["case_id"]
