#!/usr/bin/env python3
"""Build the QM-1 frozen evaluation corpus from public Git history.

The builder never calls a model or provider and never copies repository source
into the dataset. It freezes case identity from exact merge commits, computes a
snapshot with the existing ``collect_snapshot`` harness, and writes only
identity, diff-hash, and gap metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness.snapshot import SnapshotError, collect_snapshot  # noqa: E402

CORPUS_ID = "qm1-frozen-corpus-v1"
DATASET_VERSION = "2026-11-02.1"
DATASET_DATE = "2026-11-02"
OUTPUT_DIR = ROOT / "examples/evaluation/frozen-corpus-v1"
LIMITS_PATH = ROOT / "profiles/ordinary-review-limits-v3.json"

REPOSITORIES = {
    "slopsearx": {
        "owner": "magnus919",
        "name": "SlopSearX",
        "profile_path": "profiles/slopsearx.json",
        "profile_id": "slopsearx",
    },
    "codereview": {
        "owner": "groktopus",
        "name": "codereview",
        "profile_path": "profiles/codereview-native-v1-candidate.json",
        "profile_id": "codereview-native",
    },
}

# (repository key, merged PR number, split, family id, sampling basis, control class, rationale)
# Control class is an empty string for ordinary cases. Selection used only
# repository metadata and diff shape, never model output or review findings.
CASES: tuple[tuple[str, int, str, str, str, str, str], ...] = (
    ("slopsearx", 759, "development", "qm1-slopsearx-pr759-natural", "natural_merged_pr", "", "Merged documentation-adjacent PR touching gateway result documentation and its experiment evidence."),
    ("slopsearx", 757, "development", "qm1-slopsearx-pr757-natural", "natural_merged_pr", "", "Merged coverage-runner code change with accompanying tests."),
    ("slopsearx", 756, "development", "qm1-slopsearx-pr756-natural", "natural_merged_pr", "", "Merged coverage instrumentation code and test update."),
    ("slopsearx", 753, "development", "qm1-slopsearx-pr753-natural", "natural_merged_pr", "", "Merged coverage resource-evidence code and test change."),
    ("slopsearx", 752, "development", "qm1-slopsearx-pr752-natural", "natural_merged_pr", "", "Merged live-acquisition and resource-evidence code change."),
    ("slopsearx", 748, "development", "qm1-slopsearx-pr748-natural", "natural_merged_pr", "", "Merged coverage answer execution and control code change."),
    ("slopsearx", 747, "development", "qm1-slopsearx-pr747-natural", "natural_merged_pr", "", "Merged CI mirror configuration and documentation change."),
    ("slopsearx", 746, "development", "qm1-slopsearx-pr746-natural", "natural_merged_pr", "", "Merged coverage selector resource-collection code and evidence change."),
    ("slopsearx", 776, "development", "qm1-slopsearx-documentation-controls-development", "documentation_only_control", "documentation_only", "Documentation-only control diff; candidate zero-finding control, not a quality label."),
    ("slopsearx", 745, "heldout", "qm1-slopsearx-pr745-natural", "natural_merged_pr", "", "Held-out merged CI workflow and documentation change."),
    ("slopsearx", 744, "heldout", "qm1-slopsearx-pr744-natural", "natural_merged_pr", "", "Held-out merged coverage grade-closure code and test change."),
    ("slopsearx", 743, "heldout", "qm1-slopsearx-pr743-natural", "natural_merged_pr", "", "Held-out merged coverage resource-evidence code change."),
    ("slopsearx", 742, "heldout", "qm1-slopsearx-pr742-natural", "natural_merged_pr", "", "Held-out merged coverage resource-evidence code change."),
    ("slopsearx", 741, "heldout", "qm1-slopsearx-pr741-natural", "natural_merged_pr", "", "Held-out merged coverage gate-integration code change."),
    ("slopsearx", 780, "heldout", "qm1-slopsearx-documentation-controls-heldout", "documentation_only_control", "documentation_only", "Held-out documentation-only control diff; candidate zero-finding control, not a quality label."),
    ("slopsearx", 770, "challenge", "qm1-slopsearx-publisher-workflow-challenge", "risk_enriched_merged_pr", "", "Risk-enriched merged review-publisher workflow and policy change."),
    ("slopsearx", 772, "challenge", "qm1-slopsearx-publisher-workflow-challenge", "risk_enriched_merged_pr", "", "Risk-enriched merged review-publisher workflow and policy change."),
    ("slopsearx", 773, "challenge", "qm1-slopsearx-publisher-workflow-challenge", "risk_enriched_merged_pr", "", "Risk-enriched merged review-publisher workflow and policy change."),
    ("slopsearx", 708, "challenge", "qm1-slopsearx-publisher-workflow-challenge", "risk_enriched_merged_pr", "", "Risk-enriched merged pull-request publication policy and workflow change."),
    ("slopsearx", 874, "challenge", "qm1-slopsearx-ci-transition-challenge", "risk_enriched_merged_pr", "", "Risk-enriched merged Rust CI transition touching build configuration and workflows at scale."),
    ("codereview", 296, "development", "qm1-codereview-pr296-natural", "natural_merged_pr", "", "Merged release supply-chain code, workflow, and documentation change."),
    ("codereview", 295, "development", "qm1-codereview-pr295-natural", "natural_merged_pr", "", "Merged decision-record and workflow change."),
    ("codereview", 294, "development", "qm1-codereview-pr294-natural", "natural_merged_pr", "", "Merged release-pipeline code, workflow, and test change."),
    ("codereview", 293, "development", "qm1-codereview-pr293-natural", "natural_merged_pr", "", "Merged review-evidence receipt code and documentation change."),
    ("codereview", 291, "development", "qm1-codereview-pr291-natural", "natural_merged_pr", "", "Merged cost-model code and documentation change."),
    ("codereview", 292, "development", "qm1-codereview-pr292-natural", "natural_merged_pr", "", "Merged license-governance metadata and documentation change."),
    ("codereview", 282, "development", "qm1-codereview-pr282-natural", "natural_merged_pr", "", "Merged run-metrics code and test change."),
    ("codereview", 273, "development", "qm1-codereview-documentation-controls-development", "documentation_only_control", "documentation_only", "Documentation-only control diff; candidate zero-finding control, not a quality label."),
    ("codereview", 112, "development", "qm1-codereview-documentation-controls-development", "documentation_only_control", "documentation_only", "Single-file documentation-only control diff; candidate zero-finding control, not a quality label."),
    ("codereview", 289, "heldout", "qm1-codereview-pr289-natural", "natural_merged_pr", "", "Held-out merged typed-boundary code, workflow, and documentation change."),
    ("codereview", 290, "heldout", "qm1-codereview-pr290-natural", "natural_merged_pr", "", "Held-out merged status-freshness code and test change."),
    ("codereview", 287, "heldout", "qm1-codereview-pr287-natural", "natural_merged_pr", "", "Held-out merged compatibility-suite code and test change."),
    ("codereview", 288, "heldout", "qm1-codereview-pr288-natural", "natural_merged_pr", "", "Held-out merged invariant-test code and documentation change."),
    ("codereview", 286, "heldout", "qm1-codereview-pr286-natural", "natural_merged_pr", "", "Held-out merged documentation-truth code, test, and documentation change."),
    ("codereview", 283, "heldout", "qm1-codereview-pr283-natural", "natural_merged_pr", "", "Held-out merged exception-audit code and test change."),
    ("codereview", 237, "heldout", "qm1-codereview-documentation-controls-heldout", "documentation_only_control", "documentation_only", "Held-out documentation-only control diff; candidate zero-finding control, not a quality label."),
    ("codereview", 285, "challenge", "qm1-codereview-publication-and-supply-chain-challenge", "risk_enriched_merged_pr", "", "Risk-enriched merged publication effect-fault-matrix code and test change."),
    ("codereview", 284, "challenge", "qm1-codereview-publication-and-supply-chain-challenge", "risk_enriched_merged_pr", "", "Risk-enriched merged security workflow and supply-chain code change; snapshot has truncated diffs."),
    ("codereview", 279, "challenge", "qm1-codereview-publication-and-supply-chain-challenge", "risk_enriched_merged_pr", "", "Risk-enriched merged coverage-gate, workflow, and configuration change."),
    ("codereview", 277, "challenge", "qm1-codereview-publication-and-supply-chain-challenge", "risk_enriched_merged_pr", "", "Risk-enriched merged security workflow, security documentation, and test change."),
    ("codereview", 276, "challenge", "qm1-codereview-publication-and-supply-chain-challenge", "risk_enriched_merged_pr", "", "Risk-enriched merged security workflow and security documentation change."),
)

_COMPLETE_ABSENT_REASONS = {"diff_truncated", "context_selection_budget_exhausted", "changed_source_unavailable"}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise SystemExit(f"git command failed in {repo}: {' '.join(args)}")
    return result.stdout


def _merge_identity(repo: Path, pr_number: int) -> dict[str, str]:
    matches: list[tuple[str, str]] = []
    for line in _git(repo, "log", "--merges", "--format=%H %s").splitlines():
        commit, _, subject = line.partition(" ")
        found = re.match(r"Merge pull request #(\d+)\b", subject)
        if found and int(found.group(1)) == pr_number:
            matches.append((commit, subject))
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one merge commit for PR #{pr_number} in {repo}, found {len(matches)}")
    merge_commit, subject = matches[0]
    parents = _git(repo, "log", "-1", "--format=%P", merge_commit).split()
    if len(parents) != 2:
        raise SystemExit(f"merge commit for PR #{pr_number} does not have exactly two parents")
    merged_at = _git(repo, "log", "-1", "--format=%cI", merge_commit).strip()
    return {
        "merge_commit": merge_commit,
        "base_sha": parents[0],
        "head_sha": parents[1],
        "subject": subject,
        "merged_at": merged_at,
    }


def _read_object(path: Path) -> dict[str, Any]:
    with path.open("rb") as source:
        return json.loads(source.read())


def _case_record(
    repository_key: str,
    pr_number: int,
    split: str,
    family_id: str,
    sampling_basis: str,
    control_class: str,
    rationale: str,
    repo: Path,
    profile: dict[str, Any],
    limits: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    repository = REPOSITORIES[repository_key]
    merge = _merge_identity(repo, pr_number)
    try:
        snapshot = collect_snapshot(repo, merge["base_sha"], merge["head_sha"], profile, limits, pr_diff=True)
    except SnapshotError as exc:
        raise SystemExit(f"snapshot failed for {repository_key} PR #{pr_number}: {exc}") from exc
    if snapshot["base_sha"] != merge["base_sha"] or snapshot["head_sha"] != merge["head_sha"]:
        raise SystemExit(f"snapshot identity drift for {repository_key} PR #{pr_number}")
    case_id = f"qm1-{repository_key}-pr{pr_number}"
    profile_identity = {
        "profile_id": repository["profile_id"],
        "version": profile["version"],
        "sha256": digest(profile),
    }
    unit_rows = [
        {
            "path": unit["path"],
            "old_path": unit["old_path"],
            "change": unit["change"],
            "diff_sha256": unit["diff_hash"],
        }
        for unit in snapshot["inventory"]
    ]
    unit_rows.sort(key=lambda row: (row["path"], row["old_path"] or "", row["change"]))
    evidence_metadata = sorted(
        (
            {
                "evidence_id": evidence_id,
                "path": row["path"],
                "source_kind": row["source_kind"],
                "source_revision": row["source_revision"],
                "content_hash": row["content_hash"],
                "content_truncated": row["content_truncated"],
            }
            for evidence_id, row in snapshot["evidence"].items()
        ),
        key=lambda row: row["evidence_id"],
    )
    gap_reasons = Counter(str(row.get("reason")) for row in snapshot["gaps"])
    required_reasons = {str(row.get("reason")) for row in snapshot["gaps"] if row.get("required")}
    if required_reasons & _COMPLETE_ABSENT_REASONS:
        completeness = "incomplete"
    elif snapshot["gaps"]:
        completeness = "bounded"
    else:
        completeness = "complete"
    source_record = {
        "schema_version": "qm1-source-manifest.v1",
        "manifest_id": f"{case_id}-source",
        "case_id": case_id,
        "repository": {"owner": repository["owner"], "name": repository["name"]},
        "pr_number": pr_number,
        "merge_commit_sha": merge["merge_commit"],
        "merged_at": merge["merged_at"],
        "base_sha": merge["base_sha"],
        "head_sha": merge["head_sha"],
        "change_base_sha": snapshot["change_base_sha"],
        "comparison_mode": snapshot["comparison_mode"],
        "profile": profile_identity,
        "snapshot_profile_version": snapshot["profile_version"],
        "snapshot_profile_hash": snapshot["profile_hash"],
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_evidence_count": len(snapshot["evidence"]),
        "evidence_metadata_sha256": digest(evidence_metadata),
        "units": unit_rows,
        "gap_counts": {
            "total": len(snapshot["gaps"]),
            "required": sum(1 for row in snapshot["gaps"] if row.get("required")),
            "by_reason": dict(sorted(gap_reasons.items())),
        },
    }
    case = {
        "identity": {
            "case_id": case_id,
            "family_id": family_id,
            "split": split,
            "repository": {"owner": repository["owner"], "name": repository["name"]},
            "snapshot_id": snapshot["snapshot_id"],
            "base_sha": merge["base_sha"],
            "head_sha": merge["head_sha"],
            "profile": profile_identity,
            "source_manifest": {
                "manifest_id": source_record["manifest_id"],
                "sha256": digest(source_record),
            },
        },
        "scenario": {
            "kind": "natural",
            "behavior_id": f"{repository_key}-pr{pr_number}-merged-change",
            "attack_vector": None,
            "paired_case_id": None,
            "fixture_source_id": None,
            "fixture_sha256": None,
            "expected_forbidden_effects": [],
        },
    }
    manifest_case = {
        "case_id": case_id,
        "family_id": family_id,
        "split": split,
        "repository": f"{repository['owner']}/{repository['name']}",
        "pr_number": pr_number,
        "merge_commit_sha": merge["merge_commit"],
        "merged_at": merge["merged_at"],
        "scenario_kind": "natural",
        "sampling_basis": sampling_basis,
        "control_class": control_class or None,
        "selection_rationale": rationale,
        "evidence_completeness": completeness,
        "snapshot_gap_counts": source_record["gap_counts"],
        "source_manifest_id": source_record["manifest_id"],
        "source_manifest_sha256": case["identity"]["source_manifest"]["sha256"],
        "snapshot_id": snapshot["snapshot_id"],
    }
    return case, source_record, manifest_case


def _counts(cases: list[dict[str, Any]]) -> dict[str, Any]:
    by_repository = Counter(case["repository"] for case in cases)
    by_split = Counter(case["split"] for case in cases)
    by_family = Counter(case["family_id"] for case in cases)
    by_repository_split = Counter((case["repository"], case["split"]) for case in cases)
    return {
        "total": len(cases),
        "by_repository": dict(sorted(by_repository.items())),
        "by_split": {split: by_split[split] for split in ("development", "heldout", "challenge")},
        "by_repository_split": {
            f"{repository}/{split}": count
            for (repository, split), count in sorted(by_repository_split.items())
        },
        "by_family": dict(sorted(by_family.items())),
    }


def _write_json(path: Path, value: Any) -> bytes:
    raw = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n"
    path.write_bytes(raw)
    return raw


def _report(manifest: dict[str, Any]) -> str:
    lines = [
        "# Frozen evaluation corpus v1 — case report",
        "",
        "This report is generated by `scripts/build_frozen_corpus_v1.py`. It lists",
        "counts and frozen identities only. It is not a quality measurement, does not",
        "contain human labels, and does not report any model output.",
        "",
        f"- Dataset version: `{manifest['dataset_version']}`",
        f"- Corpus ID: `{manifest['corpus_id']}`",
        f"- Cases: **{manifest['counts']['total']}**",
        f"- Corpus SHA-256: `{manifest['corpus_sha256']}`",
        f"- Source-manifest catalog SHA-256: `{manifest['source_manifests_sha256']}`",
        "",
        "## Counts by repository and split",
        "",
        "| Repository | development | heldout | challenge | total |",
        "|---|---:|---:|---:|---:|",
    ]
    for repository, total in manifest["counts"]["by_repository"].items():
        row = manifest["counts"]["by_repository_split"]
        lines.append(
            f"| {repository} | {row.get(repository + '/development', 0)} | "
            f"{row.get(repository + '/heldout', 0)} | {row.get(repository + '/challenge', 0)} | {total} |"
        )
    lines.extend(
        [
            f"| **total** | **{manifest['counts']['by_split']['development']}** | "
            f"**{manifest['counts']['by_split']['heldout']}** | "
            f"**{manifest['counts']['by_split']['challenge']}** | "
            f"**{manifest['counts']['total']}** |",
            "",
            "## Counts by family",
            "",
            "| Family | Split | Cases |",
            "|---|---|---:|",
        ]
    )
    split_by_family = {case["family_id"]: case["split"] for case in manifest["cases"]}
    for family, count in manifest["counts"]["by_family"].items():
        lines.append(f"| `{family}` | {split_by_family[family]} | {count} |")
    lines.extend(
        [
            "",
            "## Cases",
            "",
            "| Case | Repository | PR | Split | Evidence | Snapshot |",
            "|---|---|---:|---|---|---|",
        ]
    )
    for case in manifest["cases"]:
        lines.append(
            f"| `{case['case_id']}` | {case['repository']} | {case['pr_number']} | "
            f"{case['split']} | {case['evidence_completeness']} | `{case['snapshot_id']}` |"
        )
    lines.extend(
        [
            "",
            "## What this corpus does not establish",
            "",
            "- It is not a prevalence sample and cannot estimate defect or finding rates.",
            "- It contains no human labels, no adjudication, and no quality claim.",
            "- It does not establish cross-language generality: the selected repositories are",
            "  Python and Python/Rust transition code, not a language-stratified sample.",
            "- Held-out cases were withheld from this curation's selection analysis. Historical",
            "  model exposure to these public repositories cannot be excluded.",
            "- Snapshot gaps and truncated diffs are recorded per case and prevent treating every",
            "  case as complete evidence.",
            "",
            "See `manifest.json` for provenance, rights, retention, contamination, and the",
            "split policy.",
            "",
        ]
    )
    return "\n".join(lines)


def build(slopsearx_repo: Path, codereview_repo: Path) -> dict[str, Any]:
    repositories = {"slopsearx": slopsearx_repo, "codereview": codereview_repo}
    profiles = {
        key: _read_object(ROOT / value["profile_path"])
        for key, value in REPOSITORIES.items()
    }
    limits = _read_object(LIMITS_PATH)
    cases: list[dict[str, Any]] = []
    source_records: dict[str, dict[str, Any]] = {}
    manifest_cases: list[dict[str, Any]] = []
    for repository_key, pr_number, split, family_id, sampling_basis, control_class, rationale in CASES:
        query = repositories[repository_key]
        if not query.is_dir():
            raise SystemExit(f"repository path is not a directory: {query}")
        case, source_record, manifest_case = _case_record(
            repository_key,
            pr_number,
            split,
            family_id,
            sampling_basis,
            control_class,
            rationale,
            query,
            profiles[repository_key],
            limits,
        )
        if case["identity"]["case_id"] in source_records:
            raise SystemExit(f"duplicate case id: {case['identity']['case_id']}")
        cases.append(case)
        source_records[case["identity"]["case_id"]] = source_record
        manifest_cases.append(manifest_case)

    cases.sort(key=lambda case: case["identity"]["case_id"])
    manifest_cases.sort(key=lambda case: case["case_id"])
    source_records = {case_id: source_records[case_id] for case_id in sorted(source_records)}
    corpus = {
        "contract_version": "review-evaluation-corpus.v1",
        "corpus_id": CORPUS_ID,
        "dataset_version": DATASET_VERSION,
        "sampling_frame": "risk_enriched_challenge",
        "expected_arms": ["harness", "droid"],
        "cases": cases,
    }
    source_catalog = {
        "schema_version": "qm1-source-manifests.v1",
        "dataset_version": DATASET_VERSION,
        "manifests": source_records,
    }
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    corpus_raw = _write_json(OUTPUT_DIR / "corpus.json", corpus)
    source_raw = _write_json(OUTPUT_DIR / "source-manifests.json", source_catalog)
    manifest = {
        "schema_version": "review-evaluation-dataset-manifest.v1",
        "dataset_version": DATASET_VERSION,
        "created_at": DATASET_DATE,
        "corpus_id": CORPUS_ID,
        "contract_version": "review-evaluation-corpus.v1",
        "corpus_file": "corpus.json",
        "corpus_sha256": hashlib.sha256(corpus_raw).hexdigest(),
        "source_manifests_file": "source-manifests.json",
        "source_manifests_sha256": hashlib.sha256(source_raw).hexdigest(),
        "counts": _counts(manifest_cases),
        "repositories": [
            {
                "key": key,
                "owner": value["owner"],
                "name": value["name"],
                "url": f"https://github.com/{value['owner']}/{value['name']}",
                "license": "MIT",
                "profile_path": value["profile_path"],
                "profile_id": value["profile_id"],
                "profile_version": profiles[key]["version"],
                "profile_sha256": digest(profiles[key]),
            }
            for key, value in sorted(REPOSITORIES.items())
        ],
        "cases": manifest_cases,
        "changelog": [
            {
                "version": DATASET_VERSION,
                "date": DATASET_DATE,
                "change": f"Initial frozen corpus. {len(cases)} cases across two public repositories and three splits.",
            }
        ],
        "sampling": {
            "corpus_frame": "risk_enriched_challenge",
            "basis": (
                "Purposive selection of natural merged PRs, risk-enriched merged PRs, and "
                "documentation-only controls. The corpus is not a random or prevalence sample."
            ),
            "per_case_basis": "Recorded in cases[].sampling_basis.",
        },
        "provenance": {
            "repositories": "Public GitHub repositories cloned read-only from existing local checkouts.",
            "case_identity": "Exact merge commit, first parent as base, second parent as PR head.",
            "snapshots": (
                "snapshot_id computed with pr_review_harness.snapshot.collect_snapshot using "
                "the checked-in profile and ordinary-review-limits-v3.json, with PR merge-base mode."
            ),
            "source_manifests": (
                "Per-case source records include changed-path diff SHA-256 values, snapshot identity, "
                "evidence metadata hash, and gap counts. The corpus binds each record by canonical SHA-256."
            ),
            "source_copies": "No repository source files are copied into this dataset.",
        },
        "rights": {
            "status": "rights_clear_public_mit",
            "detail": (
                "Both repositories publish under the MIT license. Only commit identities, paths, "
                "diff hashes, and metadata are stored; no third-party source body is redistributed."
            ),
            "confidentiality": "No private projects, credentials, prompts, provider bodies, or review text.",
        },
        "retention": {
            "policy": "Versioned and immutable.",
            "detail": (
                "A case is never silently replaced. Corrections or additions require a new dataset_version "
                "and changelog entry; the previous manifest and source hashes remain in Git history."
            ),
        },
        "contamination": {
            "risk": "nonzero",
            "detail": (
                "Both repositories are the harness's own public development repositories. Models and "
                "operators may have seen their code or PRs historically. Held-out means withheld from this "
                "curation's selection analysis, not proven unseen by every model or prompt."
            ),
            "mitigation": (
                "No prompt, profile, threshold, or model was tuned against this corpus in QM-1. "
                "Held-out case results must be reported separately and must not drive prompt/profile tuning."
            ),
        },
        "split_policy": {
            "development": "May be inspected during harness development, but not treated as held-out evidence.",
            "heldout": (
                "Must not be used to tune prompts, profiles, thresholds, context policies, or model choice. "
                "Do not inspect individual held-out failures to guide tuning; report aggregate results only."
            ),
            "challenge": (
                "Risk-enriched merged PRs. Rates are challenge-set rates and must not be reported as "
                "natural prevalence."
            ),
            "assignment": (
                "Purposive and fixed before snapshot collection. Families never cross splits. "
                "No model output or review finding informed assignment."
            ),
        },
        "limitations": [
            "No human labels or adjudications; precision, recall, and severity are undefined.",
            "No model or provider was called; the corpus contains no predictions or quality claims.",
            "Not representative of all code review or of defect prevalence.",
            "Two repositories only, with shared maintainership and a Python/Rust transition; not cross-language general.",
            "Several snapshots are bounded or incomplete; evidence completeness is recorded per case.",
            "Snapshot identity binds base/head/profile, not a guarantee that all context was captured.",
            "The diff hash manifest covers changed-path diffs, not every profile context byte.",
        ],
        "reproduction": {
            "command": (
                "python scripts/build_frozen_corpus_v1.py "
                "--slopsearx-repo /path/to/SlopSearX --codereview-repo /path/to/codereview"
            ),
            "note": "Uses only local Git objects and the checked-in profiles; no network or provider calls.",
        },
    }
    _write_json(OUTPUT_DIR / "manifest.json", manifest)
    (OUTPUT_DIR / "REPORT.md").write_text(_report(manifest), encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slopsearx-repo", required=True, type=Path)
    parser.add_argument("--codereview-repo", required=True, type=Path)
    args = parser.parse_args(argv)
    manifest = build(args.slopsearx_repo.resolve(), args.codereview_repo.resolve())
    print(json.dumps({"cases": manifest["counts"]["total"], "counts": manifest["counts"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
