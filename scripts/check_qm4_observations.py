#!/usr/bin/env python3
"""Offline integrity/missingness checker. Never creates predictions or metrics.

Hashes authenticate retained bytes relative to the local index, not provider
execution. The historical manifest/corpus remain the frozen identity authority.
This v1 admission contract cannot admit complete outputs or measured pairs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.compare_incumbent import DEFAULT_MANIFEST, load, pinned  # noqa: E402
from scripts.qm4_observation_schema import (  # noqa: E402
    ObservationError,
    fields,
    observation,
    require,
    support,
    walk,
)

DEFAULT_PACKAGE = ROOT / "examples/evaluation/qm4-incumbent-observations-v1"
CAP = 256 * 1024
DROID = {"id": 138933559, "login": "factory-droid[bot]", "type": "Bot"}
NORMALIZATION = "not_attempted_insufficient_final_exact_snapshot_evidence"


def strict_json(data: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def invalid_constant(_: str) -> None:
        raise ObservationError("nonfinite_json")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ObservationError("invalid_json: " + str(exc)) from exc


def read_bounded(path: Path, cap: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(cap + 1)
    require(len(data) <= cap, "retained_file_over_cap")
    return data


def reference(root: Path, ref: dict[str, Any], directory: str) -> tuple[Any, int]:
    raw = ref["path"]
    require(isinstance(raw, str), "invalid_reference_path")
    rel = Path(raw)
    require(not rel.is_absolute() and ".." not in rel.parts, "path_escape")
    require(rel.parent == Path(directory) and rel.suffix == ".json", "invalid_reference_path")
    try:
        resolved_root = root.resolve()
        path = (root / rel).resolve()
    except (OSError, RuntimeError) as exc:
        raise ObservationError("path_resolution_failed") from exc
    require(path.is_relative_to(resolved_root), "path_escape")
    data = read_bounded(path, CAP)
    require(type(ref["bytes"]) is int and ref["bytes"] == len(data), "reference_bytes_mismatch")
    require(hashlib.sha256(data).hexdigest() == ref["sha256"], "reference_hash_mismatch")
    return strict_json(data), len(data)


def index_schema(index: Any) -> None:
    fields(index, "authority case_byte_cap cases sanitization schema source_revision summary support")
    require(index["schema"] == "qm4-public-review-acquisition-index.v1", "index_version")
    require(index["authority"] == "public_read_only_get_no_provider_execution", "acquisition_authority")
    require(index["source_revision"] == "8e477420c5752537129963a402b1ba91b6956151", "acquisition_source_revision")
    require(type(index["case_byte_cap"]) is int and index["case_byte_cap"] == CAP, "case_cap")
    require(isinstance(index["cases"], list) and len(index["cases"]) == 41, "case_count")
    require(isinstance(index["support"], list) and len(index["support"]) == 4, "support_count")
    for ref in index["support"]:
        fields(ref, "bytes path sha256")
    for row in index["cases"]:
        fields(
            row,
            "bytes case_id complete_incumbent_output_status droid_records head_matched_original_droid_record_ids "
            "normalization_status path reason scope_caveat sha256 surface_counts surface_status",
        )
        require(row["complete_incumbent_output_status"] == "missing", "final_output_not_available")
        require(row["normalization_status"] == NORMALIZATION, "normalization_not_authorized")
        require(isinstance(row["reason"], str) and bool(row["reason"].strip()), "missing_reason")
        require(isinstance(row["scope_caveat"], str) and bool(row["scope_caveat"].strip()), "missing_scope_caveat")
        validate_index_surface_maps(row)
    fields(
        index["summary"],
        "accepted_cases actual_pairs captured_surface_count complete_incumbent_outputs fetched_surface_count frozen_cases "
        "identity_bound_security_receipt_cases original_head_matched_review_case_base_mismatches "
        "original_head_matched_review_cases over_cap_surfaces refused_accuracy",
    )
    for key, value in index["summary"].items():
        require(type(value) is (bool if key == "refused_accuracy" else int), "invalid_summary_type")
    walk(index)


def validate_index_surface_maps(row: dict[str, Any]) -> None:
    """Allow structurally sparse count maps for legacy corpus cases."""
    allowed_surfaces = {"reviews", "comments", "issue_comments"}
    count_map, status_map = row["surface_counts"], row["surface_status"]
    require(isinstance(count_map, dict) and isinstance(status_map, dict), "surface_count_keys")
    require(all(isinstance(key, str) for key in count_map), "surface_count_keys")
    require(all(isinstance(key, str) for key in status_map), "surface_status_keys")
    require(set(count_map) == set(status_map), "surface_status_keys")
    require(set(count_map) <= allowed_surfaces and bool(count_map), "surface_count_keys")
    for status in status_map.values():
        require(isinstance(status, str), "surface_status_type")
        require(status in {"captured", "response_over_capture_cap"}, "surface_status")
    validate_surface_maps(row, set(count_map))


def validate_surface_maps(row: dict[str, Any], expected_surfaces: set[str]) -> None:
    """Require exact surface keys, statuses, and JSON integer count semantics."""
    count_map, status_map = row["surface_counts"], row["surface_status"]
    require(isinstance(count_map, dict) and set(count_map) == expected_surfaces, "surface_count_keys")
    require(isinstance(status_map, dict), "surface_status_keys")
    require(all(isinstance(key, str) for key in count_map), "surface_count_keys")
    require(all(isinstance(key, str) for key in status_map), "surface_status_keys")
    require(set(count_map) == expected_surfaces, "surface_count_keys")
    require(set(status_map) == expected_surfaces, "surface_status_keys")
    for name, value in count_map.items():
        status = status_map[name]
        require(isinstance(status, str), "surface_status_type")
        require(status in {"captured", "response_over_capture_cap"}, "surface_status")
        if status == "captured":
            require(type(value) is int and value >= 0, "surface_count_type")
        else:
            require(value is None, "surface_count_type")


def project_records(case: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for name, surface in sorted(case["surfaces"].items()):
        for item in surface.get("records", []):
            if item["user"] == DROID:
                row = {
                    k: v
                    for k, v in item.items()
                    if k in {"id", "user", "html_url", "commit_id", "original_commit_id", "created_at", "submitted_at"}
                }
                result.append({"surface": name, **row})
    return result


def original_matches(case: dict[str, Any], records: list[dict[str, Any]]) -> list[int]:
    return [r["id"] for r in records if r.get("original_commit_id", r.get("commit_id")) == case["identity"]["head_sha"]]


def checkout(lines: list[str]) -> tuple[str, str]:
    matches = [re.search(r"Merge ([0-9a-f]{40}) into ([0-9a-f]{40})(?:$|\s)", line) for line in lines]
    pairs = [(m.group(1), m.group(2)) for m in matches if m is not None]
    require(len(pairs) == 1, "missing_immutable_checkout_binding")
    return pairs[0]


def exact_droid_receipt(case: dict[str, Any], comment_id: int, run_url: str) -> dict[str, Any]:
    """Require exactly one fixed Droid comment with one canonical Markdown job link."""
    surfaces = case.get("surfaces")
    if not isinstance(surfaces, dict):
        raise ObservationError("receipt_comment_surface_missing")
    surface = surfaces.get("issue_comments")
    if not isinstance(surface, dict):
        raise ObservationError("receipt_comment_surface_missing")
    rows = surface.get("records")
    if not isinstance(rows, list):
        raise ObservationError("receipt_comment_records_missing")
    matching = [row for row in rows if isinstance(row, dict) and row.get("id") == comment_id]
    require(len(matching) == 1 and matching[0].get("user") == DROID, "receipt_comment_identity_mismatch")
    row = matching[0]
    body = row.get("body")
    if not isinstance(body, str):
        raise ObservationError("receipt_comment_body_shape")
    links = re.findall(r"\[View job\]\((https://github\.com/magnus919/SlopSearX/actions/runs/[0-9]+)\)", body)
    require(links == [run_url], "receipt_run_link_missing")
    return row


def receipt_reason(case: dict[str, Any], evidence: dict[str, Any]) -> str:
    cid = case["identity"]["case_id"]
    head, base = case["identity"]["head_sha"], case["identity"]["base_sha"]
    if cid.endswith("pr745"):
        run = evidence["runs"][0]["record"]
        require(run["id"] == 37993871997, "pr745_receipt_run_binding")
        exact_droid_receipt(case, 6089587503, "https://github.com/magnus919/SlopSearX/actions/runs/37993871997")
        require(run["head_sha"] != head, "stale_run_head_no_longer_mismatched")
        return "droid_receipt_linked_run_head_mismatch"
    if cid.endswith("pr746"):
        metadata = evidence["records"][0]["record"]
        observed_head, observed_base = checkout(evidence["records"][-1]["lines"])
        require(
            metadata["head_sha"] == head and metadata["base_sha"] == observed_base != base,
            "base_mismatch_not_full_snapshot",
        )
        require(observed_head == evidence["records"][2]["record"]["head_sha"], "initial_checkout_head_mismatch")
        require(
            any(f"PR Head SHA: {head}" in line for line in evidence["records"][-1]["lines"]), "validator_head_missing"
        )
        issue_comments = evidence["records"][1].get("records")
        if not isinstance(issue_comments, list) or len(issue_comments) != 2:
            raise ObservationError("pr746_issue_comment_cardinality")
        droid_receipts = [row for row in issue_comments if isinstance(row, dict) and row.get("id") == 6090270984]
        require(
            len(droid_receipts) == 1 and droid_receipts[0].get("user") == DROID,
            "pr746_issue_comment_run_binding",
        )
        body = droid_receipts[0].get("body")
        if not isinstance(body, str):
            raise ObservationError("pr746_issue_comment_body_shape")
        require(
            re.findall(r"\[View job\]\((https://github\.com/magnus919/SlopSearX/actions/runs/[0-9]+)\)", body)
            == ["https://github.com/magnus919/SlopSearX/actions/runs/37999126510"],
            "pr746_issue_comment_run_binding",
        )
        return "original_review_head_matches_but_observed_review_base_differs_from_frozen_base"
    code_review_run = evidence["runs"][0]["record"]
    tag_run = evidence["runs"][1]["record"]
    receipts = case["surfaces"]["issue_comments"]["records"]
    require(len(receipts) == 3, "pr759_issue_comment_cardinality")
    require(code_review_run["id"] == 38055015773, "pr759_issue_comment_run_binding")
    require(tag_run["id"] == 38055054253, "pr759_issue_comment_run_binding")
    exact_droid_receipt(case, 6097886070, "https://github.com/magnus919/SlopSearX/actions/runs/38055015773")
    exact_droid_receipt(case, 6097890803, "https://github.com/magnus919/SlopSearX/actions/runs/38055054253")
    run = code_review_run
    require(checkout(evidence["job_log_excerpt"]["lines"]) == (head, base), "security_receipt_snapshot_mismatch")
    require(run["head_sha"] == head, "security_run_head_mismatch")
    job = evidence["jobs"]["record"]["jobs"][0]
    require(job["head_sha"] == head and job["html_url"].startswith(run["html_url"] + "/job/"), "security_job_binding")
    receipt = exact_droid_receipt(case, 6097886070, "https://github.com/magnus919/SlopSearX/actions/runs/38055015773")
    require(
        datetime.fromisoformat(receipt["created_at"].replace("Z", "+00:00"))
        < datetime.fromisoformat(job["completed_at"].replace("Z", "+00:00")),
        "security_receipt_not_final",
    )
    require(
        any("full output hidden" in line for line in evidence["job_log_excerpt"]["lines"]), "final_output_missingness"
    )
    return "exact_base_head_linked_security_receipt_predates_final_review_completion_full_final_output_hidden"


def validate_case(row: dict[str, Any], case: dict[str, Any], supports: dict[str, Any]) -> str:
    observation(case)
    records = project_records(case)
    require(
        sorted(row["droid_records"], key=lambda r: r["id"]) == sorted(records, key=lambda r: r["id"]),
        "arbitrary_bot_attribution_or_projection",
    )
    matches = original_matches(case, records)
    require(
        sorted(row["head_matched_original_droid_record_ids"]) == sorted(matches), "original_commit_not_current_head"
    )
    expected_surfaces = {"reviews", "comments", "issue_comments"}
    case_surfaces = case["surfaces"]
    require(isinstance(case_surfaces, dict), "surface_inventory")
    expected_surfaces = set(case_surfaces)
    validate_surface_maps(row, expected_surfaces)
    counts, statuses = {}, {}
    for name, surface in case["surfaces"].items():
        statuses[name] = surface["status"]
        counts[name] = len(surface["records"]) if surface["status"] == "captured" else None
        repo = case["identity"]["repository"]
        number = row["case_id"].rsplit("pr", 1)[1]
        route = f"issues/{number}/comments" if name == "issue_comments" else f"pulls/{number}/{name}"
        expected = f"https://api.github.com/repos/{repo['owner']}/{repo['name']}/{route}?per_page=100&page=1"
        require(surface["source_url"] == expected, "surface_identity_url_mismatch")
    require(row["surface_counts"] == counts and row["surface_status"] == statuses, "surface_gap_or_count_mismatch")
    cid = row["case_id"]
    support_name = f"support/slopsearx-pr{cid.rsplit('pr', 1)[1]}-receipt-links.json"
    if support_name in supports:
        reason = receipt_reason(case, supports[support_name])
    elif records:
        require(not matches, "head_match_without_base_evidence")
        reason = "droid_review_original_head_mismatch"
    elif cid == "qm1-codereview-pr289":
        require(
            all(r["user"] != DROID for s in case["surfaces"].values() for r in s.get("records", [])), "codeql_not_droid"
        )
        reason = "only_codeql_bot_review_on_original_head_mismatch_not_droid"
    elif any(v != "captured" for v in statuses.values()):
        reason = "no_droid_in_captured_reviews_comment_surface_over_cap_uninspected"
    else:
        reason = "no_attributable_droid_records_in_inspected_surfaces"
    require(row["reason"] == reason, "missingness_reason_mismatch")
    return reason


def validate_package(package: Path = DEFAULT_PACKAGE, *, root: Path = ROOT) -> dict[str, Any]:
    index = strict_json(read_bounded(package / "index.json", CAP))
    index_schema(index)
    manifest = load(root / DEFAULT_MANIFEST)
    corpus = pinned(root, manifest["inputs"]["corpus"])
    identities = {c["identity"]["case_id"]: c["identity"] for c in corpus["cases"]}
    require(
        {c["identity"]["case_id"]: c["identity"] for c in manifest["cases"]} == identities,
        "frozen_manifest_identity_mismatch",
    )
    ids = [r["case_id"] for r in index["cases"]]
    require(len(set(ids)) == len(ids) and set(ids) == set(identities), "frozen_case_set_mismatch")
    supports, sizes = {}, {}
    for ref in index["support"]:
        require(ref["path"] not in supports, "duplicate_reference")
        value, size = reference(package, ref, "support")
        name = Path(ref["path"]).name
        if name != "attribution-pr464.json" and not re.fullmatch(
            r"slopsearx-pr(745|746|759)-receipt-links\.json", name
        ):
            raise ObservationError("invalid_support_filename")
        support(value, expected_ref_path=ref["path"])
        supports[ref["path"]], sizes[ref["path"]] = value, size
    expected_support = {
        "support/attribution-pr464.json",
        *(f"support/slopsearx-pr{n}-receipt-links.json" for n in (745, 746, 759)),
    }
    require(set(supports) == expected_support, "support_inventory")
    attribution = supports["support/attribution-pr464.json"]
    require(
        all(r["user"] == DROID for s in attribution["surfaces"] for r in s["records"]), "untrusted_droid_attribution"
    )
    require(
        all(r["commit_id"] == attribution["known_head_sha"] for s in attribution["surfaces"] for r in s["records"]),
        "attribution_original_head",
    )
    reasons: Counter[str] = Counter()
    surfaces: Counter[str] = Counter()
    referenced = set(supports)
    largest = 0
    for row in index["cases"]:
        require(row["path"] == f"cases/{row['case_id']}.json", "case_path_identity")
        case, size = reference(package, row, "cases")
        require(case["identity"] == identities[row["case_id"]], "full_frozen_identity_mismatch")
        reasons[validate_case(row, case, supports)] += 1
        surfaces.update(s["status"] for s in case["surfaces"].values())
        support_name = f"support/slopsearx-pr{row['case_id'].rsplit('pr', 1)[1]}-receipt-links.json"
        aggregate = size + sizes["support/attribution-pr464.json"] + sizes.get(support_name, 0)
        require(aggregate <= CAP, "case_aggregate_over_cap")
        largest = max(largest, aggregate)
        require(row["path"] not in referenced, "duplicate_reference")
        referenced.add(row["path"])
    actual = {
        str(p.relative_to(package)) for d in ("cases", "support") for p in (package / d).rglob("*") if p.is_file()
    }
    require(actual == referenced and len(referenced) == 45, "unindexed_or_missing_evidence")
    expected_summary = {
        "accepted_cases": 5,
        "actual_pairs": 0,
        "captured_surface_count": surfaces["captured"],
        "complete_incumbent_outputs": 0,
        "fetched_surface_count": sum(surfaces.values()),
        "frozen_cases": len(ids),
        "identity_bound_security_receipt_cases": 1,
        "original_head_matched_review_case_base_mismatches": 1,
        "original_head_matched_review_cases": 1,
        "over_cap_surfaces": surfaces["response_over_capture_cap"],
        "refused_accuracy": True,
    }
    require(index["summary"] == expected_summary, "summary_not_supported")
    return {
        "contract": "qm4-offline-observation-validation.v1",
        "identities_checked": len(ids),
        "hashed_files_checked": len(referenced),
        "largest_case_aggregate_bytes": largest,
        "surface_status_counts": dict(sorted(surfaces.items())),
        "missing_reasons": dict(sorted(reasons.items())),
        "complete_incumbent_outputs": 0,
        "actual_pairs": 0,
        "predictions_created": False,
        "provider_execution_authenticated": False,
        "qm4_closed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, default=DEFAULT_PACKAGE)
    args = parser.parse_args()
    try:
        result = validate_package(args.package)
    except (ObservationError, OSError, KeyError, IndexError, TypeError, ValueError, AttributeError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"valid": True, **result}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
