"""Strict offline structural schema for the frozen QM4 acquisition, not predictions.

This intentionally recognizes only the retained v1 shapes. New evidence shapes
require reviewed contract changes; arbitrary source text is never executable.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit


class ObservationError(ValueError):
    """An observation violates the retained-evidence contract."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ObservationError(reason)


def fields(value: Any, required: str, optional: str = "") -> None:
    require(isinstance(value, dict), "expected_object")
    require(set(required.split()) <= value.keys(), "missing_fields")
    require(value.keys() <= set((required + " " + optional).split()), "unknown_fields")


def text(value: Any) -> None:
    require(isinstance(value, str), "expected_string")


def integer(value: Any) -> None:
    require(type(value) is int and value >= 0, "expected_nonnegative_integer")


def timestamp(value: Any) -> None:
    text(value)
    require("T" in value, "invalid_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ObservationError("invalid_timestamp") from exc
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None, "timestamp_requires_timezone")


def url(value: Any, host: str) -> None:
    text(value)
    require(not any(c.isspace() or ord(c) < 32 for c in value), "invalid_https_url")
    try:
        parsed = urlsplit(value)
        valid = parsed.scheme == "https" and parsed.hostname == host and parsed.port in (None, 443)
    except ValueError as exc:
        raise ObservationError("invalid_https_url") from exc
    require(valid and parsed.username is None and parsed.password is None, "invalid_https_url")


def model(value: Any) -> None:
    require(value is None or (isinstance(value, str) and bool(value.strip())), "invalid_model_identity")


def walk(value: Any, key: str = "") -> None:
    """Validate typed source fields even in support records and index projections."""
    if key == "model_identity":
        model(value)
    elif key == "captured_at" or (key.endswith("_at") and value is not None):
        timestamp(value)
    elif key in {"source_url", "html_url"}:
        url(value, "api.github.com" if key == "source_url" else "github.com")
    elif key in {"sha", "commit_id", "original_commit_id", "merge_commit_sha"} or key.endswith("_sha"):
        if value is not None:
            require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None, "invalid_commit")
    elif key.endswith("sha256"):
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "invalid_sha256")
    elif key in {"id", "number", "workflow_id", "pull_request_review_id", "response_bytes", "source_bytes", "bytes"}:
        integer(value)
    elif isinstance(value, dict):
        for name, child in value.items():
            walk(child, name)
    elif isinstance(value, list):
        for child in value:
            walk(child, key)


def user(value: Any) -> None:
    fields(value, "id login type")
    integer(value["id"])
    require(value["id"] > 0, "invalid_user_id")
    require(isinstance(value["login"], str) and bool(value["login"].strip()), "invalid_user_login")
    require(value["type"] in {"Bot", "User"}, "invalid_user_type")


def record(value: Any, surface: str, *, support: bool = False) -> None:
    common = "body html_url id user"
    if support:
        fields(value, common, "commit_id original_commit_id created_at submitted_at")
    elif surface == "reviews":
        fields(value, common + " commit_id state submitted_at")
        require(
            value["state"] in {"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING"}, "review_state"
        )
    elif surface == "comments":
        fields(
            value,
            common + " commit_id original_commit_id created_at updated_at path pull_request_review_id side",
            "line original_line original_start_line start_line start_side",
        )
        text(value["path"])
        require(value["side"] in {"LEFT", "RIGHT"}, "invalid_side")
        for key in ("line", "original_line", "original_start_line", "start_line"):
            if value.get(key) is not None:
                integer(value[key])
    else:
        fields(value, common + " created_at", "updated_at")
    text(value["body"])
    if not support:
        for key in ("created_at", "updated_at", "submitted_at"):
            if key in value:
                timestamp(value[key])
    user(value["user"])
    walk(value)
    for key in ("commit_id", "original_commit_id"):
        if key in value and not support:
            require(value[key] is not None, "missing_original_commit")


def identity(value: Any) -> None:
    fields(value, "base_sha case_id family_id head_sha profile repository snapshot_id source_manifest split")
    fields(value["profile"], "profile_id sha256 version")
    fields(value["repository"], "name owner")
    fields(value["source_manifest"], "manifest_id sha256")
    walk(value)


def observation(value: Any) -> None:
    fields(value, "identity interpretation model_identity schema surfaces")
    walk(value)
    require(value["schema"] == "qm4-public-review-observation.v1", "observation_version")
    identity(value["identity"])
    require(
        value["interpretation"]
        == {
            "exact_authorship_requires_original_commit_id": True,
            "no_accuracy_claim": True,
            "review_comment_commit_id_can_be_remapped": True,
            "status": "not_normalized",
        },
        "unsafe_interpretation",
    )
    fields(value["surfaces"], "reviews comments", "issue_comments")
    for name, surface in value["surfaces"].items():
        required = "captured_at response_bytes source_url status"
        if surface.get("status") == "response_over_capture_cap":
            fields(surface, required)
            require(surface["response_bytes"] > 262144, "invalid_capture_gap")
        else:
            fields(surface, required + " page pagination per_page records response_sha256")
            require(surface["status"] == "captured", "surface_status")
            integer(surface["page"])
            integer(surface["per_page"])
            require(surface["page"] == 1 and surface["per_page"] == 100, "pagination_bounds")
            require(surface["pagination"] == "complete_for_endpoint_at_capture", "pagination_gap")
            require(isinstance(surface["records"], list) and len(surface["records"]) < 100, "pagination_gap")
            require(surface["response_bytes"] <= 262144, "response_over_cap")
            for item in surface["records"]:
                record(item, name)
    walk(value)


def envelope(value: Any, content: str, *, source_log: bool = False, attribution: bool = False) -> None:
    required = "captured_at source_url " + content
    required += (
        " response_sha256"
        if attribution
        else " source_bytes source_sha256"
        if source_log
        else " response_bytes response_sha256"
    )
    fields(value, required, "selection" if source_log else "")
    walk(value)


def support(value: Any, expected_ref_path: str) -> None:
    """Validate only the support object shape authorized by its pinned index path."""
    require(isinstance(value, dict), "expected_object")
    if expected_ref_path == "support/attribution-pr464.json":
        fields(value, "conclusion documentation_source known_base_sha known_head_sha not_corpus_case schema surfaces")
        require(value["schema"] == "qm4-incumbent-attribution-support.v1", "support_version")
        require(value["not_corpus_case"] is True, "attribution_not_corpus")
        require(isinstance(value["surfaces"], list) and len(value["surfaces"]) == 2, "attribution_surface_count")
        for surface in value["surfaces"]:
            envelope(surface, "records", attribution=True)
            for item in surface["records"]:
                record(item, "", support=True)
        return

    expected = {
        "support/slopsearx-pr745-receipt-links.json": "745",
        "support/slopsearx-pr746-receipt-links.json": "746",
        "support/slopsearx-pr759-receipt-links.json": "759",
    }
    require(expected_ref_path in expected, "support_path_not_allowlisted")
    pr = expected[expected_ref_path]
    require(value.get("schema") == "qm4-public-receipt-link.v1", "support_version")
    fields(value, "model_identity schema", "interpretation records runs pr_metadata_at_capture jobs job_log_excerpt")
    records = value.get("records", [])
    runs = value.get("runs", [])
    require(isinstance(records, list) and isinstance(runs, list), "invalid_support_collections")

    if pr == "745":
        require(len(runs) >= 1 and not records, "pr745_required_run")
        require("jobs" not in value and "job_log_excerpt" not in value, "pr745_unexpected_content")
    elif pr == "746":
        require(not runs and len(records) == 4, "pr746_record_cardinality")
        expected_shapes = (frozenset({"record"}), frozenset({"records"}), frozenset({"record"}), frozenset({"lines"}))
        require(
            tuple(
                frozenset(set(item) & {"record", "records", "lines"}) if isinstance(item, dict) else frozenset()
                for item in records
            )
            == expected_shapes,
            "pr746_record_shapes",
        )
        require(len(records[1]["records"]) == 2, "pr746_comment_cardinality")
        require(len(records[3]["lines"]) >= 3, "pr746_checkout_log_incomplete")
        require(
            "jobs" not in value and "job_log_excerpt" not in value and "pr_metadata_at_capture" not in value,
            "pr746_unexpected_content",
        )
    else:
        require(not records and len(runs) >= 1, "pr759_required_run")
        require(
            "jobs" in value and "job_log_excerpt" in value and "pr_metadata_at_capture" in value,
            "pr759_required_content",
        )

    if "pr_metadata_at_capture" in value:
        envelope(value["pr_metadata_at_capture"], "record")
        support_record(value["pr_metadata_at_capture"]["record"])
        require(value["pr_metadata_at_capture"]["record"]["number"] == int(pr), "support_pr_identity_mismatch")
    if "jobs" in value:
        envelope(value["jobs"], "record")
        support_record(value["jobs"]["record"])
        require(bool(value["jobs"]["record"]["jobs"]), "empty_pr759_jobs")
    if "job_log_excerpt" in value:
        envelope(value["job_log_excerpt"], "lines", source_log=True)
        require(bool(value["job_log_excerpt"]["lines"]), "empty_pr759_job_log")
    for item in records:
        require(isinstance(item, dict), "invalid_support_content")
        kind = next((k for k in ("record", "records", "lines") if k in item), "")
        require(bool(kind), "support_content")
        if kind in {"records", "lines"}:
            require(isinstance(item[kind], list) and bool(item[kind]), "empty_support_content")
        else:
            require(isinstance(item[kind], dict), "invalid_support_record")
        envelope(item, kind)
        if kind == "records":
            for row in item[kind]:
                record(row, "issue_comments")
        elif kind == "record":
            support_record(item[kind])
        else:
            require(all(isinstance(line, str) for line in item[kind]), "invalid_log_lines")
    for item in runs:
        envelope(item, "record")
        support_record(item["record"])
    walk(value)


def support_record(value: Any) -> None:
    if "jobs" in value:
        fields(value, "jobs total_count")
        require(isinstance(value["jobs"], list), "invalid_jobs")
        require(value["total_count"] == len(value["jobs"]), "jobs_count")
        for job in value["jobs"]:
            fields(job, "completed_at conclusion head_sha html_url id name started_at status")
    elif "base" in value:
        fields(value, "base created_at head html_url merge_commit_sha merged_at number state updated_at")
        fields(value["base"], "ref sha")
        fields(value["head"], "ref sha")
    elif "base_sha" in value:
        fields(value, "base_sha head_sha html_url number")
    else:
        fields(
            value,
            "conclusion created_at event head_sha html_url id status updated_at",
            "head_branch name path pull_requests run_started_at workflow_id",
        )
        require(value.get("pull_requests", []) == [], "unrecognized_run_pr_binding")
    walk(value)
