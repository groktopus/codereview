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


MAX_EVIDENCE_NODES = 100_000
MAX_EVIDENCE_DEPTH = 256


def walk(value: Any, key: str = "") -> None:
    """Validate typed evidence iteratively with explicit resource bounds."""
    pending: list[tuple[Any, str, int]] = [(value, key, 0)]
    visited = 0
    while pending:
        current, current_key, depth = pending.pop()
        visited += 1
        require(visited <= MAX_EVIDENCE_NODES, "evidence_node_limit")
        require(depth <= MAX_EVIDENCE_DEPTH, "evidence_depth_limit")
        if current_key == "model_identity":
            model(current)
        elif current_key == "captured_at" or (current_key.endswith("_at") and current is not None):
            timestamp(current)
        elif current_key in {"source_url", "html_url"}:
            url(current, "api.github.com" if current_key == "source_url" else "github.com")
        elif current_key in {"sha", "commit_id", "original_commit_id", "merge_commit_sha"} or current_key.endswith(
            "_sha"
        ):
            if current is not None:
                require(
                    isinstance(current, str) and re.fullmatch(r"[0-9a-f]{40}", current) is not None, "invalid_commit"
                )
        elif current_key.endswith("sha256"):
            require(isinstance(current, str) and re.fullmatch(r"[0-9a-f]{64}", current) is not None, "invalid_sha256")
        elif current_key in {
            "id",
            "number",
            "workflow_id",
            "pull_request_review_id",
            "response_bytes",
            "source_bytes",
            "bytes",
        }:
            integer(current)
        elif isinstance(current, dict):
            require(depth < MAX_EVIDENCE_DEPTH, "evidence_depth_limit")
            pending.extend((child, name, depth + 1) for name, child in current.items())
        elif isinstance(current, list):
            require(depth < MAX_EVIDENCE_DEPTH, "evidence_depth_limit")
            pending.extend((child, current_key, depth + 1) for child in current)


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
    expected_urls = {
        "reviews": f"https://api.github.com/repos/{value['identity']['repository']['owner']}/{value['identity']['repository']['name']}/pulls/{value['identity']['case_id'].rsplit('pr', 1)[-1]}/reviews?per_page=100&page=1",
        "comments": f"https://api.github.com/repos/{value['identity']['repository']['owner']}/{value['identity']['repository']['name']}/pulls/{value['identity']['case_id'].rsplit('pr', 1)[-1]}/comments?per_page=100&page=1",
        "issue_comments": f"https://api.github.com/repos/{value['identity']['repository']['owner']}/{value['identity']['repository']['name']}/issues/{value['identity']['case_id'].rsplit('pr', 1)[-1]}/comments?per_page=100&page=1",
    }
    for name, surface in value["surfaces"].items():
        require(isinstance(surface, dict), "expected_surface_object")
        require(name in expected_urls, "unknown_surface_name")
        require(surface.get("source_url") == expected_urls[name], "surface_source_identity_mismatch")
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


def support_source_contract(value: dict[str, Any], ref_path: str) -> None:
    """Bind retained support envelopes to the exact captured API endpoints."""
    base = "https://api.github.com/repos/magnus919/SlopSearX/"
    endpoints: dict[str, tuple[tuple[tuple[str | int, ...], str], ...]] = {
        "support/attribution-pr464.json": (
            (("surfaces", 0, "source_url"), "pulls/464/reviews?per_page=100&page=1"),
            (("surfaces", 1, "source_url"), "pulls/464/comments?per_page=100&page=1"),
        ),
        "support/slopsearx-pr745-receipt-links.json": (
            (("pr_metadata_at_capture", "source_url"), "pulls/745"),
            (("runs", 0, "source_url"), "actions/runs/37993871997"),
        ),
        "support/slopsearx-pr746-receipt-links.json": (
            (("records", 0, "source_url"), "pulls/746"),
            (("records", 1, "source_url"), "issues/746/comments?per_page=100&page=1"),
            (("records", 2, "source_url"), "actions/runs/37999126510"),
            (("records", 3, "source_url"), "actions/jobs/114052602113/logs"),
        ),
        "support/slopsearx-pr759-receipt-links.json": (
            (("pr_metadata_at_capture", "source_url"), "pulls/759"),
            (("runs", 0, "source_url"), "actions/runs/38055015773"),
            (("runs", 1, "source_url"), "actions/runs/38055054253"),
            (("jobs", "source_url"), "actions/runs/38055015773/jobs?per_page=100&page=1"),
            (("job_log_excerpt", "source_url"), "actions/jobs/114221572962/logs"),
        ),
    }
    require(ref_path in endpoints, "support_path_not_allowlisted")
    for path, endpoint in endpoints[ref_path]:
        current: Any = value
        for part in path:
            try:
                current = current[part]
            except (KeyError, IndexError, TypeError) as exc:
                raise ObservationError("support_source_envelope_missing") from exc
        require(current == base + endpoint, "support_source_url_mismatch")


def support(value: Any, expected_ref_path: str) -> None:
    require(isinstance(value, dict), "expected_object")
    if value.get("schema") == "qm4-incumbent-attribution-support.v1":
        attribution_support(value, expected_ref_path)
    else:
        receipt_support(value, expected_ref_path)


def attribution_support(value: dict[str, Any], expected_ref_path: str) -> None:
    fields(value, "conclusion documentation_source known_base_sha known_head_sha not_corpus_case schema surfaces")
    require(expected_ref_path == "support/attribution-pr464.json", "unexpected_support_pr_binding")
    require(isinstance(value["surfaces"], list) and len(value["surfaces"]) == 2, "attribution_surface_count")
    support_source_contract(value, expected_ref_path)
    require(
        value["known_base_sha"] == "20a743f0434a1843aa00068483f608f1e213b2af"
        and value["known_head_sha"] == "bffc26f9e4bf95aca0c252e88a2396d03ece854c",
        "attribution_identity_mismatch",
    )
    for surface in value["surfaces"]:
        require(isinstance(surface, dict), "invalid_attribution_surface")
        records_for_surface = surface.get("records")
        require(
            isinstance(records_for_surface, list) and len(records_for_surface) == 1,
            "attribution_record_cardinality",
        )
        expected_record_id = {
            "https://api.github.com/repos/magnus919/SlopSearX/pulls/464/reviews?per_page=100&page=1": 5274263526,
            "https://api.github.com/repos/magnus919/SlopSearX/pulls/464/comments?per_page=100&page=1": 4068557444,
        }.get(surface["source_url"])
        require(expected_record_id is not None, "attribution_source_endpoint")
        for item in records_for_surface:
            require(isinstance(item, dict), "invalid_attribution_record")
            record(item, "", support=True)
            require(
                item["id"] == expected_record_id
                and item["user"]["id"] == 138933559
                and item["commit_id"] == value["known_head_sha"],
                "attribution_record_identity_mismatch",
            )
        envelope(surface, "records", attribution=True)
    require(value["not_corpus_case"] is True, "attribution_not_corpus_case")


def validate_receipt_envelopes(
    value: dict[str, Any],
    expected_ref_path: str,
    records: list[Any],
    runs: list[Any],
    pr_metadata: Any,
    jobs_container: Any,
    job_excerpt: Any,
) -> None:
    """Validate nested receipt data shapes before PR-specific indexing."""
    for item in records:
        require(isinstance(item, dict), "invalid_support_content")
        kinds = [key for key in ("record", "records", "lines") if key in item]
        require(len(kinds) == 1, "support_content")
        kind = kinds[0]
        if kind == "record":
            require(isinstance(item[kind], dict), "invalid_support_record")
        else:
            require(isinstance(item[kind], list) and bool(item[kind]), "empty_support_content")
        envelope(item, kind)
        if kind == "records":
            for row in item[kind]:
                record(row, "issue_comments")
        elif kind == "record":
            support_record(item[kind])
        else:
            require(all(isinstance(line, str) for line in item[kind]), "invalid_log_lines")
    for item in runs:
        require(isinstance(item, dict), "invalid_support_runs")
        envelope(item, "record")
        support_record(item["record"])
    for wrapper in (pr_metadata, jobs_container):
        if wrapper is not None:
            envelope(wrapper, "record")
            support_record(wrapper["record"])
    if job_excerpt is not None:
        envelope(job_excerpt, "lines", source_log=True)
        require(isinstance(job_excerpt["lines"], list), "invalid_support_job_log")
        require(all(isinstance(line, str) for line in job_excerpt["lines"]), "invalid_log_lines")
    support_source_contract(value, expected_ref_path)


def receipt_support(value: dict[str, Any], expected_ref_path: str) -> None:
    version = value.get("schema")
    if version != "qm4-public-receipt-link.v1":
        raise ObservationError("support_version")
    validate_public_receipt_support(value, expected_ref_path)


def validate_public_receipt_support(value: dict[str, Any], expected_ref_path: str) -> None:
    fields(value, "model_identity schema", "interpretation records runs pr_metadata_at_capture jobs job_log_excerpt")
    expected = {
        "support/slopsearx-pr745-receipt-links.json": 745,
        "support/slopsearx-pr746-receipt-links.json": 746,
        "support/slopsearx-pr759-receipt-links.json": 759,
    }
    require(expected_ref_path in expected, "support_pr_required")
    support_id = expected[expected_ref_path]
    model(value["model_identity"])
    if "interpretation" in value:
        require(
            isinstance(value["interpretation"], str) and bool(value["interpretation"].strip()),
            "invalid_support_interpretation",
        )
    records = value.get("records", [])
    runs = value.get("runs", [])
    jobs_container = value.get("jobs")
    pr_metadata = value.get("pr_metadata_at_capture")
    job_excerpt = value.get("job_log_excerpt")
    require(isinstance(records, list), "invalid_support_records")
    require(isinstance(runs, list), "invalid_support_runs")
    require(jobs_container is None or isinstance(jobs_container, dict), "invalid_support_jobs")
    require(pr_metadata is None or isinstance(pr_metadata, dict), "invalid_support_pr_metadata")
    require(job_excerpt is None or isinstance(job_excerpt, dict), "invalid_support_job_log")

    validate_receipt_envelopes(value, expected_ref_path, records, runs, pr_metadata, jobs_container, job_excerpt)

    if support_id == 745:
        validate_pr745_support(value, records, runs, pr_metadata, jobs_container, job_excerpt)
    elif support_id == 746:
        validate_pr746_support(value, records, runs, pr_metadata, jobs_container, job_excerpt)
    else:
        validate_pr759_support(value, records, runs, pr_metadata, jobs_container, job_excerpt)

    if pr_metadata is not None:
        metadata_record = pr_metadata.get("record")
        require(isinstance(metadata_record, dict), "invalid_support_record")
        require(metadata_record.get("number") == support_id, "support_pr_identity_mismatch")
    if support_id in {745, 759}:
        require(bool(runs), "empty_support_runs")
    else:
        require(not runs, "unexpected_pr746_runs")
    if "records" in value:
        require(bool(records), "empty_support_records")
    walk(value)


def validate_pr745_support(
    value: dict[str, Any],
    records: list[Any],
    runs: list[Any],
    pr_metadata: Any,
    jobs_container: Any,
    job_excerpt: Any,
) -> None:
    require(len(runs) == 1, "missing_pr745_receipt_run")
    require(
        not records and jobs_container is None and job_excerpt is None and pr_metadata is not None,
        "unexpected_pr745_support_shape",
    )
    if not isinstance(pr_metadata, dict) or not isinstance(runs[0], dict):
        raise ObservationError("missing_pr745_support_envelope")
    run_record = runs[0].get("record")
    metadata_record = pr_metadata.get("record")
    if not isinstance(run_record, dict) or not isinstance(metadata_record, dict):
        raise ObservationError("missing_pr745_support_record")
    pr_head = metadata_record.get("head")
    pr_base = metadata_record.get("base")
    if not isinstance(pr_head, dict) or not isinstance(pr_base, dict):
        raise ObservationError("pr745_metadata_snapshot_missing")
    require(
        run_record.get("id") == 37993871997
        and run_record.get("head_sha") == "d00c3d3a30b5594d5d2619d9f184a7a60acaf343",
        "pr745_run_identity",
    )
    require(
        metadata_record.get("number") == 745
        and pr_head.get("sha") == "1db229364205e35acc97442456f56a4c19a38050"
        and pr_base.get("sha") == "ebf79b983d357d51213b6eff928333e8f1cb9a92",
        "pr745_metadata_identity",
    )
    require(
        run_record.get("event") == "pull_request"
        and run_record.get("status") == "completed"
        and run_record.get("conclusion") == "success"
        and run_record.get("html_url") == "https://github.com/magnus919/SlopSearX/actions/runs/37993871997",
        "pr745_run_details",
    )


def validate_pr746_support(
    value: dict[str, Any], records: list[Any], runs: list[Any], pr_metadata: Any, jobs_container: Any, job_excerpt: Any
) -> None:
    require(not runs and len(records) == 4, "missing_pr746_expected_records")
    require(all(isinstance(item, dict) for item in records), "invalid_pr746_record_shape")
    expected_shapes = (frozenset({"record"}), frozenset({"records"}), frozenset({"record"}), frozenset({"lines"}))
    actual_shapes = tuple(frozenset(set(item) & {"record", "records", "lines"}) for item in records)
    require(actual_shapes == expected_shapes, "pr746_record_shapes")
    metadata_record = records[0]["record"]
    require(isinstance(metadata_record, dict), "pr746_metadata_shape")
    require(metadata_record.get("number") == 746, "pr746_metadata_number")
    require(metadata_record.get("base_sha") == "753aeb50821900e680ad48fe1ef5772d3179ac33", "pr746_expected_base")
    require(metadata_record.get("head_sha") == "b85c6370e842522f78e32260d38cdc0c770744c4", "pr746_review_head")
    require(len(records[1]["records"]) == 2, "pr746_comment_cardinality")
    require(len(records[3]["lines"]) == 3, "pr746_checkout_log_incomplete")
    require(
        records[1]["source_url"].endswith("/issues/746/comments?per_page=100&page=1")
        and records[2]["record"]["id"] == 37999126510
        and records[2]["record"]["head_sha"] == "8f5778a62f0b67d36626f764a47f864e39362f11",
        "pr746_linked_receipt_identity",
    )
    issue_comments = records[1]["records"]
    require(
        [item["id"] for item in issue_comments] == [6090270984, 6090272096]
        and issue_comments[0]["user"]["id"] == 138933559
        and issue_comments[1]["user"]["id"] == 942000,
        "pr746_issue_comment_run_binding",
    )
    linked_run = records[2]["record"]
    require(
        linked_run.get("event") == "pull_request"
        and linked_run.get("status") == "completed"
        and linked_run.get("conclusion") == "success"
        and linked_run.get("html_url") == "https://github.com/magnus919/SlopSearX/actions/runs/37999126510",
        "pr746_run_details",
    )
    require(
        records[3]["source_url"] == "https://api.github.com/repos/magnus919/SlopSearX/actions/jobs/114052602113/logs",
        "pr746_job_log_binding",
    )
    require(
        not runs and jobs_container is None and pr_metadata is None and job_excerpt is None,
        "unexpected_pr746_support_shape",
    )


def validate_pr759_support(
    value: dict[str, Any], records: list[Any], runs: list[Any], pr_metadata: Any, jobs_container: Any, job_excerpt: Any
) -> None:
    require(len(runs) == 2, "missing_pr759_final_state_run")
    require(
        isinstance(runs[0], dict)
        and isinstance(runs[0].get("record"), dict)
        and isinstance(runs[1], dict)
        and isinstance(runs[1].get("record"), dict),
        "invalid_pr759_runs",
    )
    if not isinstance(pr_metadata, dict) or not isinstance(jobs_container, dict) or not isinstance(job_excerpt, dict):
        raise ObservationError("pr759_required_support_envelope")
    metadata_record = pr_metadata.get("record")
    jobs_record = jobs_container.get("record")
    log_lines = job_excerpt.get("lines")
    if not isinstance(metadata_record, dict) or not isinstance(jobs_record, dict) or not isinstance(log_lines, list):
        raise ObservationError("pr759_required_support_record")
    jobs = jobs_record.get("jobs")
    if not isinstance(jobs, list) or len(jobs) != 1:
        raise ObservationError("empty_pr759_jobs")
    job = jobs[0]
    require(isinstance(job, dict), "invalid_pr759_job")
    require(jobs_record.get("total_count") == 1, "pr759_job_count_mismatch")
    metadata_head, metadata_base = metadata_record.get("head"), metadata_record.get("base")
    if not isinstance(metadata_head, dict) or not isinstance(metadata_base, dict):
        raise ObservationError("pr759_metadata_snapshot_missing")
    require(not records, "unexpected_pr759_support_shape")
    require(len(log_lines) == 7, "missing_pr759_job_log")
    code_review_run, tag_run = runs[0]["record"], runs[1]["record"]
    require(
        code_review_run.get("id") == 38055015773
        and code_review_run.get("head_sha") == "6fbd0675091420397b6757e7e87816305e9f5b58"
        and code_review_run.get("event") == "pull_request"
        and code_review_run.get("status") == "completed"
        and code_review_run.get("conclusion") == "success"
        and code_review_run.get("html_url") == "https://github.com/magnus919/SlopSearX/actions/runs/38055015773",
        "pr759_code_review_run_details",
    )
    require(
        tag_run.get("id") == 38055054253
        and tag_run.get("event") == "issue_comment"
        and tag_run.get("head_sha") == "8c69cde94436782bde13efa018c2f428f5a6881d"
        and tag_run.get("status") == "completed"
        and tag_run.get("conclusion") == "success"
        and tag_run.get("html_url") == "https://github.com/magnus919/SlopSearX/actions/runs/38055054253",
        "pr759_tag_run_on_base",
    )
    require(
        job.get("id") == 114221572962
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and job.get("head_sha") == code_review_run["head_sha"]
        and job.get("html_url") == code_review_run["html_url"] + "/job/114221572962"
        and job_excerpt.get("source_url")
        == "https://api.github.com/repos/magnus919/SlopSearX/actions/jobs/114221572962/logs",
        "pr759_job_identity",
    )
    require(
        metadata_record.get("number") == 759
        and metadata_head.get("sha") == "6fbd0675091420397b6757e7e87816305e9f5b58"
        and metadata_base.get("sha") == "8c69cde94436782bde13efa018c2f428f5a6881d",
        "pr759_metadata_identity",
    )
    require(
        any("full output hidden" in line for line in log_lines)
        and any("Artifact droid-review-debug-38055015773" in line for line in log_lines),
        "pr759_code_review_receipt_incomplete",
    )


def support_record(value: Any) -> None:
    require(isinstance(value, dict), "invalid_support_record")
    if "jobs" in value:
        fields(value, "jobs total_count")
        require(isinstance(value["jobs"], list), "invalid_support_job_runs")
        integer(value["total_count"])
        require(value["total_count"] == len(value["jobs"]), "jobs_count")
        for job in value["jobs"]:
            fields(job, "completed_at conclusion head_sha html_url id name started_at status")
            integer(job["id"])
            text(job["name"])
            require(
                job["status"] in {"completed", "in_progress", "queued", "waiting", "requested"}, "invalid_job_status"
            )
            require(
                job["conclusion"] is None
                or job["conclusion"]
                in {"success", "failure", "cancelled", "skipped", "neutral", "timed_out", "action_required", "stale"},
                "invalid_job_conclusion",
            )
            text(job["head_sha"])
            require(re.fullmatch(r"[0-9a-f]{40}", job["head_sha"]) is not None, "invalid_job_head")
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
