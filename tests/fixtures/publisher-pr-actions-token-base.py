"""Guarded GitHub review publishing primitives, disabled by default."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from contextlib import closing
from typing import Callable


class PublicationRejected(ValueError):
    """A review is not eligible for a publishing attempt."""


class SQLiteEffectStore:
    """Durable local idempotency claims; callers must serialize remote runners."""

    def __init__(self, path: str, deadline_at: float | None = None):
        self.path = os.fspath(path)
        self.deadline_at = deadline_at

    def _connect(self):
        timeout = 10.0
        if self.deadline_at is not None:
            timeout = min(timeout, self.deadline_at - time.monotonic())
        if timeout <= 0:
            raise TimeoutError("effect store deadline exceeded")
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=timeout, isolation_level=None)
        os.chmod(self.path, 0o600)
        connection.execute(
            "CREATE TABLE IF NOT EXISTS effects (effect_key TEXT PRIMARY KEY, state TEXT NOT NULL, detail TEXT)"
        )
        return connection

    def lookup(self, key: str) -> str:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT state FROM effects WHERE effect_key = ?", (key,)).fetchone()
        return "not_found" if row is None else ("confirmed" if row[0] == "confirmed" else "unknown")

    def claim(self, key: str) -> str:
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT state FROM effects WHERE effect_key = ?", (key,)).fetchone()
                if row is not None:
                    connection.commit()
                    return "confirmed" if row[0] == "confirmed" else "in_progress"
                connection.execute("INSERT INTO effects(effect_key, state) VALUES (?, 'claimed')", (key,))
                connection.commit()
                return "acquired"
            except Exception:
                connection.rollback()
                raise

    def confirm(self, key: str, detail: str = "") -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                "UPDATE effects SET state = 'confirmed', detail = ? WHERE effect_key = ?", (detail[:500], key)
            )

    def release(self, key: str) -> None:
        with closing(self._connect()) as connection:
            connection.execute("DELETE FROM effects WHERE effect_key = ? AND state = 'claimed'", (key,))


def _canonical_hash(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def effect_idempotency_key(
    result: dict, effect_type: str = "PULL_REQUEST_REVIEW", rendered_review: str | None = None
) -> str:
    if rendered_review is None:
        from .report import render_report

        try:
            body = render_report(result)
        except (TypeError, ValueError):
            raise PublicationRejected("canonical review report is invalid") from None
    else:
        body = rendered_review
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest() if isinstance(body, str) else None
    stable_result_hash = _canonical_hash(
        {
            "repository": result.get("repository"),
            "pull_request_number": result.get("pull_request_number"),
            "base_sha": result.get("base_sha"),
            "head_sha": result.get("head_sha"),
            "profile_version": result.get("project_profile_version"),
            "disposition": result.get("disposition"),
            "review_body_hash": body_hash,
        }
    )
    identity = {
        "repository": result.get("repository"),
        "pull_request_number": result.get("pull_request_number"),
        "head_sha": result.get("head_sha"),
        "disposition": result.get("disposition"),
        "effect_type": effect_type,
        "result_hash": stable_result_hash,
    }
    return "effect-" + _canonical_hash(identity)


def _validate_result(result: dict) -> None:
    if not isinstance(result, dict):
        raise PublicationRejected("review result is invalid")
    supplied_hash = result.get("result_hash")
    unsigned = {key: value for key, value in result.items() if key != "result_hash"}
    if not isinstance(supplied_hash, str) or _canonical_hash(unsigned) != supplied_hash:
        raise PublicationRejected("review result hash is invalid")
    repository = result.get("repository")
    number = result.get("pull_request_number")
    head = result.get("head_sha")
    if (
        not isinstance(repository, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
        or isinstance(number, bool)
        or not isinstance(number, int)
        or number < 1
        or not isinstance(head, str)
        or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", head)
        or not isinstance(result.get("base_sha"), str)
        or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", result.get("base_sha", ""))
        or not isinstance(result.get("project_profile_version"), str)
        or not result.get("project_profile_version")
        or not isinstance(result.get("policy_valid"), bool)
        or not isinstance(result.get("allow_empty_approve"), bool)
        or not isinstance(result.get("findings"), list)
        or not isinstance(result.get("coverage_ledger"), list)
        or not isinstance(result.get("task_results"), dict)
        or not isinstance(result.get("ledger"), dict)
        or not isinstance(result.get("evidence_index"), dict)
        or result.get("coverage_state") not in {"COMPLETE", "PARTIAL", "NOT_STARTED"}
    ):
        raise PublicationRejected("review result contract is invalid")
    if result.get("freshness") != "CURRENT":
        raise PublicationRejected("review freshness is not current")
    if result.get("disposition") not in {"APPROVE", "REQUEST_CHANGES", "COMMENT", "INCOMPLETE"}:
        raise PublicationRejected("review disposition cannot be published")
    if any(
        not isinstance(entry, dict)
        or not isinstance(entry.get("required", True), bool)
        or not isinstance(entry.get("obligation_id"), str)
        or not entry.get("obligation_id")
        for entry in result["coverage_ledger"]
    ):
        raise PublicationRejected("review coverage ledger is invalid")
    obligation_ids = [entry["obligation_id"] for entry in result["coverage_ledger"]]
    if len(obligation_ids) != len(set(obligation_ids)):
        raise PublicationRejected("review coverage ledger is invalid")
    required = [entry for entry in result["coverage_ledger"] if entry.get("required", True)]
    # A vacuously complete empty ledger is not evidence of a completed review.
    # Empty-diff publishing needs a separately versioned immutable authority.
    if not required:
        raise PublicationRejected("review has no required coverage obligations")
    if any(entry.get("state") not in {"COMPLETE", "PARTIAL", "NOT_STARTED"} for entry in required):
        raise PublicationRejected("review coverage ledger is invalid")
    aggregate = (
        "COMPLETE"
        if all(entry["state"] == "COMPLETE" for entry in required)
        else "NOT_STARTED"
        if not any(entry["state"] != "NOT_STARTED" for entry in required)
        else "PARTIAL"
    )
    if aggregate != result["coverage_state"]:
        raise PublicationRejected("review coverage state is inconsistent")
    if any(
        not isinstance(finding, dict)
        or finding.get("status") not in {"ACCEPTED", "NEEDS_EVIDENCE", "CONTRADICTED", "UNSUPPORTED"}
        or finding.get("blocking_class") not in {"BLOCKING", "NON_BLOCKING", "UNRESOLVED"}
        or (finding.get("blocking_class") == "BLOCKING" and finding.get("status") != "ACCEPTED")
        for finding in result["findings"]
    ):
        raise PublicationRejected("review findings are invalid")
    sections = result.get("report_sections")
    if not isinstance(sections, dict):
        raise PublicationRejected("review report sections are invalid")
    for section, blocking_class in (("blockers", "BLOCKING"), ("suggested_improvements", "NON_BLOCKING")):
        rendered_ids = (
            {
                item.get("finding_id")
                for item in sections.get(section, [])
                if isinstance(item, dict) and isinstance(item.get("finding_id"), str)
            }
            if isinstance(sections.get(section), list)
            else set()
        )
        expected_ids = {
            finding.get("finding_id")
            for finding in result["findings"]
            if finding.get("status") == "ACCEPTED" and finding.get("blocking_class") == blocking_class
        }
        if expected_ids != rendered_ids:
            raise PublicationRejected("canonical report findings do not match accepted findings")
    _validate_accepted_findings(result)
    _validate_report_notes(result)
    # Reuse the production reducer; publication must not reinterpret a
    # rehashed but internally inconsistent disposition as trustworthy.
    from .engine import _reduce

    allow_empty_approve = result["allow_empty_approve"]
    try:
        expected = _reduce(result, allow_empty_approve, result["policy_valid"])
    except (KeyError, TypeError):
        raise PublicationRejected("review reducer inputs are invalid") from None
    if expected != result["disposition"]:
        raise PublicationRejected("review disposition is inconsistent with deterministic policy")


def _validate_accepted_findings(result: dict) -> None:
    """Rebind every publishable finding to a validated candidate and its task evidence."""
    from .engine import _hash
    from .reconcile import stable_candidate_id

    task_results = result["task_results"]
    ledger = result["ledger"]
    records = ledger.get("candidate_records")
    evidence_index = result["evidence_index"]
    if not isinstance(records, list):
        raise PublicationRejected("review candidate ledger is invalid")
    record_by_id = {
        record.get("candidate_id"): record
        for record in records
        if isinstance(record, dict) and isinstance(record.get("candidate_id"), str)
    }
    if len(record_by_id) != sum(isinstance(record, dict) for record in records):
        raise PublicationRejected("review candidate ledger is invalid")
    for finding in result["findings"]:
        if finding.get("status") != "ACCEPTED":
            continue
        location = finding.get("location")
        path = finding.get("path")
        if (
            not isinstance(location, dict)
            or location.get("kind") not in {"line", "file"}
            or not isinstance(path, str)
            or not path
            or location.get("path") != path
            or location.get("side") not in {"BASE", "HEAD"}
            or (
                location.get("kind") == "line"
                and (
                    isinstance(location.get("line"), bool)
                    or not isinstance(location.get("line"), int)
                    or location["line"] < 1
                )
            )
            or (
                location.get("kind") == "file"
                and (
                    location.get("line") is not None
                    or not isinstance(location.get("reason"), str)
                    or not location.get("reason")
                )
            )
        ):
            raise PublicationRejected("accepted finding location is invalid")
        candidate_ids = finding.get("candidate_ids", [finding.get("candidate_id")])
        task_ids = finding.get("task_ids", [finding.get("task_id")])
        refs = finding.get("evidence_refs")
        if (
            not isinstance(candidate_ids, list)
            or not candidate_ids
            or any(not isinstance(item, str) or not item for item in candidate_ids)
            or not isinstance(task_ids, list)
            or not task_ids
            or any(not isinstance(item, str) or not item for item in task_ids)
            or not isinstance(refs, list)
            or not refs
            or any(not isinstance(item, str) or item not in evidence_index for item in refs)
        ):
            raise PublicationRejected("accepted finding evidence is invalid")
        if not set(task_ids).issubset(task_results):
            raise PublicationRejected("accepted finding task binding is invalid")
        matching_anchor = False
        expected_revision = result["base_sha"] if location["side"] == "BASE" else result["head_sha"]
        bound_refs = set()
        for evidence_id in refs:
            evidence = evidence_index[evidence_id]
            if not isinstance(evidence, dict):
                raise PublicationRejected("accepted finding evidence is invalid")
            content_hash = evidence.get("content_hash")
            if not isinstance(content_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", content_hash):
                raise PublicationRejected("accepted finding evidence integrity is invalid")
            if evidence.get("path") == path and evidence.get("source_revision") == expected_revision:
                start, end = evidence.get("line_start"), evidence.get("line_end")
                if location["kind"] == "file" or (
                    (start is None and end is None)
                    or (
                        isinstance(start, int)
                        and not isinstance(start, bool)
                        and isinstance(end, int)
                        and not isinstance(end, bool)
                        and start <= location["line"] <= end
                    )
                ):
                    matching_anchor = True
        if not matching_anchor:
            raise PublicationRejected("accepted finding lacks source-bound evidence")

        for candidate_id in candidate_ids:
            record = record_by_id.get(candidate_id)
            if (
                not isinstance(record, dict)
                or record.get("validation_state") != "VALID"
                or record.get("finding_id") != finding.get("finding_id")
                or record.get("snapshot_id") != result.get("snapshot_id")
                or record.get("task_id") not in task_ids
            ):
                raise PublicationRejected("accepted finding candidate binding is invalid")
            task_id = record["task_id"]
            task = task_results[task_id]
            if not isinstance(task, dict) or task.get("status") != "SUCCEEDED":
                raise PublicationRejected("accepted finding task is incomplete")
            payload = task.get("payload")
            inputs = task.get("input_evidence_ids")
            if not isinstance(payload, dict) or not isinstance(inputs, list):
                raise PublicationRejected("accepted finding was not supported by its task inputs")
            candidate = record.get("raw")
            if not isinstance(candidate, dict) or candidate.get("finding_id") is not None:
                # The engine enriches normalized candidates in the ledger, but
                # keeps original provider candidates in the durable task payload.
                raise PublicationRejected("accepted finding candidate record is invalid")
            task_candidates = payload.get("finding_candidates")
            if not isinstance(task_candidates, list):
                raise PublicationRejected("accepted finding source candidate is missing")
            raw_index = next(
                (
                    index
                    for index, raw in enumerate(task_candidates)
                    if _hash({"task_id": task_id, "index": index, "raw": raw})[:24] == candidate_id
                ),
                None,
            )
            if raw_index is None:
                raise PublicationRejected("accepted finding source candidate is unbound")
            source_candidate = task_candidates[raw_index]
            if not isinstance(source_candidate, dict) or any(
                candidate.get(key) != value for key, value in source_candidate.items()
            ):
                raise PublicationRejected("accepted finding differs from its provider candidate")
            if stable_candidate_id(result["snapshot_id"], candidate) != finding.get("finding_id"):
                raise PublicationRejected("accepted finding identity is inconsistent")
            if (
                candidate.get("unit_id") != finding.get("unit_id")
                or candidate.get("location") != location
                or not isinstance(candidate.get("evidence_refs"), list)
                or not set(candidate.get("evidence_refs", [])).issubset(inputs)
                or not set(candidate.get("evidence_refs", [])).issubset(refs)
            ):
                raise PublicationRejected("accepted finding source candidate differs from report")
            bound_refs.update(candidate["evidence_refs"])
        if bound_refs != set(refs):
            raise PublicationRejected("accepted finding evidence references are inconsistent")


def _validate_report_notes(result: dict) -> None:
    """Bind optional user-facing notes to V4 provider notes and delivered evidence."""
    from .engine import _hash

    task_results = result["task_results"]
    evidence_index = result["evidence_index"]
    sections = result["report_sections"]
    for section, detail_key in (("specific_strengths", "why_it_matters"), ("future_guidance", "guidance")):
        rows = sections.get(section)
        if not isinstance(rows, list):
            raise PublicationRejected("review report note section is invalid")
        for note in rows:
            if not isinstance(note, dict):
                raise PublicationRejected("review report note is invalid")
            unit_id = note.get("unit_id")
            basis = {key: note.get(key) for key in ("unit_id", "title", "observation")}
            detail = note.get(detail_key)
            if not isinstance(detail, str) or not detail:
                raise PublicationRejected("review report note is invalid")
            basis["detail"] = detail
            expected_id = "note-" + _hash({"snapshot_id": result["snapshot_id"], "kind": section, **basis})[:20]
            task_ids = note.get("task_ids")
            refs = note.get("evidence_refs")
            if (
                note.get("finding_id") != expected_id
                or note.get("note_id") != expected_id
                or note.get("snapshot_id") != result["snapshot_id"]
                or not isinstance(unit_id, str)
                or not isinstance(task_ids, list)
                or not task_ids
                or not isinstance(refs, list)
                or not refs
                or any(not isinstance(ref, str) or ref not in evidence_index for ref in refs)
                or not set(task_ids).issubset(task_results)
            ):
                raise PublicationRejected("review report note provenance is invalid")
            bound_refs = set()
            for task_id in task_ids:
                task = task_results[task_id]
                if not isinstance(task, dict) or task.get("status") != "SUCCEEDED":
                    raise PublicationRejected("review report note task is incomplete")
                if unit_id not in task.get("unit_ids", []):
                    raise PublicationRejected("review report note unit is outside task scope")
                payload = task.get("payload")
                inputs = task.get("input_evidence_ids")
                source_notes = payload.get(section) if isinstance(payload, dict) else None
                if not isinstance(inputs, list) or not isinstance(source_notes, list):
                    raise PublicationRejected("review report note source is missing")
                source_match = next(
                    (
                        item
                        for item in source_notes
                        if isinstance(item, dict)
                        and item.get("unit_id") == unit_id
                        and item.get("title") == note.get("title")
                        and item.get("observation") == note.get("observation")
                        and item.get("detail") == detail
                    ),
                    None,
                )
                if not isinstance(source_match, dict) or not set(source_match.get("evidence_refs", [])).issubset(
                    inputs
                ):
                    raise PublicationRejected("review report note is not bound to task evidence")
                bound_refs.update(source_match.get("evidence_refs", []))
            if bound_refs != set(refs):
                raise PublicationRejected("review report note evidence is inconsistent")


def prepare_publication(
    result: dict, config: dict, effect_policy: str, authorized: bool, rendered_review: str | None = None
) -> dict:
    """Validate authority and build the narrow review request."""
    if effect_policy != "PUBLISH_REVIEW":
        raise PublicationRejected("effect policy does not permit review publishing")
    if not isinstance(config, dict) or config.get("schema_version") != "1.0":
        raise PublicationRejected("publisher configuration schema is invalid")
    if config.get("enabled") is not True:
        raise PublicationRejected("review publishing is disabled")
    if authorized is not True:
        raise PublicationRejected("explicit operator authorization is required")
    return preview_publication(result, config, rendered_review)


def preview_publication(result: dict, config: dict, rendered_review: str | None = None) -> dict:
    """Build a truthful, side-effect-free preview without granting authority."""
    _validate_result(result)
    if not isinstance(config, dict) or config.get("schema_version") != "1.0":
        raise PublicationRejected("publisher configuration schema is invalid")
    repository = result.get("repository")
    number = result.get("pull_request_number")
    head = result.get("head_sha")
    if (
        not isinstance(repository, str)
        or not repository
        or isinstance(number, bool)
        or not isinstance(number, int)
        or number < 1
    ):
        raise PublicationRejected("pull request identity is invalid")
    if not isinstance(head, str) or len(head) not in {40, 64} or any(char not in "0123456789abcdef" for char in head):
        raise PublicationRejected("review head SHA is invalid")
    allowed_repositories = config.get("allowed_repositories")
    if not isinstance(allowed_repositories, list) or repository not in allowed_repositories:
        raise PublicationRejected("repository is outside publisher authorization scope")
    allowed_dispositions = config.get("allowed_dispositions")
    source_disposition = result.get("disposition")
    if source_disposition == "INCOMPLETE":
        if result.get("policy_valid") is not True:
            raise PublicationRejected("review policy is invalid")
        review_event = "COMMENT"
    elif source_disposition in {"APPROVE", "REQUEST_CHANGES", "COMMENT"}:
        review_event = source_disposition
    else:
        raise PublicationRejected("review disposition cannot be published")
    if not isinstance(allowed_dispositions, list) or review_event not in allowed_dispositions:
        raise PublicationRejected("disposition is outside publisher authorization scope")
    from .report import render_report

    try:
        canonical_body = render_report(result)
    except (TypeError, ValueError):
        raise PublicationRejected("canonical review report is invalid") from None
    if rendered_review is not None and rendered_review != canonical_body:
        raise PublicationRejected("review body differs from canonical result")
    body = canonical_body
    max_body = config.get("max_review_body_bytes", 60000)
    marker_reserve = len(("\n\n<!-- pr-review-harness:effect-" + "0" * 64 + " -->").encode("utf-8"))
    if (
        isinstance(max_body, bool)
        or not isinstance(max_body, int)
        or max_body < 1
        or not isinstance(body, str)
        or len(body.encode("utf-8")) + marker_reserve > min(max_body, 60000)
    ):
        raise PublicationRejected("review body is invalid or exceeds its bound")
    return {
        "effect_type": "PULL_REQUEST_REVIEW",
        "repository": repository,
        "pull_request_number": number,
        "head_sha": head,
        "disposition": source_disposition,
        "review_event": review_event,
        "result_hash": result["result_hash"],
        "review_body_hash": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "idempotency_key": effect_idempotency_key(result, rendered_review=body),
        "merge": False,
        "review_payload": {
            "commit_id": head,
            "event": review_event,
            "body": body,
        },
    }


def _stateless_effect_key(slot, result_hash: str, review_body_hash: str, disposition: str) -> str:
    identity = {
        "slot_key": slot.key,
        "result_hash": result_hash,
        "review_body_hash": review_body_hash,
        "disposition": disposition,
    }
    return "effect-" + _canonical_hash(identity)


def _expected_review_state(review_event: str):
    from .publication_receipts import ReviewState

    return {
        "APPROVE": ReviewState.APPROVED,
        "REQUEST_CHANGES": ReviewState.CHANGES_REQUESTED,
        "COMMENT": ReviewState.COMMENTED,
    }[review_event]


def _marked_review_payload(payload: dict, effect_key: str) -> dict:
    """Append exactly one stable marker to the canonical body for POST."""
    body = payload.get("body")
    if not isinstance(body, str) or "<!-- pr-review-harness:" in body:
        raise PublicationRejected("canonical review body contains a reserved marker")
    return {**payload, "body": f"{body}\n\n<!-- pr-review-harness:{effect_key} -->"}


def publish_review_stateless(
    result: dict,
    config: dict,
    effect_policy: str,
    *,
    admission_provider,
    history_reader,
    receipt_writer,
    fresh_head,
    submit_review,
    limits=None,
    rendered_review: str | None = None,
) -> dict:
    """Publish once using verified Actions identity and GitHub-backed receipts.

    There is intentionally no boolean authorization parameter, local claim or
    release callback, or transport retry. The admission provider must bind the
    exact result and publisher run to trusted GitHub API evidence. A successful
    pre-POST artifact acknowledgement is required before the sole POST call.
    """
    from .publication_receipts import (
        AttemptReceipt,
        EffectSlot,
        HistoryScan,
        HistoryStatus,
        PublicationAdmission,
        ReceiptContractError,
        ReceiptPersistence,
        ReceiptPersistenceStatus,
        ReviewObservation,
        ScanLimits,
    )

    bounds = limits if limits is not None else ScanLimits()
    if not isinstance(bounds, ScanLimits):
        return {"status": "REJECTED", "reason": "publication_limits_invalid"}
    if effect_policy != "PUBLISH_REVIEW":
        return {"status": "REJECTED", "reason": "effect_policy_denied"}
    if not isinstance(config, dict) or config.get("schema_version") != "1.0":
        return {"status": "REJECTED", "reason": "publisher_config_invalid"}
    if config.get("enabled") is not True:
        return {"status": "REJECTED", "reason": "publication_disabled"}
    if not all(
        callable(value)
        for value in (
            getattr(admission_provider, "admit", None),
            getattr(history_reader, "scan", None),
            getattr(receipt_writer, "persist", None),
            fresh_head,
            submit_review,
        )
    ):
        return {"status": "REJECTED", "reason": "publisher_capability_unavailable"}
    deadline_at = time.monotonic() + bounds.deadline_seconds

    def remaining_bounds():
        remaining = deadline_at - time.monotonic()
        if remaining <= 0:
            return None
        return ScanLimits(
            max_runs=bounds.max_runs,
            max_pages=bounds.max_pages,
            max_reviews=bounds.max_reviews,
            deadline_seconds=min(bounds.deadline_seconds, remaining),
        )

    try:
        request = preview_publication(result, config, rendered_review)
        allowed_profiles = config.get("allowed_profile_versions")
        allowed_actors = config.get("allowed_actors")
        if not isinstance(allowed_profiles, list) or result["project_profile_version"] not in allowed_profiles:
            raise PublicationRejected("review profile is outside publisher authorization scope")
        if not isinstance(allowed_actors, list):
            raise PublicationRejected("publisher actor policy is invalid")
        stage_bounds = remaining_bounds()
        if stage_bounds is None:
            return {"status": "UNKNOWN", "reason": "publication_deadline_exhausted"}
        admission = admission_provider.admit(result, config, stage_bounds)
        if not isinstance(admission, PublicationAdmission):
            raise ReceiptContractError("admission capability is invalid")
        if admission.actor_login not in allowed_actors:
            raise PublicationRejected("publisher actor is outside authorization scope")
        expected_slot = EffectSlot(
            admission.slot.repository_id,
            request["repository"],
            request["pull_request_number"],
            request["head_sha"],
        )
        if (
            admission.slot != expected_slot
            or admission.base_sha != result.get("base_sha")
            or admission.result_hash != request["result_hash"]
            or admission.review_body_hash != request["review_body_hash"]
            or admission.disposition != request["disposition"]
            or admission.review_event != request["review_event"]
            or admission.policy_hash != _canonical_hash(config)
            or admission.effect_key
            != _stateless_effect_key(
                expected_slot, request["result_hash"], request["review_body_hash"], request["disposition"]
            )
        ):
            raise PublicationRejected("verified publication context does not match the review")
        request["idempotency_key"] = admission.effect_key
    except (PublicationRejected, ReceiptContractError, KeyError, TypeError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, PublicationRejected) else "publication_admission_invalid"
        return {"status": "REJECTED", "reason": reason, "request": locals().get("request")}
    except Exception:
        return {"status": "UNKNOWN", "reason": "publication_admission_unavailable", "request": locals().get("request")}

    def read_history():
        stage_bounds = remaining_bounds()
        if stage_bounds is None:
            return None, "publication_deadline_exhausted"
        try:
            scan = history_reader.scan(admission.slot, stage_bounds)
        except Exception:
            return None, "publication_history_unavailable"
        if not isinstance(scan, HistoryScan):
            return None, "publication_history_contract_invalid"
        if scan.status is not HistoryStatus.COMPLETE:
            return None, scan.reason_code or "publication_history_incomplete"
        if scan.scanned_runs > stage_bounds.max_runs or scan.scanned_pages > stage_bounds.max_pages:
            return None, "publication_history_limit_exceeded"
        if len(scan.receipts) > stage_bounds.max_runs:
            return None, "publication_receipt_limit_exceeded"
        if len(scan.reviews) > stage_bounds.max_reviews:
            return None, "publication_review_limit_exceeded"
        return scan, None

    def effect_state(scan):
        prior_reviews = [entry for entry in scan.reviews if entry.slot.key == admission.slot.key]
        if prior_reviews:
            if len(prior_reviews) != 1:
                return "CONFLICT", "multiple_reviews_for_slot"
            review = prior_reviews[0]
            if (
                review.effect_key == admission.effect_key
                and review.review_body_hash == admission.review_body_hash
                and review.actor_login == admission.actor_login
                and review.state is _expected_review_state(admission.review_event)
            ):
                return "CONFIRMED", None
            return "CONFLICT", "existing_review_conflicts_with_slot"
        prior_receipts = [entry for entry in scan.receipts if entry.slot.key == admission.slot.key]
        if prior_receipts:
            if len(prior_receipts) != 1:
                return "UNKNOWN", "multiple_attempt_receipts_for_slot"
            receipt = prior_receipts[0]
            if receipt.effect_key != admission.effect_key:
                return "CONFLICT", "different_result_already_claimed_slot"
            return "UNKNOWN", "prior_attempt_has_no_confirmed_review"
        return "READY", None

    scan, reason = read_history()
    if scan is None:
        return {"status": "UNKNOWN", "reason": reason, "request": request}
    state, reason = effect_state(scan)
    if state != "READY":
        return {"status": state, "reason": reason, "request": request}
    try:
        stage_bounds = remaining_bounds()
        if stage_bounds is None:
            return {"status": "UNKNOWN", "reason": "publication_deadline_exhausted", "request": request}
        observed = fresh_head(stage_bounds.deadline_seconds)
    except Exception:
        return {"status": "UNKNOWN", "reason": "pre_receipt_head_unavailable", "request": request}
    if observed != admission.slot.head_sha:
        return {"status": "STALE", "reason": "head_sha_changed_before_receipt", "request": request}

    receipt = AttemptReceipt(
        slot=admission.slot,
        effect_key=admission.effect_key,
        result_hash=admission.result_hash,
        review_body_hash=admission.review_body_hash,
        disposition=admission.disposition,
        review_event=admission.review_event,
        actor_login=admission.actor_login,
        profile_hash=admission.profile_hash,
        upstream_run=admission.upstream_run,
        publisher_run=admission.publisher_run,
    )
    try:
        stage_bounds = remaining_bounds()
        if stage_bounds is None:
            return {"status": "UNKNOWN", "reason": "publication_deadline_exhausted", "request": request}
        persistence = receipt_writer.persist(receipt, stage_bounds)
    except Exception:
        return {"status": "UNKNOWN", "reason": "receipt_persistence_unknown", "request": request}
    if not isinstance(persistence, ReceiptPersistence):
        return {"status": "UNKNOWN", "reason": "receipt_persistence_contract_invalid", "request": request}
    if persistence.status is not ReceiptPersistenceStatus.ACKNOWLEDGED:
        status = "REJECTED" if persistence.status is ReceiptPersistenceStatus.REJECTED else "UNKNOWN"
        return {"status": status, "reason": persistence.reason_code or "receipt_not_acknowledged", "request": request}
    if not persistence.acknowledges(receipt):
        return {"status": "UNKNOWN", "reason": "receipt_acknowledgement_mismatch", "request": request}

    try:
        stage_bounds = remaining_bounds()
        if stage_bounds is None:
            return {"status": "UNKNOWN", "reason": "publication_deadline_exhausted", "request": request}
        observed = fresh_head(stage_bounds.deadline_seconds)
    except Exception:
        return {"status": "UNKNOWN", "reason": "post_receipt_head_unavailable", "request": request}
    if observed != admission.slot.head_sha:
        return {"status": "STALE", "reason": "head_sha_changed_after_receipt", "request": request}

    try:
        wire_payload = _marked_review_payload(request["review_payload"], admission.effect_key)
        stage_bounds = remaining_bounds()
        if stage_bounds is None:
            return {"status": "UNKNOWN", "reason": "publication_deadline_exhausted", "request": request}
        submitted = submit_review(wire_payload, admission.effect_key, stage_bounds.deadline_seconds)
    except Exception:
        scan, reason = read_history()
        if scan is not None:
            state, state_reason = effect_state(scan)
            if state == "CONFIRMED":
                return {"status": "CONFIRMED", "reason": "confirmed_after_ambiguous_response", "request": request}
            if state == "CONFLICT":
                return {"status": "CONFLICT", "reason": state_reason, "request": request}
        return {"status": "UNKNOWN", "reason": "submit_response_ambiguous", "request": request}

    if not isinstance(submitted, ReviewObservation):
        scan, reason = read_history()
        if scan is not None:
            state, state_reason = effect_state(scan)
            if state == "CONFIRMED":
                return {"status": "CONFIRMED", "reason": "confirmed_after_response_validation", "request": request}
            if state == "CONFLICT":
                return {"status": "CONFLICT", "reason": state_reason, "request": request}
        return {"status": "UNKNOWN", "reason": "submit_response_invalid", "request": request}
    if (
        submitted.slot.key != admission.slot.key
        or submitted.effect_key != admission.effect_key
        or submitted.review_body_hash != admission.review_body_hash
        or submitted.actor_login != admission.actor_login
        or submitted.state is not _expected_review_state(admission.review_event)
    ):
        return {"status": "UNKNOWN", "reason": "submit_response_binding_invalid", "request": request}
    return {"status": "CONFIRMED", "reason": None, "request": request}


def publish_review(
    result: dict,
    config: dict,
    effect_policy: str,
    authorized: bool,
    *,
    fresh_head: Callable[[], str] | None = None,
    lookup_effect: Callable[[str], str] | None = None,
    claim_effect: Callable[[str], str] | None = None,
    submit_review: Callable[[dict, str], object] | None = None,
    confirm_effect: Callable[[str, str], object] | None = None,
    release_effect: Callable[[str], object] | None = None,
    rendered_review: str | None = None,
) -> dict:
    """Attempt one explicitly enabled review effect through injected capabilities.

    This legacy single-host API uses an explicit authorization flag and local
    effect-store callbacks. Stateless Actions publication is implemented by
    :func:`publish_review_stateless`; callers of either API must provide a
    fresh-head reader and a narrowly scoped review submitter. Ambiguous
    submissions are reconciled once and are never blindly retried. This module
    has no merge or source-edit operation.
    """
    request = prepare_publication(result, config, effect_policy, authorized, rendered_review)
    if not all(callable(value) for value in (fresh_head, lookup_effect, claim_effect, submit_review, confirm_effect)):
        return {"status": "REJECTED", "reason": "publisher_capability_unavailable", "request": request}
    try:
        observed = fresh_head()
    except Exception:
        return {"status": "UNKNOWN", "reason": "fresh_head_unavailable", "request": request}
    if observed != request["head_sha"]:
        return {"status": "REJECTED", "reason": "head_sha_changed", "request": request, "observed_head_sha": observed}
    try:
        prior = lookup_effect(request["idempotency_key"])
    except Exception:
        return {"status": "UNKNOWN", "reason": "existing_effect_state_unavailable", "request": request}
    if prior == "confirmed":
        return {"status": "CONFIRMED", "reason": "idempotent_effect_already_exists", "request": request}
    if prior == "unknown":
        return {"status": "UNKNOWN", "reason": "existing_effect_state_ambiguous", "request": request}
    if prior != "not_found":
        return {"status": "REJECTED", "reason": "existing_effect_state_invalid", "request": request}
    try:
        observed = fresh_head()
    except Exception:
        return {"status": "UNKNOWN", "reason": "final_fresh_head_unavailable", "request": request}
    if observed != request["head_sha"]:
        return {
            "status": "REJECTED",
            "reason": "head_sha_changed_before_submit",
            "request": request,
            "observed_head_sha": observed,
        }
    try:
        claim = claim_effect(request["idempotency_key"])
    except Exception:
        return {"status": "UNKNOWN", "reason": "effect_claim_unavailable", "request": request}
    if claim == "confirmed":
        return {"status": "CONFIRMED", "reason": "idempotent_effect_already_exists", "request": request}
    if claim != "acquired":
        return {"status": "UNKNOWN", "reason": "effect_claim_not_acquired", "request": request}
    try:
        observed = fresh_head()
    except Exception:
        if callable(release_effect):
            release_effect(request["idempotency_key"])
        return {"status": "UNKNOWN", "reason": "final_fresh_head_unavailable", "request": request}
    if observed != request["head_sha"]:
        if callable(release_effect):
            release_effect(request["idempotency_key"])
        return {
            "status": "REJECTED",
            "reason": "head_sha_changed_before_submit",
            "request": request,
            "observed_head_sha": observed,
        }
    try:
        submitted = submit_review(request["review_payload"], request["idempotency_key"])
    except Exception:
        # A failed response may follow a successful remote write. Confirm by
        # querying effect state before reporting or permitting any new attempt.
        try:
            after = lookup_effect(request["idempotency_key"])
        except Exception:
            after = "unknown"
        if after == "confirmed":
            try:
                confirm_effect(request["idempotency_key"], "confirmed_after_ambiguous_response")
            except Exception:
                pass
            return {"status": "CONFIRMED", "reason": "confirmed_after_ambiguous_response", "request": request}
        return {"status": "UNKNOWN", "reason": "submit_response_ambiguous", "request": request}
    try:
        confirm_effect(request["idempotency_key"], str(submitted)[:500])
    except Exception:
        try:
            after = lookup_effect(request["idempotency_key"])
        except Exception:
            after = "unknown"
        if after != "confirmed":
            return {"status": "UNKNOWN", "reason": "effect_recording_failed", "request": request}
    return {"status": "CONFIRMED", "reason": None, "request": request}
