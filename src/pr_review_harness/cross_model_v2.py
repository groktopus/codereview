"""Byte-bound advisory relation assertions for cross-model review evidence.

This contract verifies that a named reporter response contains a structured
relation at a declared JSON Pointer. It does not judge whether that relation
is semantically true or whether any model is accurate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from pathlib import Path
from typing import Any

from .evaluation import MAX_INPUT_BYTES, EvaluationError, parse_bounded_json, validate_corpus

CONTRACT_VERSION = "review-cross-model-comparison.v2"
ROLES = ("writer", "jev", "source_auditor", "claim_auditor")
PAIRS = {
    "writer_jev": ("writer", "jev"),
    "jev_claim_auditor": ("jev", "claim_auditor"),
}
RELATIONS = ("MATCH", "DISAGREEMENT", "NO_COUNTERPART", "ABSTAINED", "INCOMPLETE", "NOT_RUN", "UNKNOWN")
RUN_STATUSES = ("completed", "incomplete", "failed", "unavailable", "abstained", "not_run")
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_COUNT = 256
MAX_CALLS_PER_RUN = 10_000
MAX_TOTAL_CALLS = 50_000
MAX_ASSERTIONS_PER_CASE = 20_000
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
HASH = re.compile(r"^[0-9a-f]{64}$")


def _fail(code: str) -> None:
    raise EvaluationError(code)


def _exact(obj: Any, fields: set[str], code: str) -> dict[str, Any]:
    if not isinstance(obj, dict) or set(obj) != fields:
        _fail(code)
    return obj


def _id(value: Any, code: str) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        _fail(code)
    return value


def _hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or not HASH.fullmatch(value):
        _fail(code)
    return value


def _text(value: Any, code: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > limit:
        _fail(code)
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def calls_manifest_sha256(calls: list[dict[str, Any]]) -> str:
    """Return the canonical manifest digest used to bind each provider call."""
    return hashlib.sha256(_canonical(calls)).hexdigest()


def _validate_call(call: Any) -> dict[str, Any]:
    item = _exact(
        call,
        {"call_id", "request_sha256", "request_artifact_id", "response_sha256", "response_artifact_id"},
        "invalid_provider_call",
    )
    _id(item["call_id"], "invalid_call_id")
    _hash(item["request_sha256"], "invalid_request_sha256")
    _id(item["request_artifact_id"], "invalid_request_artifact_id")
    if item["response_sha256"] is None and item["response_artifact_id"] is None:
        return item
    if item["response_sha256"] is None or item["response_artifact_id"] is None:
        _fail("incomplete_call_response_binding")
    _hash(item["response_sha256"], "invalid_response_sha256")
    _id(item["response_artifact_id"], "invalid_response_artifact_id")
    return item


def validate_cross_model_comparison_v2(value: Any, corpus_value: Any) -> dict[str, Any]:
    """Validate role/run/call provenance and relation reference structure."""
    corpus = validate_corpus(corpus_value)
    comparison = _exact(value, {"contract_version", "comparison_id", "corpus_id", "dataset_version", "procedure", "cases"}, "invalid_cross_model_v2_contract")
    if comparison["contract_version"] != CONTRACT_VERSION:
        _fail("unsupported_cross_model_v2_contract")
    if comparison["corpus_id"] != corpus["corpus_id"] or comparison["dataset_version"] != corpus["dataset_version"]:
        _fail("cross_model_corpus_mismatch")
    _id(comparison["comparison_id"], "invalid_comparison_id")
    procedure = _exact(comparison["procedure"], {"revision", "frozen_sha256"}, "invalid_procedure")
    _id(procedure["revision"], "invalid_procedure_revision")
    _hash(procedure["frozen_sha256"], "invalid_procedure_hash")
    expected_cases = {item["identity"]["case_id"]: item["identity"] for item in corpus["cases"]}
    cases = comparison["cases"]
    if not isinstance(cases, list) or len(cases) > 10_000:
        _fail("invalid_cross_model_cases")
    seen_cases: set[str] = set()
    seen_run_ids: set[str] = set()
    seen_artifact_ids: set[str] = set()
    total_calls = 0
    for case in cases:
        item = _exact(case, {"case_id", "identity", "runs", "records", "assertions"}, "invalid_cross_model_case")
        case_id = _id(item["case_id"], "invalid_case_id")
        if case_id in seen_cases:
            _fail("duplicate_case_id")
        seen_cases.add(case_id)
        if expected_cases.get(case_id) != item["identity"]:
            _fail("cross_model_snapshot_mismatch")
        runs = item["runs"]
        if not isinstance(runs, list) or len(runs) != len(ROLES):
            _fail("missing_or_duplicate_role_run")
        by_role: dict[str, dict[str, Any]] = {}
        all_calls: dict[tuple[str, str], dict[str, Any]] = {}
        for run in runs:
            run = _exact(run, {"role", "status", "run_id", "provider_id", "model_id", "runtime_id", "prompt_revision", "rubric_revision", "calls", "calls_manifest_sha256"}, "invalid_role_run")
            role = run["role"]
            status = run["status"]
            if role not in ROLES or role in by_role or status not in RUN_STATUSES:
                _fail("missing_or_duplicate_role_run")
            by_role[role] = run
            if status == "not_run":
                if run["run_id"] is not None or run["calls"] != [] or run["calls_manifest_sha256"] is not None:
                    _fail("not_run_has_execution_provenance")
                for field in ("provider_id", "model_id", "runtime_id", "prompt_revision", "rubric_revision"):
                    if run[field] is not None:
                        _id(run[field], f"invalid_{field}")
            else:
                run_id = _id(run["run_id"], "invalid_run_id")
                if run_id in seen_run_ids:
                    _fail("duplicate_run_id")
                seen_run_ids.add(run_id)
                for field in ("provider_id", "model_id", "runtime_id", "prompt_revision", "rubric_revision"):
                    _text(run[field], f"invalid_{field}")
                calls = run["calls"]
                if not isinstance(calls, list) or len(calls) > MAX_CALLS_PER_RUN:
                    _fail("invalid_provider_calls")
                total_calls += len(calls)
                if total_calls > MAX_TOTAL_CALLS:
                    _fail("too_many_provider_calls")
                if calls_manifest_sha256(calls) != _hash(run["calls_manifest_sha256"], "invalid_calls_manifest_sha256"):
                    _fail("calls_manifest_mismatch")
                local_ids: set[str] = set()
                for raw_call in calls:
                    call = _validate_call(raw_call)
                    if call["call_id"] in local_ids:
                        _fail("duplicate_call_id")
                    local_ids.add(call["call_id"])
                    artifact_ids = [call["request_artifact_id"]]
                    if call["response_artifact_id"] is not None:
                        artifact_ids.append(call["response_artifact_id"])
                    for aid in artifact_ids:
                        if aid in seen_artifact_ids:
                            _fail("duplicate_artifact_id")
                        seen_artifact_ids.add(aid)
                    all_calls[(role, call["call_id"])] = call
        if set(by_role) != set(ROLES):
            _fail("missing_or_duplicate_role_run")
        records = item["records"]
        if not isinstance(records, list) or len(records) > 60_000:
            _fail("invalid_records")
        record_ids: set[tuple[str, str]] = set()
        for record in records:
            record = _exact(record, {"role", "record_id"}, "invalid_record")
            if record["role"] not in ROLES:
                _fail("invalid_record_role")
            key = (record["role"], _id(record["record_id"], "invalid_record_id"))
            if key in record_ids:
                _fail("duplicate_record_id")
            record_ids.add(key)
            if by_role[record["role"]]["status"] in {"not_run", "unavailable"}:
                _fail("record_without_role_output")
        assertions = item["assertions"]
        if not isinstance(assertions, list) or len(assertions) > MAX_ASSERTIONS_PER_CASE:
            _fail("invalid_assertions")
        assertion_ids: set[str] = set()
        for assertion in assertions:
            assertion = _exact(assertion, {"assertion_id", "pair", "relation", "reporter_role", "reporter_run_id", "reporter_call_id", "response_artifact_id", "json_pointer", "left_record_id", "right_record_id"}, "invalid_relation_assertion")
            aid = _id(assertion["assertion_id"], "invalid_assertion_id")
            if aid in assertion_ids:
                _fail("duplicate_assertion_id")
            assertion_ids.add(aid)
            pair = assertion["pair"]
            relation = assertion["relation"]
            if pair not in PAIRS or relation not in RELATIONS:
                _fail("invalid_pair_or_relation")
            left_role, right_role = PAIRS[pair]
            reporter_role = assertion["reporter_role"]
            if reporter_role != right_role:
                _fail("relation_reporter_mismatch")
            run = by_role[reporter_role]
            run_id = _id(assertion["reporter_run_id"], "invalid_reporter_run_id")
            if run.get("run_id") != run_id:
                _fail("reporter_run_mismatch")
            call_id = _id(assertion["reporter_call_id"], "invalid_reporter_call_id")
            call = all_calls.get((reporter_role, call_id))
            if call is None or call["response_artifact_id"] != assertion["response_artifact_id"]:
                _fail("reporter_call_mismatch")
            pointer = assertion["json_pointer"]
            if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")) or len(pointer.encode("utf-8")) > 2048:
                _fail("invalid_json_pointer")
            for field, role in (("left_record_id", left_role), ("right_record_id", right_role)):
                value = assertion[field]
                if value is not None:
                    _id(value, f"invalid_{field}")
                    if (role, value) not in record_ids:
                        _fail("unresolved_relation_record")
            if relation in {"MATCH", "DISAGREEMENT"} and (assertion["left_record_id"] is None or assertion["right_record_id"] is None):
                _fail("relation_record_required")
            if relation == "NO_COUNTERPART" and (assertion["left_record_id"] is None) == (assertion["right_record_id"] is None):
                _fail("no_counterpart_shape_invalid")
            counterpart_statuses = (by_role[left_role]["status"], by_role[right_role]["status"])
            if relation in {"MATCH", "DISAGREEMENT", "NO_COUNTERPART"} and counterpart_statuses != ("completed", "completed"):
                _fail("relation_conflicts_with_run_status")
            if relation == "ABSTAINED" and "abstained" not in counterpart_statuses:
                _fail("relation_conflicts_with_run_status")
            if relation == "INCOMPLETE" and not set(counterpart_statuses) & {"incomplete", "failed", "unavailable"}:
                _fail("relation_conflicts_with_run_status")
            if relation == "NOT_RUN" and "not_run" not in counterpart_statuses:
                _fail("relation_conflicts_with_run_status")
    if seen_cases != set(expected_cases):
        _fail("cross_model_case_coverage_mismatch")
    return comparison


def _read_artifact(path: Path, expected_hash: str, byte_budget: int, per_file_limit: int) -> tuple[str, str | None, bytes, int]:
    """Read one local regular file without following symlinks or blocking on FIFOs."""
    try:
        if ".." in path.parts:
            return "PATH_TRAVERSAL", None, b"", 0
        absolute = path.absolute()
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current = current / part
            if current.is_symlink():
                return "SYMLINK", None, b"", 0
        info = absolute.lstat()
        if not stat.S_ISREG(info.st_mode):
            return "NOT_REGULAR", None, b"", 0
        if info.st_size > per_file_limit:
            return "TOO_LARGE", None, b"", 0
        if info.st_size > byte_budget:
            return "CHECK_LIMIT", None, b"", 0
        fd = os.open(absolute, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                return "NOT_REGULAR", None, b"", 0
            if opened.st_size > per_file_limit:
                return "TOO_LARGE", None, b"", 0
            if opened.st_size > byte_budget:
                return "CHECK_LIMIT", None, b"", 0
            chunks = bytearray()
            read_limit = min(per_file_limit, byte_budget)
            while len(chunks) <= read_limit:
                block = os.read(fd, min(64 * 1024, read_limit + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
            if len(chunks) > per_file_limit:
                return "TOO_LARGE", None, b"", len(chunks)
            if len(chunks) > byte_budget:
                return "CHECK_LIMIT", None, b"", len(chunks)
        finally:
            os.close(fd)
    except OSError:
        return "UNREADABLE", None, b"", 0
    raw = bytes(chunks)
    digest = hashlib.sha256(raw).hexdigest()
    return ("VERIFIED" if digest == expected_hash else "HASH_MISMATCH"), digest, raw, len(raw)


def _pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    current = value
    for raw in pointer[1:].split("/"):
        if re.search(r"~(?![01])", raw):
            raise KeyError("bad_escape")
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and re.fullmatch(r"0|[1-9][0-9]*", part) and int(part) < len(current):
            current = current[int(part)]
        else:
            raise KeyError("missing")
    return current


def compare_cross_model_v2(value: Any, corpus_value: Any, *, artifacts: dict[str, Path] | None = None) -> dict[str, Any]:
    """Verify response-byte relation references and report advisory denominators."""
    comparison = validate_cross_model_comparison_v2(value, corpus_value)
    artifacts = artifacts or {}
    expected: dict[str, tuple[str, str, str]] = {}
    for case in comparison["cases"]:
        for run in case["runs"]:
            for call in run["calls"]:
                expected[call["request_artifact_id"]] = (call["request_sha256"], run["role"], "request")
                if call["response_artifact_id"] is not None:
                    expected[call["response_artifact_id"]] = (call["response_sha256"], run["role"], "response")
    if set(artifacts) - set(expected):
        _fail("artifact_for_unknown_id")
    verification: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    for index, (artifact_id, (digest, role, kind)) in enumerate(expected.items()):
        if index >= MAX_ARTIFACT_COUNT or total_bytes >= MAX_TOTAL_BYTES:
            status, observed, raw, size = "CHECK_LIMIT", None, b"", 0
        elif artifact_id not in artifacts:
            status, observed, raw, size = "NOT_PROVIDED", None, b"", 0
        else:
            per_file_limit = MAX_RESPONSE_BYTES if kind == "response" else MAX_REQUEST_BYTES
            status, observed, raw, size = _read_artifact(artifacts[artifact_id], digest, MAX_TOTAL_BYTES - total_bytes, per_file_limit)
        total_bytes += size
        parsed = None
        if kind == "response" and status == "VERIFIED":
            try:
                parsed = parse_bounded_json(raw, "response")
            except EvaluationError:
                status = "MALFORMED_JSON"
        verification[artifact_id] = {"artifact_id": artifact_id, "role": role, "kind": kind, "status": status, "declared_sha256": digest, "observed_sha256": observed, "parsed": parsed}
    relation_counts: dict[str, Counter[str]] = {pair: Counter({r: 0 for r in RELATIONS}) for pair in PAIRS}
    assertion_status_counts: Counter[str] = Counter()
    verified_assertion_count = 0
    case_rows = []
    for case in comparison["cases"]:
        rows = []
        for assertion in case["assertions"]:
            relation_counts[assertion["pair"]][assertion["relation"]] += 1
            evidence = verification.get(assertion["response_artifact_id"])
            result = "NOT_PROVIDED"
            if evidence is not None:
                result = evidence["status"]
                if result == "VERIFIED":
                    try:
                        target = _pointer(evidence["parsed"], assertion["json_pointer"])
                    except (KeyError, TypeError, IndexError, ValueError):
                        result = "POINTER_MISSING"
                    else:
                        expected_relation = {
                            "relation": assertion["relation"],
                            "left_record_id": assertion["left_record_id"],
                            "right_record_id": assertion["right_record_id"],
                        }
                        if not isinstance(target, dict):
                            result = "TARGET_NOT_OBJECT"
                        elif any(key not in target or target[key] != expected_relation[key] for key in expected_relation):
                            result = "RESPONSE_MISMATCH"
                        else:
                            result = "VERIFIED_STRUCTURED_RELATION"
                            verified_assertion_count += 1
                assertion_status_counts[result] += 1
                rows.append({"assertion_id": assertion["assertion_id"], "pair": assertion["pair"], "relation": assertion["relation"], "reporter_role": assertion["reporter_role"], "reporter_run_id": assertion["reporter_run_id"], "reporter_call_id": assertion["reporter_call_id"], "response_artifact_id": assertion["response_artifact_id"], "status": result, "relation_emitted": result == "VERIFIED_STRUCTURED_RELATION"})
        case_rows.append({"case_id": case["case_id"], "assertions": rows, "assertion_denominator": len(rows), "zero_assertions": len(rows) == 0})
    role_counts = {}
    for role in ROLES:
        statuses = Counter(run["status"] for case in comparison["cases"] for run in case["runs"] if run["role"] == role)
        role_runs = [run for case in comparison["cases"] for run in case["runs"] if run["role"] == role]
        role_counts[role] = {"denominator": len(comparison["cases"]), "status_counts": {status: statuses[status] for status in RUN_STATUSES}, "zero_call_runs": sum(not run["calls"] for run in role_runs), "call_denominator": sum(len(run["calls"]) for run in role_runs), "calls_without_response": sum(call["response_artifact_id"] is None for run in role_runs for call in run["calls"])}
    report = {
        "contract_version": CONTRACT_VERSION,
        "comparison_id": comparison["comparison_id"],
        "evidence_kind": "advisory_model_only_structured_relation_presence",
        "hashes_are_authentication": False,
        "remote_delivery_proven": False,
        "relation_semantics": "verified response bytes contain the declared typed relation and IDs at the declared JSON Pointer; semantic truth and accuracy are not evaluated",
        "claims": {"accuracy": None, "ground_truth": None, "calibration": None, "correctness": None},
        "roles": list(ROLES),
        "role_run_counts": role_counts,
        "role_record_counts": {
            role: {
                "case_denominator": len(comparison["cases"]),
                "cases_with_records": sum(any(record["role"] == role for record in case["records"]) for case in comparison["cases"]),
                "cases_with_zero_records": sum(not any(record["role"] == role for record in case["records"]) for case in comparison["cases"]),
                "record_denominator": sum(record["role"] == role for case in comparison["cases"] for record in case["records"]),
            }
            for role in ROLES
        },
        "relation_counts": {pair: {"denominator": sum(counts.values()), "status_counts": dict(counts)} for pair, counts in relation_counts.items()},
        "assertion_verification": {"denominator": sum(assertion_status_counts.values()), "status_counts": {key: assertion_status_counts[key] for key in ("VERIFIED_STRUCTURED_RELATION", "NOT_PROVIDED", "UNREADABLE", "SYMLINK", "NOT_REGULAR", "TOO_LARGE", "CHECK_LIMIT", "PATH_TRAVERSAL", "HASH_MISMATCH", "MALFORMED_JSON", "POINTER_MISSING", "TARGET_NOT_OBJECT", "RESPONSE_MISMATCH")}, "verified_structured_relation_count": verified_assertion_count},
        "artifact_verification": {"scope": "bounded supplied local bytes", "denominator": len(verification), "status_counts": {status: sum(row["status"] == status for row in verification.values()) for status in ("VERIFIED", "HASH_MISMATCH", "NOT_PROVIDED", "UNREADABLE", "SYMLINK", "NOT_REGULAR", "TOO_LARGE", "CHECK_LIMIT", "MALFORMED_JSON", "PATH_TRAVERSAL")}, "artifacts": [{key: row[key] for key in ("artifact_id", "role", "kind", "status", "declared_sha256", "observed_sha256")} for row in verification.values()]},
        "cases": case_rows,
    }
    encoded = _canonical(report)
    if len(encoded) > MAX_INPUT_BYTES:
        _fail("cross_model_v2_report_too_large")
    report["report_sha256"] = hashlib.sha256(encoded).hexdigest()
    return report
