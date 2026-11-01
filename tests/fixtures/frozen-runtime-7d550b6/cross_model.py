"""Bounded, source-bound cross-model comparison records.

This companion contract preserves advisory model outputs and deterministic
anchor checks. It deliberately does not infer semantic relations from text or
compute accuracy, correctness, calibration, precision, or recall.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import signal
import stat
import subprocess
import threading
import time
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

from .evaluation import (
    MAX_INPUT_BYTES,
    EvaluationError,
    parse_bounded_json,
    validate_corpus,
)

CROSS_MODEL_VERSION = "review-cross-model-comparison.v1"
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_ARTIFACTS_CHECKED = 256
MAX_TOTAL_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_ANCHOR_SOURCE_BYTES = 16 * 1024 * 1024
MAX_DIFF_BYTES = 4 * 1024 * 1024
MAX_ANCHOR_PATHS = 256
MAX_ANCHOR_CHECK_SECONDS = 60.0
MAX_GIT_CALL_SECONDS = 2.0
MAX_CASES = 10_000
MAX_RUNS = 100_000
MAX_RECORDS_PER_CASE = 6_000
MAX_ANCHORS_PER_CASE = 10_000
MAX_UNITS_PER_CASE = 20_000

ROLES = ("writer", "jev", "auditor")
ROLE_RECORD_KINDS = {"writer": "finding", "jev": "classification", "auditor": "audit"}
RECORD_KINDS = {"finding", "classification", "audit", "no_counterpart", "abstention", "failure"}
PAIR_ROLES = {"writer_jev": ("writer", "jev"), "jev_auditor": ("jev", "auditor")}
RUN_STATUSES = {"completed", "incomplete", "failed", "unavailable", "abstained", "not_run"}
SLOT_STATES = {"record", "no_counterpart", "abstained", "incomplete", "not_run"}
RELATIONS = {"MATCH", "DISAGREEMENT", "NO_COUNTERPART", "ABSTAINED", "INCOMPLETE", "NOT_RUN"}
ANCHOR_STATUSES = {
    "CHANGED_RANGE",
    "EXISTING_HEAD_RANGE",
    "PATH_MISSING",
    "LINE_OUT_OF_RANGE",
    "SNAPSHOT_MISMATCH",
    "CHECK_FAILED",
    "CHECK_LIMIT",
    "NOT_RUN",
}

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_BAD_RUNS = {"incomplete", "failed", "unavailable"}


def _fail(code: str) -> None:
    raise EvaluationError(code)


def _exact(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(code)
    return value


def _identifier(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        _fail(code)
    return value


def _hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        _fail(code)
    return value


def _text(value: Any, code: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(code)
    try:
        if len(value.encode("utf-8")) > limit:
            _fail(code)
    except UnicodeError:
        _fail(code)
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _identity_digest(identity: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(identity)).hexdigest()


def _validate_run(run: Any, expected_role: str, seen_run_ids: set[str]) -> dict[str, Any]:
    fields = {
        "role", "status", "run_id", "provider_id", "model_id", "runtime_id",
        "prompt_revision", "rubric_revision", "input_sha256", "input_artifact_id", "output_sha256", "artifact_id",
    }
    item = _exact(run, fields, "invalid_role_run")
    if item["role"] != expected_role or not isinstance(item["status"], str) or item["status"] not in RUN_STATUSES:
        _fail("invalid_role_or_run_status")
    if item["status"] == "not_run":
        if any(item[key] is not None for key in ("run_id", "provider_id", "model_id", "runtime_id", "input_sha256", "input_artifact_id", "output_sha256", "artifact_id")):
            _fail("not_run_has_execution_provenance")
        for key in ("prompt_revision", "rubric_revision"):
            if item[key] is not None:
                _identifier(item[key], f"invalid_{key}")
        return item

    _identifier(item["run_id"], "invalid_run_id")
    _hash(item["input_sha256"], "invalid_role_input_sha256")
    _identifier(item["input_artifact_id"], "invalid_input_artifact_id")
    if item["run_id"] in seen_run_ids:
        _fail("duplicate_run_id")
    seen_run_ids.add(item["run_id"])
    for key in ("provider_id", "model_id", "runtime_id", "prompt_revision", "rubric_revision"):
        _text(item[key], f"invalid_{key}")
    if item["status"] in {"completed", "incomplete", "failed", "abstained"}:
        _hash(item["output_sha256"], "invalid_output_sha256")
        _identifier(item["artifact_id"], "invalid_artifact_id")
    elif item["output_sha256"] is not None or item["artifact_id"] is not None:
        _fail("unavailable_run_has_output")
    return item


def validate_cross_model_comparison(value: Any, corpus_value: Any) -> dict[str, Any]:
    """Validate a companion matrix against the exact validated corpus identity."""
    corpus = validate_corpus(corpus_value)
    comparison = _exact(
        value,
        {"contract_version", "comparison_id", "corpus_id", "dataset_version", "procedure", "cases"},
        "invalid_cross_model_contract",
    )
    if comparison["contract_version"] != CROSS_MODEL_VERSION:
        _fail("unsupported_cross_model_contract")
    if comparison["corpus_id"] != corpus["corpus_id"] or comparison["dataset_version"] != corpus["dataset_version"]:
        _fail("cross_model_corpus_mismatch")
    _identifier(comparison["comparison_id"], "invalid_comparison_id")
    procedure = _exact(comparison["procedure"], {"revision", "relation_origin", "frozen_sha256"}, "invalid_procedure")
    _identifier(procedure["revision"], "invalid_procedure_revision")
    if procedure["relation_origin"] != "declared_reporter_relation":
        _fail("invalid_relation_origin")
    _hash(procedure["frozen_sha256"], "invalid_procedure_hash")

    expected_cases = {case["identity"]["case_id"]: case["identity"] for case in corpus["cases"]}
    cases = comparison["cases"]
    if not isinstance(cases, list) or len(cases) > MAX_CASES:
        _fail("invalid_cross_model_cases")
    case_ids: set[str] = set()
    run_ids: set[str] = set()
    artifact_ids: set[str] = set()
    all_units = 0
    all_runs = 0
    for case in cases:
        item = _exact(case, {"case_id", "identity", "runs", "anchors", "records", "units"}, "invalid_cross_model_case")
        case_id = _identifier(item["case_id"], "invalid_case_id")
        if case_id in case_ids:
            _fail("duplicate_case_id")
        case_ids.add(case_id)
        identity = item["identity"]
        if case_id not in expected_cases or identity != expected_cases[case_id]:
            _fail("cross_model_snapshot_mismatch")
        runs = item["runs"]
        if not isinstance(runs, list) or len(runs) != len(ROLES):
            _fail("missing_or_duplicate_role_run")
        run_by_role: dict[str, dict[str, Any]] = {}
        for run in runs:
            if not isinstance(run, dict) or run.get("role") not in ROLES or run.get("role") in run_by_role:
                _fail("missing_or_duplicate_role_run")
            run_by_role[run["role"]] = _validate_run(run, run["role"], run_ids)
            for artifact_id in (run_by_role[run["role"]]["input_artifact_id"], run_by_role[run["role"]]["artifact_id"]):
                if artifact_id is not None:
                    if artifact_id in artifact_ids:
                        _fail("duplicate_artifact_id")
                    artifact_ids.add(artifact_id)
            all_runs += 1
        if set(run_by_role) != set(ROLES):
            _fail("missing_or_duplicate_role_run")

        anchors = item["anchors"]
        if not isinstance(anchors, list) or len(anchors) > MAX_ANCHORS_PER_CASE:
            _fail("invalid_anchors")
        anchor_ids: set[str] = set()
        for anchor in anchors:
            anchor = _exact(anchor, {"anchor_id", "path", "line_start", "line_end"}, "invalid_anchor")
            aid = _identifier(anchor["anchor_id"], "invalid_anchor_id")
            if aid in anchor_ids:
                _fail("duplicate_anchor_id")
            anchor_ids.add(aid)
            path = anchor["path"]
            if not isinstance(path, str):
                _fail("invalid_anchor_path")
            try:
                if len(path.encode("utf-8")) > 1024:
                    _fail("invalid_anchor_path")
            except UnicodeError:
                _fail("invalid_anchor_path")
            parsed = PurePosixPath(path)
            if not path or "\x00" in path or parsed.is_absolute() or any(part in {"", ".", ".."} for part in path.split("/")) or path.startswith("-"):
                _fail("invalid_anchor_path")
            if not isinstance(anchor["line_start"], int) or isinstance(anchor["line_start"], bool) or anchor["line_start"] < 1:
                _fail("invalid_anchor_lines")
            if not isinstance(anchor["line_end"], int) or isinstance(anchor["line_end"], bool) or anchor["line_end"] < anchor["line_start"]:
                _fail("invalid_anchor_lines")

        records = item["records"]
        if not isinstance(records, list) or len(records) > MAX_RECORDS_PER_CASE:
            _fail("invalid_records")
        record_ids: set[tuple[str, str]] = set()
        for record in records:
            record = _exact(record, {"role", "record_id", "record_kind", "anchor_ids"}, "invalid_record")
            if record["role"] not in ROLES or not isinstance(record["record_kind"], str) or record["record_kind"] not in RECORD_KINDS:
                _fail("invalid_record_role")
            rid = _identifier(record["record_id"], "invalid_record_id")
            key = (record["role"], rid)
            if key in record_ids:
                _fail("duplicate_record_id")
            record_ids.add(key)
            refs = record["anchor_ids"]
            if not isinstance(refs, list) or len(refs) > 500:
                _fail("invalid_record_anchor_ids")
            ref_ids = [_identifier(ref, "invalid_record_anchor_id") for ref in refs]
            if len(ref_ids) != len(set(ref_ids)):
                _fail("duplicate_record_anchor_id")
            if any(ref not in anchor_ids for ref in ref_ids):
                _fail("unresolved_record_anchor")
            if run_by_role[record["role"]]["status"] in {"not_run", "unavailable"}:
                _fail("record_without_role_output")

        units = item["units"]
        if not isinstance(units, list) or len(units) > MAX_UNITS_PER_CASE:
            _fail("invalid_units")
        unit_ids: set[tuple[str, str]] = set()
        for unit in units:
            unit = _exact(unit, {"pair", "unit_id", "left", "right", "relation", "relation_reporter", "reporter_record_id"}, "invalid_comparison_unit")
            pair = unit["pair"]
            if not isinstance(pair, str) or pair not in PAIR_ROLES or not isinstance(unit["relation"], str) or unit["relation"] not in RELATIONS:
                _fail("invalid_pair_or_relation")
            left_role, right_role = PAIR_ROLES[pair]
            if unit["relation_reporter"] != right_role:
                _fail("relation_reporter_mismatch")
            reporter_record_id = unit["reporter_record_id"]
            if reporter_record_id is not None:
                reporter_record_id = _identifier(reporter_record_id, "invalid_reporter_record_id")
                if (right_role, reporter_record_id) not in record_ids:
                    _fail("unresolved_reporter_record")
            elif run_by_role[right_role]["output_sha256"] is not None:
                _fail("missing_reporter_record")
            uid = _identifier(unit["unit_id"], "invalid_unit_id")
            key = pair, uid
            if key in unit_ids:
                _fail("duplicate_unit_id")
            unit_ids.add(key)
            slots = []
            for slot, role in ((unit["left"], left_role), (unit["right"], right_role)):
                slot = _exact(slot, {"state", "record_id"}, "invalid_unit_slot")
                if not isinstance(slot["state"], str) or slot["state"] not in SLOT_STATES:
                    _fail("invalid_slot_status")
                if slot["state"] == "record":
                    rid = _identifier(slot["record_id"], "invalid_slot_record_id")
                    if slot["record_id"] is None or (role, rid) not in record_ids:
                        _fail("unresolved_unit_record")
                elif slot["record_id"] is not None:
                    _fail("nonrecord_slot_has_record")
                slots.append(slot)

            for slot, role in zip(slots, (left_role, right_role), strict=True):
                role_status = run_by_role[role]["status"]
                if role_status == "not_run" and slot["state"] != "not_run":
                    _fail("role_slot_status_mismatch")
                if role_status == "abstained" and slot["state"] != "abstained":
                    _fail("role_slot_status_mismatch")
                if role_status == "unavailable" and slot["state"] != "incomplete":
                    _fail("role_slot_status_mismatch")

            relation = unit["relation"]
            role_runs = (run_by_role[left_role], run_by_role[right_role])
            run_statuses = {r["status"] for r in role_runs}
            slot_states = {s["state"] for s in slots}
            required = None
            if "not_run" in run_statuses or "not_run" in slot_states:
                required = "NOT_RUN"
            elif run_statuses & _BAD_RUNS or "incomplete" in slot_states:
                required = "INCOMPLETE"
            elif "abstained" in run_statuses or "abstained" in slot_states:
                required = "ABSTAINED"
            elif relation in {"MATCH", "DISAGREEMENT"} and all(s["state"] == "record" for s in slots):
                required = relation
            elif relation == "NO_COUNTERPART" and sorted(s["state"] for s in slots) == ["no_counterpart", "record"]:
                required = relation
            else:
                _fail("relation_slot_contradiction")
            if relation != required:
                _fail("relation_masks_missing_or_abstained_role")
            if relation in {"MATCH", "DISAGREEMENT", "NO_COUNTERPART", "ABSTAINED"} and reporter_record_id is None:
                _fail("missing_reporter_record")
            if relation in {"MATCH", "DISAGREEMENT"} and unit["right"]["record_id"] != reporter_record_id:
                _fail("relation_reporter_record_mismatch")
            all_units += 1

    if case_ids != set(expected_cases):
        _fail("cross_model_case_coverage_mismatch")
    if all_runs > MAX_RUNS:
        _fail("too_many_role_runs")
    if all_units > MAX_CASES * MAX_UNITS_PER_CASE:
        _fail("too_many_units")
    return comparison


_GIT_OUTPUT_LIMIT = b"\x00CROSS_MODEL_GIT_OUTPUT_LIMIT\x00"
_GIT_CHECK_FAILED = b"\x00CROSS_MODEL_GIT_CHECK_FAILED\x00"


def _git(root: Path, *args: str, deadline: float | None = None) -> bytes | None:
    limit = MAX_ANCHOR_SOURCE_BYTES if args and args[0] == "show" else MAX_DIFF_BYTES
    timeout = MAX_GIT_CALL_SECONDS
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
    if timeout <= 0:
        return _GIT_CHECK_FAILED
    git_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    git_env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
        }
    )
    output_queue: queue.Queue[bytes | None] = queue.Queue(maxsize=2)
    stop_reader = threading.Event()
    reader: threading.Thread | None = None
    process: subprocess.Popen[bytes] | None = None

    def stop_process() -> None:
        if process is None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            elif process.poll() is None:
                process.kill()
        except (OSError, ProcessLookupError):
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass

    def read_output(pipe) -> None:
        try:
            while True:
                block = pipe.read(64 * 1024)
                if not block:
                    break
                while not stop_reader.is_set():
                    try:
                        output_queue.put(block, timeout=0.1)
                        break
                    except queue.Full:
                        continue
                if stop_reader.is_set():
                    break
        finally:
            while not stop_reader.is_set():
                try:
                    output_queue.put(None, timeout=0.1)
                    break
                except queue.Full:
                    continue

    try:
        process = subprocess.Popen(
            ["git", "--no-lazy-fetch", "--no-replace-objects", "-C", str(root), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=git_env,
            start_new_session=(os.name == "posix"),
        )
        if process.stdout is None:
            process.kill()
            process.wait(timeout=1)
            return _GIT_CHECK_FAILED
        reader = threading.Thread(target=read_output, args=(process.stdout,), daemon=True)
        reader.start()
        chunks: list[bytes] = []
        total = 0
        end = time.monotonic() + timeout
        if deadline is not None:
            end = min(end, deadline)
        while True:
            remaining_time = end - time.monotonic()
            if remaining_time <= 0:
                raise subprocess.TimeoutExpired("git", timeout)
            try:
                block = output_queue.get(timeout=remaining_time)
            except queue.Empty:
                raise subprocess.TimeoutExpired("git", timeout) from None
            if block is None:
                break
            total += len(block)
            if total > limit:
                stop_process()
                return _GIT_OUTPUT_LIMIT
            chunks.append(block)
        returncode = process.wait(timeout=max(0.01, end - time.monotonic()))
        return b"".join(chunks) if returncode == 0 else None
    except subprocess.TimeoutExpired:
        stop_process()
        return _GIT_CHECK_FAILED
    except OSError:
        return _GIT_CHECK_FAILED
    finally:
        stop_reader.set()
        if process is not None and process.stdout is not None:
            process.stdout.close()
        if reader is not None:
            reader.join(timeout=0.1)


def _anchor_statuses(
    root: Path | None,
    identity: dict[str, Any],
    anchors: list[dict[str, Any]],
    *,
    deadline: float,
    path_budget: int,
) -> tuple[dict[str, str], int]:
    if root is None:
        return {item["anchor_id"]: "NOT_RUN" for item in anchors}, 0
    if not anchors:
        return {}, 0
    if time.monotonic() >= deadline or path_budget <= 0:
        return {item["anchor_id"]: "CHECK_LIMIT" for item in anchors}, 0
    head = _git(root, "rev-parse", "HEAD", deadline=deadline)
    if head is None or head == _GIT_CHECK_FAILED:
        return {item["anchor_id"]: "CHECK_FAILED" for item in anchors}, 0
    if head == _GIT_OUTPUT_LIMIT:
        return {item["anchor_id"]: "CHECK_LIMIT" for item in anchors}, 0
    if head.decode("ascii", "ignore").strip().lower() != identity["head_sha"].lower():
        return {item["anchor_id"]: "SNAPSHOT_MISMATCH" for item in anchors}, 0
    base = _git(root, "cat-file", "-e", f"{identity['base_sha']}^{{commit}}", deadline=deadline)
    if base is None or base == _GIT_CHECK_FAILED:
        return {item["anchor_id"]: "CHECK_FAILED" for item in anchors}, 0
    paths = sorted({item["path"] for item in anchors})
    selected_paths = set(paths[:path_budget])
    path_state: dict[str, tuple[str | None, list[tuple[int, int]], int]] = {}
    hunk = re.compile(rb"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)
    for path in paths:
        if path not in selected_paths or time.monotonic() >= deadline:
            path_state[path] = ("CHECK_LIMIT", [], 0)
            continue
        source = _git(root, "show", f"{identity['head_sha']}:{path}", deadline=deadline)
        if source == _GIT_CHECK_FAILED:
            path_state[path] = ("CHECK_FAILED", [], 0)
            continue
        if source == _GIT_OUTPUT_LIMIT:
            path_state[path] = ("CHECK_LIMIT", [], 0)
            continue
        if source is None:
            path_state[path] = ("PATH_MISSING", [], 0)
            continue
        diff = _git(root, "--no-pager", "diff", "--no-ext-diff", "--no-textconv", "--unified=0", identity["base_sha"], identity["head_sha"], "--", f":(literal){path}", deadline=deadline)
        if diff == _GIT_CHECK_FAILED:
            path_state[path] = ("CHECK_FAILED", [], 0)
            continue
        if diff == _GIT_OUTPUT_LIMIT:
            path_state[path] = ("CHECK_LIMIT", [], 0)
            continue
        if diff is None:
            path_state[path] = ("CHECK_FAILED", [], 0)
            continue
        changed_ranges = []
        for match in hunk.finditer(diff):
            start = int(match.group(1))
            count = int(match.group(2) or b"1")
            if count:
                changed_ranges.append((start, start + count - 1))
        path_state[path] = (None, changed_ranges, len(source.splitlines()))
    result = {}
    for anchor in anchors:
        state, changed, *line_count = path_state[anchor["path"]]
        if state is not None:
            result[anchor["anchor_id"]] = state
        elif anchor["line_end"] > line_count[0]:
            result[anchor["anchor_id"]] = "LINE_OUT_OF_RANGE"
        elif any(start <= anchor["line_end"] and end >= anchor["line_start"] for start, end in changed):
            result[anchor["anchor_id"]] = "CHANGED_RANGE"
        else:
            result[anchor["anchor_id"]] = "EXISTING_HEAD_RANGE"
    return result, min(len(paths), path_budget)


def _verify_artifact(path: Path, expected_hash: str, remaining_bytes: int) -> tuple[str, str | None, int]:
    try:
        absolute = path.absolute()
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current = current / part
            if current.is_symlink():
                return "SYMLINK", None, 0
        info = absolute.lstat()
        if not stat.S_ISREG(info.st_mode):
            return "NOT_REGULAR", None, 0
        if info.st_size > MAX_ARTIFACT_BYTES:
            return "TOO_LARGE", None, 0
        if info.st_size > remaining_bytes:
            return "CHECK_LIMIT", None, 0
        descriptor = os.open(absolute, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                return "NOT_REGULAR", None, 0
            if opened.st_size > MAX_ARTIFACT_BYTES:
                return "TOO_LARGE", None, 0
            if opened.st_size > remaining_bytes:
                return "CHECK_LIMIT", None, 0
            digest = hashlib.sha256()
            total = 0
            while True:
                block = os.read(descriptor, min(64 * 1024, MAX_ARTIFACT_BYTES + 1 - total))
                if not block:
                    break
                total += len(block)
                if total > MAX_ARTIFACT_BYTES:
                    return "TOO_LARGE", None, total
                digest.update(block)
        finally:
            os.close(descriptor)
    except FileNotFoundError:
        return "UNREADABLE", None, 0
    except OSError:
        return "UNREADABLE", None, 0
    observed_hash = digest.hexdigest()
    return ("VERIFIED" if observed_hash == expected_hash else "HASH_MISMATCH"), observed_hash, total


def compare_cross_model(
    comparison_value: Any,
    corpus_value: Any,
    *,
    snapshot_roots: dict[str, Path] | None = None,
    artifacts: dict[str, Path] | None = None,
    corpus_sha256: str | None = None,
    input_sha256: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic summary without raw outputs or quality claims."""
    comparison = validate_cross_model_comparison(comparison_value, corpus_value)
    snapshot_roots = snapshot_roots or {}
    artifacts = artifacts or {}
    if corpus_sha256 is not None:
        _hash(corpus_sha256, "invalid_corpus_sha256")
    if input_sha256 is not None:
        _hash(input_sha256, "invalid_comparison_sha256")
    if set(snapshot_roots) - {c["case_id"] for c in comparison["cases"]}:
        _fail("snapshot_root_for_unknown_case")
    expected_artifacts: dict[str, tuple[str, str, str]] = {}
    for case in comparison["cases"]:
        for run in case["runs"]:
            if run["input_artifact_id"] is not None:
                expected_artifacts[run["input_artifact_id"]] = (run["input_sha256"], run["role"], "input")
            if run["artifact_id"] is not None:
                expected_artifacts[run["artifact_id"]] = (run["output_sha256"], run["role"], "output")
    if set(artifacts) - set(expected_artifacts):
        _fail("artifact_for_unknown_id")
    artifact_rows = []
    artifact_status_by_id: dict[str, str] = {}
    artifact_bytes_checked = 0
    artifacts_checked = 0
    for artifact_id, (expected_hash, role, kind) in expected_artifacts.items():
        if artifact_id in artifacts:
            if artifacts_checked >= MAX_ARTIFACTS_CHECKED or artifact_bytes_checked >= MAX_TOTAL_ARTIFACT_BYTES:
                status, observed_hash, bytes_read = "CHECK_LIMIT", None, 0
            else:
                artifacts_checked += 1
                status, observed_hash, bytes_read = _verify_artifact(
                    artifacts[artifact_id], expected_hash, MAX_TOTAL_ARTIFACT_BYTES - artifact_bytes_checked
                )
                artifact_bytes_checked += bytes_read
        else:
            status, observed_hash, bytes_read = "NOT_PROVIDED", None, 0
        artifact_status_by_id[artifact_id] = status
        artifact_rows.append({
            "artifact_id": artifact_id,
            "role": role,
            "kind": kind,
            "status": status,
            "declared_sha256": expected_hash,
            "observed_sha256": observed_hash,
        })
    role_counts = {role: Counter({status: 0 for status in sorted(RUN_STATUSES)}) for role in ROLES}
    pair_counts = {pair: Counter({status: 0 for status in sorted(RELATIONS)}) for pair in PAIR_ROLES}
    anchor_counts: Counter[str] = Counter({status: 0 for status in sorted(ANCHOR_STATUSES)})
    case_reports: list[dict[str, Any]] = []
    total_roles = total_anchors = total_units = 0
    anchor_deadline = time.monotonic() + MAX_ANCHOR_CHECK_SECONDS
    remaining_anchor_paths = MAX_ANCHOR_PATHS
    for case in comparison["cases"]:
        runs = {run["role"]: run for run in case["runs"]}
        role_summary = {}
        for role in ROLES:
            run = runs[role]
            role_counts[role][run["status"]] += 1
            total_roles += 1
            role_summary[role] = {
                "status": run["status"],
                "run_id": run["run_id"],
                "provider_id": run["provider_id"],
                "model_id": run["model_id"],
                "runtime_id": run["runtime_id"],
                "prompt_revision": run["prompt_revision"],
                "rubric_revision": run["rubric_revision"],
                "input_sha256": run["input_sha256"],
                "input_artifact_id": run["input_artifact_id"],
                "input_artifact_status": artifact_status_by_id.get(run["input_artifact_id"], "NOT_APPLICABLE"),
                "output_sha256": run["output_sha256"],
                "artifact_id": run["artifact_id"],
                "output_artifact_status": artifact_status_by_id.get(run["artifact_id"], "NOT_APPLICABLE"),
                "record_count": sum(record["role"] == role for record in case["records"]),
                "records_by_kind": {
                    kind: sum(record["role"] == role and record["record_kind"] == kind for record in case["records"])
                    for kind in sorted(RECORD_KINDS)
                },
            }
        root = snapshot_roots.get(case["case_id"])
        anchor_rows = []
        checked_anchors, used_paths = _anchor_statuses(
            root,
            case["identity"],
            case["anchors"],
            deadline=anchor_deadline,
            path_budget=remaining_anchor_paths,
        )
        remaining_anchor_paths -= used_paths
        for anchor in case["anchors"]:
            status = checked_anchors[anchor["anchor_id"]]
            anchor_counts[status] += 1
            total_anchors += 1
            anchor_rows.append({"anchor_id": anchor["anchor_id"], "status": status})
        for unit in case["units"]:
            pair_counts[unit["pair"]][unit["relation"]] += 1
            total_units += 1
        case_reports.append({
            "case_id": case["case_id"],
            "identity_sha256": _identity_digest(case["identity"]),
            "roles": role_summary,
            "anchors": anchor_rows,
            "comparison_units": [
                {
                    "pair": u["pair"],
                    "unit_id": u["unit_id"],
                    "relation": u["relation"],
                    "relation_reporter": u["relation_reporter"],
                    "reporter_record_id": u["reporter_record_id"],
                    "relation_provenance_status": "DECLARED_ONLY",
                }
                for u in case["units"]
            ],
        })
    summary = {
        "contract_version": CROSS_MODEL_VERSION,
        "comparison_id": comparison["comparison_id"],
        "corpus_id": comparison["corpus_id"],
        "dataset_version": comparison["dataset_version"],
        "corpus_sha256": corpus_sha256,
        "input_sha256": input_sha256,
        "hashes_are_authentication": False,
        "evidence_kind": "advisory_model_only_cross_model_evidence",
        "relation_semantics": "declared_reporter_relation_only; not verified in output bytes, factual support, or correctness",
        "claims": {"accuracy": None, "ground_truth": None, "calibration": None, "correctness": None},
        "role_run_counts": {
            role: {"denominator": len(comparison["cases"]), "status_counts": dict(role_counts[role])}
            for role in ROLES
        },
        "role_record_counts": {
            role: {
                "case_denominator": len(comparison["cases"]),
                "cases_with_records": sum(any(record["role"] == role for record in case["records"]) for case in comparison["cases"]),
                "cases_with_zero_records": sum(not any(record["role"] == role for record in case["records"]) for case in comparison["cases"]),
                "record_denominator": sum(record["role"] == role for case in comparison["cases"] for record in case["records"]),
                "record_kind_counts": {
                    kind: sum(record["role"] == role and record["record_kind"] == kind for case in comparison["cases"] for record in case["records"])
                    for kind in sorted(RECORD_KINDS)
                },
                "candidate_or_decision_count": sum(
                    record["role"] == role and record["record_kind"] == ROLE_RECORD_KINDS[role]
                    for case in comparison["cases"] for record in case["records"]
                ),
                "candidate_or_decision_cases_with_zero": sum(
                    not any(record["role"] == role and record["record_kind"] == ROLE_RECORD_KINDS[role] for record in case["records"])
                    for case in comparison["cases"]
                ),
            }
            for role in ROLES
        },
        "all_role_runs": {"denominator": total_roles, "status_counts": {status: sum(role_counts[r][status] for r in ROLES) for status in sorted(RUN_STATUSES)}},
        "pair_comparison_counts": {
            pair: {"denominator": sum(pair_counts[pair].values()), "status_counts": dict(pair_counts[pair])}
            for pair in PAIR_ROLES
        },
        "relation_provenance": {"denominator": total_units, "status_counts": {"DECLARED_ONLY": total_units}},
        "deterministic_anchor_counts": {"denominator": total_anchors, "status_counts": dict(anchor_counts)},
        "artifact_verification": {
            "scope": "supplied_local_bytes_only",
            "unprovided_means": "DECLARED_ONLY",
            "hash_verification_proves": "local_bytes_match_declared_hash_only",
            "remote_delivery_proven": False,
            "denominator": len(artifact_rows),
            "status_counts": {
                status: sum(row["status"] == status for row in artifact_rows)
                for status in ("VERIFIED", "HASH_MISMATCH", "NOT_PROVIDED", "UNREADABLE", "SYMLINK", "NOT_REGULAR", "TOO_LARGE", "CHECK_LIMIT")
            },
            "checked_artifact_limit": MAX_ARTIFACTS_CHECKED,
            "checked_byte_limit": MAX_TOTAL_ARTIFACT_BYTES,
            "artifacts": artifact_rows,
        },
        "cases": case_reports,
    }
    encoded = _canonical(summary)
    if len(encoded) > MAX_OUTPUT_BYTES:
        _fail("cross_model_report_too_large")
    summary["report_sha256"] = hashlib.sha256(encoded).hexdigest()
    return summary


def parse_cross_model_json(data: bytes, label: str) -> Any:
    if len(data) > MAX_INPUT_BYTES:
        _fail(f"{label}_too_large")
    return parse_bounded_json(data, label)
