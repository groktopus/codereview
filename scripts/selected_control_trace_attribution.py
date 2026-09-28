#!/usr/bin/env python3
"""Attribute bounded observer trace bytes for the frozen synthetic control case.

This is a secretless loopback diagnostic, not a model-quality or live-HTTPS
equivalence test. It uses the normal installed CLI and a parser wrapper that
retains fixed syscall counts and byte totals. Lexical path classes are available
only where the observer input exposes a path (currently openat); raw-argument
newfstatat rows remain explicitly unknown. No observed paths are retained.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness import external_effect_observer as observer  # noqa: E402
from pr_review_harness.claim_assessment import (  # noqa: E402
    CONTRACT_VERSION,
    PRIMARY_ASSESSMENT_CONTRACT_VERSION,
    _questions,
)
from pr_review_harness.injection_trials import invoke_cli_bounded, prepare_suite  # noqa: E402
from pr_review_harness.planner import plan_review  # noqa: E402
from pr_review_harness.selected_model_trial import (  # noqa: E402
    CASE_IDS,
    MAX_CLAIM_ASSESSMENTS_PER_RUN,
    _command,
    _limits,
    _runtime_provenance,
    canonical_json,
)

MAX_HTTP_REQUEST_BYTES = 64_000
MAX_HTTP_RESPONSE_BYTES = 32_768
MAX_SUMMARY_BYTES = 65_536
TRANSPORT_PAIR_DEADLINE_SECONDS = 660
DIAGNOSTIC_CONTRACT_VERSION = "selected-control-trace-attribution.v4"
CARDINALITY_PAIR_CONTRACT_VERSION = "selected-control-candidate-cardinality-pair.v2"
FAKE_PROVIDER_KEY = "loopback-only-synthetic-key"
FAKE_DECISION_KEY = "loopback-only-synthetic-decision-key"
FAKE_MODEL = "synthetic-control-model"
JEV_ALIAS = "jev-latest"
JEV_REPORTED_MODEL = "jev-1.13.0"
_TASK_STATUSES = frozenset(
    {
        "FAILED", "INTERRUPTED_UNKNOWN", "INVALID", "NOT_CONFIGURED", "NOT_RUN",
        "MISSING_RESULT", "PREPARING", "RECEIVED", "RESERVED", "SKIPPED", "SUCCEEDED", "TIMED_OUT",
        "VALID_UNRESOLVED",
    }
)
KNOWN_SYSCALLS = frozenset(
    "access arch_prctl brk chdir chmod clone clone3 close connect dup dup2 dup3 execve execveat exit exit_group "
    "fcntl fstat fstatat64 futex getcwd getdents64 getegid geteuid getgid getrandom getuid ioctl lseek madvise "
    "mmap mprotect mkdir mkdirat nanosleep newfstatat open openat openat2 pipe pipe2 poll ppoll prlimit64 read "
    "readlink recvfrom rename renameat renameat2 rt_sigaction rt_sigprocmask rt_sigreturn rseq sendto set_robust_list "
    "socket stat statx unlink unlinkat uname vfork wait4 waitid write"
    .split()
)
_SYSCALL_LABELS = tuple(sorted((*KNOWN_SYSCALLS, "OTHER")))
_TRACE_LINE_LABELS = tuple(sorted((*KNOWN_SYSCALLS, "OTHER", "PROCESS_END", "SIGNAL", "UNPARSED")))
_RAW_SYSCALL = re.compile(r"^(?:(?:\[pid\s+\d+\]|\[\d+\]|\d+)\s+)?([A-Za-z_][A-Za-z0-9_]*)\(")
_TARGET_SYSCALL = re.compile(
    r"^(?:(?:\[pid\s+\d+\]|\[\d+\]|\d+)\s+)?(openat|newfstatat)\((.*)$"
)
_RESUMED_TARGET_SYSCALL = re.compile(
    r"^(?:(?:\[pid\s+\d+\]|\[\d+\]|\d+)\s+)?<\.\.\.\s+(openat|newfstatat)\s+resumed>"
)
_DIRFD_AND_PATH = re.compile(
    r"^\s*(AT_FDCWD|-?[0-9]+)\s*,\s*(\"(?:\\.|[^\"\\])*\")(?=\s*,)"
)
_RAW_HEX_VALUE = r"(?:0|0x[1-9a-fA-F][0-9a-fA-F]{0,15})"
_RAW_NEWFSTATAT_ARGS = rf"\s*{_RAW_HEX_VALUE}\s*,\s*{_RAW_HEX_VALUE}\s*,\s*{_RAW_HEX_VALUE}\s*,\s*{_RAW_HEX_VALUE}\s*\)"
_RAW_NEWFSTATAT_SUCCESS = re.compile(rf"^{_RAW_NEWFSTATAT_ARGS}\s+=\s+{_RAW_HEX_VALUE}\s*$")
_RAW_NEWFSTATAT_ERROR = re.compile(
    rf"^{_RAW_NEWFSTATAT_ARGS}\s+=\s+-1\s+[A-Z][A-Z0-9_]*(?:\s+\([^()\n]{{0,256}}\))?\s*$"
)
_SYSTEM_PATH_ROOTS = (
    "/usr", "/lib", "/lib64", "/etc", "/proc", "/dev", "/var", "/run",
    "/opt", "/System", "/Library", "/Applications",
)
_FILE_PATH_CLASSES = (
    "CASE_WORKDIR", "CLI_ENVIRONMENT", "REPO_SUPPORT", "TEMP_ROOT", "SYSTEM_ROOT",
    "OTHER_ABSOLUTE", "UNKNOWN_RELATIVE", "UNKNOWN_SYNTAX", "UNKNOWN_UNFINISHED",
    "UNKNOWN_RESUMED", "UNKNOWN_ELLIPSIS_AMBIGUOUS", "UNKNOWN_RAW_ARGUMENTS",
)
_TRUSTED_PATH_ROOT_CLASSES = frozenset(
    {"CASE_WORKDIR", "CLI_ENVIRONMENT", "REPO_SUPPORT", "TEMP_ROOT", "SYSTEM_ROOT"}
)


def _path_roots(*, cli: Path, work_root: Path, repo_support: Path) -> tuple[tuple[str, str], ...]:
    """Return trusted lexical roots; observed paths are never resolved or retained."""
    candidates = [
        ("CASE_WORKDIR", os.path.abspath(os.fspath(work_root))),
        ("CLI_ENVIRONMENT", os.path.abspath(os.fspath(cli.parent.parent))),
        ("REPO_SUPPORT", os.path.abspath(os.fspath(repo_support))),
        ("TEMP_ROOT", os.path.abspath(tempfile.gettempdir())),
        *(('SYSTEM_ROOT', root) for root in _SYSTEM_PATH_ROOTS),
    ]
    # More specific roots win when trusted roots are nested.
    return tuple(sorted(candidates, key=lambda item: len(item[1]), reverse=True))


def _path_class_for_line(line: str, syscall: str, roots: tuple[tuple[str, str], ...]) -> str:
    """Classify a target syscall lexically, without retaining or resolving its path."""
    if _RESUMED_TARGET_SYSCALL.match(line):
        return "UNKNOWN_RESUMED"
    if "<unfinished ...>" in line:
        return "UNKNOWN_UNFINISHED"
    match = _TARGET_SYSCALL.match(line)
    if not match or match.group(1) != syscall:
        return "UNKNOWN_SYNTAX"
    args = match.group(2)
    if syscall == "newfstatat":
        raw_shape = _RAW_NEWFSTATAT_SUCCESS.fullmatch(args) or _RAW_NEWFSTATAT_ERROR.fullmatch(args)
        return "UNKNOWN_RAW_ARGUMENTS" if raw_shape else "UNKNOWN_SYNTAX"
    parsed = _DIRFD_AND_PATH.match(args)
    if parsed is None:
        return "UNKNOWN_SYNTAX"
    token = parsed.group(2)
    try:
        value = _decode_strace_c_string(token)
    except (ValueError, UnicodeError):
        return "UNKNOWN_SYNTAX"
    if "\x00" in value:
        return "UNKNOWN_SYNTAX"
    if value.endswith("..."):
        return "UNKNOWN_ELLIPSIS_AMBIGUOUS"
    if not value.startswith("/"):
        return "UNKNOWN_RELATIVE"
    lexical = os.path.normpath(value)
    for path_class, root in roots:
        if (
            path_class in _TRUSTED_PATH_ROOT_CLASSES
            and (lexical == root or lexical.startswith(root.rstrip(os.sep) + os.sep))
        ):
            return path_class
    return "OTHER_ABSOLUTE"


def _decode_strace_c_string(token: str) -> str:
    """Decode a bounded C-style quoted pathname; reject unsupported escapes."""
    if len(token) < 2 or token[0] != '"' or token[-1] != '"':
        raise ValueError("quoted_path_invalid")
    source = token[1:-1]
    escapes = {
        "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r",
        "t": "\t", "v": "\v", "\\": "\\", '"': '"', "'": "'", "?": "?",
    }
    output: list[str] = []
    index = 0
    while index < len(source):
        char = source[index]
        if char != "\\":
            output.append(char)
            index += 1
            continue
        index += 1
        if index >= len(source):
            raise ValueError("escape_incomplete")
        escaped = source[index]
        if escaped in escapes:
            output.append(escapes[escaped])
            index += 1
        elif escaped in "01234567":
            end = index + 1
            while end < min(index + 3, len(source)) and source[end] in "01234567":
                end += 1
            output.append(chr(int(source[index:end], 8)))
            index = end
        elif escaped == "x":
            end = index + 1
            while end < len(source) and end <= index + 2 and source[end] in "0123456789abcdefABCDEF":
                end += 1
            if end == index + 1:
                raise ValueError("hex_escape_empty")
            output.append(chr(int(source[index + 1 : end], 16)))
            index = end
        else:
            # Python accepts implementation-specific/unknown escapes and \u/\U;
            # strace's escaped C-string representation is not a Python literal.
            raise ValueError("escape_unsupported")
    return "".join(output)


def _label_line(line: str) -> str:
    """Map a raw trace line to a fixed syscall label without retaining it."""
    match = _RAW_SYSCALL.match(line)
    if match:
        name = match.group(1)
        return name if name in KNOWN_SYSCALLS else "OTHER"
    if "+++ " in line and " +++" in line:
        return "PROCESS_END"
    if line.startswith("--- SIG"):
        return "SIGNAL"
    return "UNPARSED"


class _LineAttributor:
    def __init__(self, parser, cwd: Path, roots: tuple[tuple[str, str], ...] = ()):
        self.parser = parser
        self.cwd = cwd
        self.roots = roots
        self.bytes_by_label: Counter[str] = Counter()
        self.lines_by_label: Counter[str] = Counter()
        self.file_path_bytes: Counter[tuple[str, str]] = Counter()
        self.file_path_lines: Counter[tuple[str, str]] = Counter()
        self.target_file_bytes: Counter[str] = Counter()
        self.target_file_lines: Counter[str] = Counter()
        self.resumed_file_bytes: Counter[str] = Counter()
        self.resumed_file_lines: Counter[str] = Counter()
        self.total_line_bytes = 0
        self.parse_failures = 0

    def __call__(self, line: str, cwd: Path):
        label = _label_line(line)
        # The observer passes a decoded line after splitting on its newline.
        size = len(line.encode("utf-8", "strict")) + 1
        self.bytes_by_label[label] += size
        self.lines_by_label[label] += 1
        self.total_line_bytes += size
        try:
            parsed = self.parser(line, cwd)
        except Exception:
            self.parse_failures += 1
            target = _target_syscall(line)
            if target is not None:
                self._record_file_path(
                    target,
                    "UNKNOWN_RESUMED" if _RESUMED_TARGET_SYSCALL.match(line) else "UNKNOWN_SYNTAX",
                    size,
                    resumed=bool(_RESUMED_TARGET_SYSCALL.match(line)),
                )
            raise
        target = _target_syscall(line)
        if target is not None:
            path_class = _path_class_for_line(line, target, self.roots)
            self._record_file_path(target, path_class, size, resumed=bool(_RESUMED_TARGET_SYSCALL.match(line)))
        return parsed

    def _record_file_path(self, syscall: str, path_class: str, size: int, *, resumed: bool = False) -> None:
        self.target_file_bytes[syscall] += size
        self.target_file_lines[syscall] += 1
        self.file_path_bytes[(syscall, path_class)] += size
        self.file_path_lines[(syscall, path_class)] += 1
        if resumed:
            self.resumed_file_bytes[syscall] += size
            self.resumed_file_lines[syscall] += 1


def _target_syscall(line: str) -> str | None:
    resumed = _RESUMED_TARGET_SYSCALL.match(line)
    if resumed:
        return resumed.group(1)
    match = _TARGET_SYSCALL.match(line)
    return match.group(1) if match else None


def _file_path_projection(attributor: _LineAttributor, *, complete_trace: bool) -> dict[str, Any]:
    counts: dict[str, dict[str, int]] = {}
    byte_counts: dict[str, dict[str, int]] = {}
    count_reconciles = True
    bytes_reconcile = True
    for syscall in ("openat", "newfstatat"):
        counts[syscall] = {
            path_class: attributor.file_path_lines[(syscall, path_class)]
            for path_class in _FILE_PATH_CLASSES
            if attributor.file_path_lines[(syscall, path_class)]
        }
        byte_counts[syscall] = {
            path_class: attributor.file_path_bytes[(syscall, path_class)]
            for path_class in _FILE_PATH_CLASSES
            if attributor.file_path_bytes[(syscall, path_class)]
        }
        # Independently reconcile regular syscall rows to the existing attribution;
        # resumed fragments are deliberately `UNPARSED` in that unchanged channel.
        count_reconciles &= (
            sum(counts[syscall].values()) - attributor.resumed_file_lines[syscall]
            == attributor.lines_by_label[syscall]
        )
        bytes_reconcile &= (
            sum(byte_counts[syscall].values()) - attributor.resumed_file_bytes[syscall]
            == attributor.bytes_by_label[syscall]
        )
        count_reconciles &= sum(counts[syscall].values()) == attributor.target_file_lines[syscall]
        bytes_reconcile &= sum(byte_counts[syscall].values()) == attributor.target_file_bytes[syscall]
    reconciliation = count_reconciles and bytes_reconcile
    return {
        "state": "COMPLETE" if complete_trace and reconciliation else "PARTIAL",
        "state_meaning": "numeric_line_and_byte_accounting_complete_unknown_classes_are_valid",
        "basis": "lexical_path_namespace_only_no_symlink_fd_or_pid_cwd_resolution",
        "path_argument_visibility": {
            "openat": "path_visible_and_lexically_classified",
            "newfstatat": "raw_hex_arguments_path_unavailable",
        },
        "line_bytes": "decoded_utf8_line_bytes_plus_observed_newline_byte",
        "lines_by_syscall_class": counts,
        "bytes_by_syscall_class": byte_counts,
        "target_lines_by_syscall": {
            name: attributor.target_file_lines[name] for name in ("openat", "newfstatat")
        },
        "target_bytes_by_syscall": {
            name: attributor.target_file_bytes[name] for name in ("openat", "newfstatat")
        },
        "reconciliation": "MATCH" if reconciliation else "MISMATCH",
    }


class _CallCounters(Counter):
    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()


def _increment(counters: _CallCounters, name: str) -> None:
    with counters.lock:
        counters[name] += 1


def _increment_by(counters: _CallCounters, name: str, amount: int) -> None:
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
        raise ValueError("diagnostic_counter_amount_invalid")
    with counters.lock:
        counters[name] += amount


def _write_json_response(
    handler: BaseHTTPRequestHandler,
    response: dict[str, Any],
    response_stage: str,
) -> bool:
    encoded = json.dumps(response, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_HTTP_RESPONSE_BYTES:
        _increment(handler.server.counters, "response_size_rejections")
        handler.send_error(413)
        return False
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(encoded)))
    handler.end_headers()
    handler.wfile.write(encoded)
    handler.wfile.flush()
    # This records a server-side successful write/flush, not client parsing.
    _increment(handler.server.counters, "server_response_writes_completed")
    _increment(handler.server.counters, f"{response_stage}_response_writes_completed")
    if getattr(handler.server, "measure_payload_bytes", False):
        _increment_by(handler.server.counters, f"response_body_bytes_{response_stage}", len(encoded))
        handler.server.record_payload(response_stage, "response", len(encoded), hashlib.sha256(encoded).hexdigest())
    return True


def _request_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    try:
        length = int(handler.headers.get("Content-Length", "-1"))
    except ValueError:
        raise ValueError("bad_content_length") from None
    if not 0 <= length <= MAX_HTTP_REQUEST_BYTES:
        raise ValueError("request_size_invalid")
    raw = handler.rfile.read(length)
    if len(raw) != length:
        raise ValueError("request_truncated")
    handler._diagnostic_request_body_bytes = length
    handler._diagnostic_request_body_sha256 = hashlib.sha256(raw).hexdigest()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("request_not_object")
    return value


def _native_claim_contract_valid(request: dict[str, Any]) -> bool:
    """Match the exact pinned question set for the candidate and source sides."""
    state = request.get("state")
    questions = request.get("questions")
    if not isinstance(state, dict) or not isinstance(questions, dict):
        return False
    candidate = state.get("candidate")
    evidence = state.get("cited_evidence")
    if (
        not isinstance(candidate, dict)
        or not isinstance(candidate.get("candidate_id"), str)
        or not isinstance(evidence, list)
    ):
        return False
    sides = {item.get("side") for item in evidence if isinstance(item, dict)}
    include_introducedness = {"BASE", "HEAD"}.issubset(sides)
    contract_version = state.get("assessment_contract_version", CONTRACT_VERSION)
    if contract_version not in {CONTRACT_VERSION, PRIMARY_ASSESSMENT_CONTRACT_VERSION}:
        return False
    expected, _dimension_ids = _questions(
        candidate["candidate_id"], include_introducedness, contract_version
    )
    return request.get("model") == JEV_ALIAS and questions == expected


def _native_summary_contract_valid(request: dict[str, Any]) -> bool:
    state = request.get("state")
    questions = request.get("questions")
    if (
        set(request) != {"model", "state", "questions"}
        or request.get("model") != JEV_ALIAS
        or not isinstance(state, dict)
        or set(state) != {"review_evidence"}
        or not isinstance(state.get("review_evidence"), str)
        or not isinstance(questions, dict)
        or set(questions) != {"review_claim"}
    ):
        return False
    question = questions["review_claim"]
    instructions = question.get("instructions") if isinstance(question, dict) else None
    try:
        instruction_bytes = instructions.encode("utf-8") if isinstance(instructions, str) else b""
    except UnicodeEncodeError:
        return False
    return (
        isinstance(question, dict)
        and set(question) == {"type", "instructions"}
        and question.get("type") == "noul"
        and 0 < len(instruction_bytes) <= 8000
    )


def _project_task_statuses(
    durable: Any, planned_tasks: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]] | None, int]:
    if not isinstance(durable, dict) or not isinstance(durable.get("task_results"), dict):
        return None, 0
    task_results = durable["task_results"]
    rows: list[dict[str, Any]] = []
    claimed_result_ids: set[str] = set()
    for task in planned_tasks:
        task_id = task.get("task_id")
        lens = task.get("lens")
        if not isinstance(task_id, str) or lens not in {"correctness", "security", "tests"}:
            return None, 0
        matched = {
            key: value
            for key, value in task_results.items()
            if isinstance(key, str)
            and (key == task_id or re.fullmatch(re.escape(task_id) + r":chunk-[1-9][0-9]*", key))
        }
        claimed_result_ids.update(matched)
        statuses = [
            value.get("status") if isinstance(value, dict) else None
            for value in matched.values()
        ]
        if not statuses:
            status = "MISSING_RESULT"
        elif any(not isinstance(value, str) or value not in _TASK_STATUSES for value in statuses):
            status = "UNKNOWN"
        elif all(value == "SUCCEEDED" for value in statuses):
            status = "SUCCEEDED"
        else:
            status = "INCOMPLETE"
        rows.append(
            {
                "task_id": task_id,
                "lens": lens,
                "status": status,
                "chunk_count": len(matched),
                "completed_chunks": sum(value == "SUCCEEDED" for value in statuses),
            }
        )
    unexpected_count = sum(1 for key in task_results if key not in claimed_result_ids)
    return rows, unexpected_count


def _validate_candidate_cardinality(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value not in {1, 2}:
        raise ValueError("candidate_cardinality_invalid")
    return value


def _primary_payload(
    request: dict[str, Any], counters: _CallCounters, *, candidate_cardinality: int = 1
) -> dict[str, Any]:
    candidate_cardinality = _validate_candidate_cardinality(candidate_cardinality)
    messages = request.get("messages")
    if not isinstance(messages, list) or len(messages) < 2 or not isinstance(messages[-1], dict):
        raise ValueError("specialist_messages_invalid")
    user = json.loads(messages[-1].get("content", ""))
    if not isinstance(user, dict):
        raise ValueError("specialist_user_invalid")
    if set(user) == {"candidate", "evidence"}:
        _increment(counters, "semantic_adjudication_received")
        candidate = user["candidate"]
        refs = candidate.get("evidence_refs", [])
        evidence_ids = {item.get("evidence_id") for item in user["evidence"] if isinstance(item, dict)}
        refs = [ref for ref in refs if ref in evidence_ids]
        if not refs:
            raise ValueError("semantic_evidence_missing")
        all_refs = [item.get("evidence_id") for item in user["evidence"] if isinstance(item, dict)]
        all_refs = [ref for ref in all_refs if isinstance(ref, str) and ref in evidence_ids][:20]
        value = {
            "contract_version": "semantic-adjudication.v3",
            "outcome": "SUPPORTED",
            "observation_support": "SUPPORTED",
            "consequence_support": "SUPPORTED",
            "rule_connection_support": "SUPPORTED",
            "introducedness": "INTRODUCED",
            "material_consequence": True,
            "evidence_refs": all_refs,
            "assumptions": [],
            "uncertainties": [],
            "summary": "Synthetic response only; no quality inference is intended.",
            "causal_roles": {
                role: {
                    "support": "SUPPORTED",
                    "assessment": "A static synthetic response for protocol-path coverage.",
                    "evidence_refs": all_refs[:1],
                }
                for role in ("behavior", "consumer", "impact")
            },
        }
        return {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(value)}}],
                "model": FAKE_MODEL, "id": "loopback-semantic", "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                "_diagnostic_stage": "semantic_adjudication"}

    task = user.get("task")
    evidence = user.get("evidence")
    if not isinstance(task, dict) or not isinstance(evidence, list):
        raise ValueError("specialist_task_invalid")
    lens = task.get("lens")
    _increment(counters, f"primary_{lens if lens in {'correctness', 'security', 'tests'} else 'other'}_received")
    units = task.get("unit_ids")
    evidence_ids = [item.get("evidence_id") for item in evidence if isinstance(item, dict)]
    refs = [ref for ref in evidence_ids if isinstance(ref, str)][:20]
    if not units or not refs:
        raise ValueError("specialist_bindings_missing")
    candidates: list[dict[str, Any]] = []
    if lens == "security":
        diff_refs = [
            item.get("evidence_id")
            for item in evidence
            if isinstance(item, dict) and item.get("source_kind") == "diff" and item.get("evidence_id") in evidence_ids
        ]
        candidate_refs = diff_refs[:1] or refs[:1]
        candidates.append({
                "unit_id": units[0],
                "location": {"kind": "line", "path": "src/auth.py", "side": "HEAD", "line": 2, "reason": None},
                "title": "Synthetic authorization candidate",
                "observation": "The changed predicate no longer compares the caller and owner IDs.",
                "consequence": "A caller may pass the authorization check for another owner’s document.",
                "rule_or_contract": "The fixture’s authorization behavior requires owner matching.",
                "severity": "high",
                "reasoning_kind": "inferred",
                "evidence_refs": candidate_refs,
                "introducedness": "INTRODUCED",
            })
        if candidate_cardinality == 2:
            candidates.append(
                {
                    **candidates[0],
                    "title": "Synthetic request-scope candidate",
                    "observation": "The changed route accepts a request without checking resource ownership.",
                    "consequence": "A request may expose a record that belongs to a different owner.",
                    "rule_or_contract": "The synthetic route contract requires an ownership check on each request.",
                }
            )
    return {
        "_diagnostic_stage": f"primary_{lens}",
        "contract_version": "specialist-findings.v4",
        "finding_candidates": candidates,
        "context_gap_proposals": [],
        "coverage_notes": [
            {"unit_id": unit, "state": "COVERED", "reason_code": "SYNTHETIC_PROTOCOL_FIXTURE",
             "evidence_refs": refs, "coverage_basis": "STATIC_REVIEW"}
            for unit in units
        ],
        "specific_strengths": [],
        "future_guidance": [],
    } | {"_envelope": {"model": FAKE_MODEL, "id": "loopback-primary", "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}}


class _FakeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, *, ssl_context: ssl.SSLContext | None = None):
        self.counters = _CallCounters()
        self.primary_response_delay_seconds = 0.0
        self.candidate_cardinality = 1
        self.measure_payload_bytes = False
        self.payload_hashes: dict[str, dict[str, Any]] = {}
        self._active_handlers = 0
        self._idle_condition = threading.Condition()
        super().__init__(address, self.handler_type())
        if ssl_context is not None:
            self.socket = ssl_context.wrap_socket(self.socket, server_side=True)

    def record_payload(self, stage: str, direction: str, size: int, digest: str) -> None:
        if direction not in {"request", "response"} or not isinstance(stage, str):
            raise ValueError("payload_receipt_invalid")
        with self.counters.lock:
            row = self.payload_hashes.setdefault(stage, {})
            if direction in row:
                row[direction + "_duplicate_count"] = row.get(direction + "_duplicate_count", 0) + 1
                return
            row[direction + "_bytes"] = size
            row[direction + "_sha256"] = digest

    def handler_started(self) -> None:
        with self._idle_condition:
            self._active_handlers += 1

    def handler_finished(self) -> None:
        with self._idle_condition:
            self._active_handlers -= 1
            self._idle_condition.notify_all()

    def wait_until_idle(self, timeout: float) -> tuple[bool, int]:
        deadline = time.monotonic() + timeout
        with self._idle_condition:
            while self._active_handlers and time.monotonic() < deadline:
                self._idle_condition.wait(max(0.0, deadline - time.monotonic()))
            return self._active_handlers == 0, self._active_handlers

    @staticmethod
    def handler_type():
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.server.handler_started()
                _increment(self.server.counters, "http_requests_received")
                try:
                    request = _request_json(self)
                    counters = self.server.counters
                    response_stage = "unknown"
                    if self.path == "/v1/chat/completions":
                        response = _primary_payload(
                            request,
                            counters,
                            candidate_cardinality=self.server.candidate_cardinality,
                        )
                        response_stage = response.pop("_diagnostic_stage", "primary")
                        if "_envelope" in response:
                            envelope = response.pop("_envelope")
                            response = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(response)}}], **envelope}
                    elif self.path == "/v1/systemone":
                        questions = request.get("questions")
                        if not isinstance(questions, dict) or not questions:
                            raise ValueError("native_questions_invalid")
                        if set(questions) == {"review_claim"}:
                            if not _native_summary_contract_valid(request):
                                raise ValueError("native_summary_question_invalid")
                            _increment(counters, "native_summary_received")
                            response_stage = "native_summary"
                            response = {"model": JEV_REPORTED_MODEL, "answers": {"review_claim": {"type": "noul", "noul": 0.5}}}
                        else:
                            if not _native_claim_contract_valid(request):
                                raise ValueError("native_claim_questions_invalid")
                            _increment(counters, "native_claim_received")
                            response_stage = "native_claim"
                            answers = {}
                            for question_id, question in questions.items():
                                choices = list(question.get("criteria", {}))
                                if question.get("type") != "choice" or not choices:
                                    raise ValueError("native_claim_question_invalid")
                                selected = choices[0]
                                remainder = 0.1 / max(1, len(choices) - 1)
                                probabilities = {choice: 0.9 if choice == selected else remainder for choice in choices}
                                answers[question_id] = {"type": "choice", "choice": selected,
                                                        "probabilities": probabilities, "confidence": 0.9}
                            response = {"model": JEV_REPORTED_MODEL, "request_id": "loopback-claim", "answers": answers}
                    else:
                        _increment(counters, "handler_errors")
                        self.send_error(404)
                        return
                    if self.server.measure_payload_bytes:
                        _increment_by(
                            counters,
                            f"request_body_bytes_{response_stage}",
                            self._diagnostic_request_body_bytes,
                        )
                        self.server.record_payload(
                            response_stage,
                            "request",
                            self._diagnostic_request_body_bytes,
                            self._diagnostic_request_body_sha256,
                        )
                    delay = self.server.primary_response_delay_seconds if response_stage.startswith("primary_") else 0.0
                    if delay:
                        time.sleep(delay)
                    _write_json_response(self, response, response_stage)
                except Exception:
                    _increment(self.server.counters, "handler_errors")
                    try:
                        self.send_error(400)
                    except OSError:
                        pass
                finally:
                    self.server.handler_finished()

            def log_message(self, *_args):
                return

        return Handler


def _environment() -> dict[str, str]:
    allowed = {"PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL"}
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LLM_API_KEY": FAKE_PROVIDER_KEY,
            "JEV_API_KEY": FAKE_DECISION_KEY,
        }
    )
    return env


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def _write_limits(path: Path) -> bytes:
    """Write the exact normalized limits bytes used by the selected trial."""
    encoded = canonical_json(_limits()) + b"\n"
    path.write_bytes(encoded)
    return encoded


def _bounded_summary_bytes(value: Any) -> tuple[bytes, bool]:
    """Serialize only small diagnostic receipts; never truncate JSON output."""
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) <= MAX_SUMMARY_BYTES:
        return encoded, True
    failure = b'{"status":"FAILED","error_type":"summary_limit_exceeded"}\n'
    return failure, False


_PAIR_STAGE_NAMES = (
    "primary_correctness",
    "primary_security",
    "primary_tests",
    "semantic_adjudication",
    "native_claim",
    "native_summary",
)
_PAIR_IDENTITY_SHA_FIELDS = (
    "runtime_tree_sha256",
    "fixture_suite_sha256",
    "generated_profile_sha256",
    "limits_sha256",
    "snapshot_hash",
    "observer_source_sha256",
)


def _cardinality_stage_counts(candidate_count: int) -> dict[str, int]:
    count = _validate_candidate_cardinality(candidate_count)
    return {
        "primary_correctness_received": 1,
        "primary_security_received": 1,
        "primary_tests_received": 1,
        "semantic_adjudication_received": count,
        "native_claim_received": count,
        "native_summary_received": 1,
        "primary_correctness_response_writes_completed": 1,
        "primary_security_response_writes_completed": 1,
        "primary_tests_response_writes_completed": 1,
        "semantic_adjudication_response_writes_completed": count,
        "native_claim_response_writes_completed": count,
        "native_summary_response_writes_completed": 1,
    }


def _is_sha(value: Any, length: int = 64) -> bool:
    return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is not None


def _valid_pair_input_identity(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if any(not _is_sha(value.get(key)) for key in _PAIR_IDENTITY_SHA_FIELDS):
        return False
    if any(not _is_sha(value.get(key), 40) for key in ("base_sha", "head_sha")):
        return False
    modules = value.get("runtime_module_hashes")
    if (
        value.get("runtime_module_count") != 34
        or not isinstance(modules, dict)
        or len(modules) != 34
        or any(
            not isinstance(name, str)
            or not name.startswith("pr_review_harness/")
            or not name.endswith(".py")
            or not _is_sha(digest)
            for name, digest in modules.items()
        )
    ):
        return False
    return (
        isinstance(value.get("runtime_source_commit"), str)
        and _is_sha(value.get("runtime_source_commit"), 40)
        and _is_sha(value.get("diagnostic_script_sha256"))
        and value.get("installed_source_match") is True
        and isinstance(value.get("snapshot_id"), str)
        and 1 <= len(value["snapshot_id"]) <= 128
        and value.get("observer_id") == observer.OBSERVER_ID
        and value.get("trace_cap_bytes") == observer.TRACE_MAX_BYTES
        and value.get("syscall_scope") == observer.SYSCALL_SCOPE
        and value.get("configured_transport") == "HTTP_LOOPBACK_FAKE"
    )


def _cardinality_arm_state(arm: Any, expected_candidates: int) -> str:
    try:
        expected_candidates = _validate_candidate_cardinality(expected_candidates)
    except ValueError:
        return "INVALID_EXPECTATION"
    if not isinstance(arm, dict) or not _valid_pair_input_identity(arm.get("input_identity")):
        return "INVALID_RECEIPT"
    requested = arm.get("requested_candidate_count")
    if isinstance(requested, bool) or not isinstance(requested, int) or requested != expected_candidates:
        return "CARDINALITY_REQUEST_MISMATCH"
    trace = arm.get("trace_attribution")
    trace_bytes = trace.get("trace_bytes") if isinstance(trace, dict) else None
    if isinstance(trace_bytes, bool) or not isinstance(trace_bytes, int) or trace_bytes < 0:
        return "TRACE_MEASUREMENT_UNKNOWN"
    if trace_bytes > observer.TRACE_MAX_BYTES or arm.get("observer_reason") == "trace_byte_cap_exceeded":
        return "TRACE_CAP_EXCEEDED"
    stage_counts = arm.get("protocol_stage_counts")
    expected_stage_counts = _cardinality_stage_counts(expected_candidates)
    if (
        not isinstance(stage_counts, dict)
        or set(stage_counts) != set(expected_stage_counts)
        or any(
            isinstance(stage_counts.get(name), bool)
            or not isinstance(stage_counts.get(name), int)
            for name in expected_stage_counts
        )
        or stage_counts != expected_stage_counts
    ):
        return "PROTOCOL_STAGE_MISMATCH"
    task_rows = arm.get("primary_task_statuses")
    expected_lenses = ["correctness", "security", "tests"]
    if (
        not isinstance(task_rows, list)
        or [row.get("lens") for row in task_rows if isinstance(row, dict)] != expected_lenses
        or any(not isinstance(row, dict) or row.get("status") != "SUCCEEDED" for row in task_rows)
    ):
        return "PRIMARY_TASKS_INCOMPLETE"
    statuses = arm.get("claim_assessment_statuses")
    if (
        isinstance(arm.get("candidate_count"), bool)
        or not isinstance(arm.get("candidate_count"), int)
        or arm.get("candidate_count") != expected_candidates
        or isinstance(arm.get("claim_assessment_rows"), bool)
        or not isinstance(arm.get("claim_assessment_rows"), int)
        or arm.get("claim_assessment_rows") != expected_candidates
        or not isinstance(statuses, list)
        or statuses != ["COMPLETE"] * expected_candidates
        or arm.get("native_advisory_status") != "RECEIVED"
    ):
        return "CANDIDATE_STAGES_INCOMPLETE"
    if (
        arm.get("cli_invocation_status") != "CLI_COMPLETED"
        or arm.get("cli_exit_code") != 0
        or arm.get("coverage_state") != "COMPLETE"
        or arm.get("protocol_exchange_state") != "SERVER_WRITES_SETTLED"
        or arm.get("fake_server_handlers_settled") is not True
        or arm.get("fake_server_active_handlers_at_snapshot") != 0
        or isinstance(arm.get("http_requests_received"), bool)
        or not isinstance(arm.get("http_requests_received"), int)
        or arm.get("http_requests_received") != 4 + 2 * expected_candidates
        or isinstance(arm.get("server_response_writes_completed"), bool)
        or not isinstance(arm.get("server_response_writes_completed"), int)
        or arm.get("server_response_writes_completed") != 4 + 2 * expected_candidates
        or arm.get("observer_coverage") != "SCOPED_COMPLETE"
        or arm.get("synthetic_protocol_path_state") != "COMPLETE"
        or not isinstance(trace, dict)
        or trace.get("state") != "COMPLETE"
    ):
        return "PROTOCOL_OR_OBSERVER_INCOMPLETE"
    file_paths = trace.get("file_path_attribution")
    if (
        not isinstance(file_paths, dict)
        or file_paths.get("state") != "COMPLETE"
        or file_paths.get("reconciliation") != "MATCH"
    ):
        return "FILE_PATH_ATTRIBUTION_INCOMPLETE"
    syscall_bytes = _bounded_numeric_map(trace.get("bytes_by_syscall"), _TRACE_LINE_LABELS)
    syscall_lines = _bounded_numeric_map(trace.get("lines_by_syscall"), _TRACE_LINE_LABELS)
    if syscall_bytes is None or syscall_lines is None:
        return "TRACE_SYSCALL_ATTRIBUTION_INCOMPLETE"
    line_bytes = trace.get("newline_terminated_line_bytes")
    parsed_lines = trace.get("parsed_line_count")
    residual_bytes = trace.get("unattributed_or_partial_bytes")
    if (
        isinstance(line_bytes, bool)
        or not isinstance(line_bytes, int)
        or isinstance(parsed_lines, bool)
        or not isinstance(parsed_lines, int)
        or isinstance(residual_bytes, bool)
        or not isinstance(residual_bytes, int)
        or sum(syscall_bytes.values()) != line_bytes
        or sum(syscall_lines.values()) != parsed_lines
        or line_bytes + residual_bytes != trace_bytes
        or residual_bytes != 0
    ):
        return "TRACE_SYSCALL_ATTRIBUTION_INCOMPLETE"
    return "COMPLETE"


def _bounded_numeric_map(value: Any, allowed_names: tuple[str, ...]) -> dict[str, int] | None:
    if not isinstance(value, dict) or any(
        name not in allowed_names
        or isinstance(number, bool)
        or not isinstance(number, int)
        or number < 0
        for name, number in value.items()
    ):
        return None
    return {name: value[name] for name in allowed_names if name in value}


def _bounded_nested_numeric_map(
    value: Any, allowed_names: tuple[str, ...], allowed_children: tuple[str, ...]
) -> dict[str, dict[str, int]] | None:
    if not isinstance(value, dict) or any(name not in allowed_names for name in value):
        return None
    projected: dict[str, dict[str, int]] = {}
    for name, child in value.items():
        safe_child = _bounded_numeric_map(child, allowed_children)
        if safe_child is None:
            return None
        projected[name] = safe_child
    return {name: projected[name] for name in allowed_names if name in projected}


def _cardinality_arm_projection(arm: Any, expected_candidates: int | None = None) -> dict[str, Any]:
    if not isinstance(arm, dict):
        return {"state": "INVALID_RECEIPT"}
    trace = arm.get("trace_attribution")
    trace_bytes = trace.get("trace_bytes") if isinstance(trace, dict) else None
    safe_trace = trace_bytes if isinstance(trace_bytes, int) and not isinstance(trace_bytes, bool) else None
    stage_counts = arm.get("protocol_stage_counts")
    safe_stages = (
        {name: stage_counts.get(name) for name in _cardinality_stage_counts(1)}
        if isinstance(stage_counts, dict)
        and all(
            isinstance(stage_counts.get(name), int) and not isinstance(stage_counts.get(name), bool)
            for name in _cardinality_stage_counts(1)
        )
        else None
    )
    request_bytes = arm.get("request_body_bytes_by_stage")
    response_bytes = arm.get("response_body_bytes_by_stage")
    def safe_stage_bytes(value: Any) -> dict[str, int] | None:
        if not isinstance(value, dict) or any(
            name not in _PAIR_STAGE_NAMES
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            for name, size in value.items()
        ):
            return None
        return {name: value[name] for name in _PAIR_STAGE_NAMES if name in value}

    expected = arm.get("requested_candidate_count")
    expected_for_state = expected_candidates
    if expected_for_state is None and isinstance(expected, int) and not isinstance(expected, bool):
        expected_for_state = expected
    computed_state = (
        _cardinality_arm_state(arm, expected_for_state)
        if expected_for_state in {1, 2}
        else "CARDINALITY_REQUEST_MISMATCH"
    )
    trace_projection = trace if isinstance(trace, dict) else {}
    file_paths = trace_projection.get("file_path_attribution")
    path_counts = _bounded_nested_numeric_map(
        file_paths.get("lines_by_syscall_class") if isinstance(file_paths, dict) else None,
        ("openat", "newfstatat"),
        _FILE_PATH_CLASSES,
    )
    path_bytes = _bounded_nested_numeric_map(
        file_paths.get("bytes_by_syscall_class") if isinstance(file_paths, dict) else None,
        ("openat", "newfstatat"),
        _FILE_PATH_CLASSES,
    )
    path_targets_lines = _bounded_numeric_map(
        file_paths.get("target_lines_by_syscall") if isinstance(file_paths, dict) else None,
        ("openat", "newfstatat"),
    )
    path_targets_bytes = _bounded_numeric_map(
        file_paths.get("target_bytes_by_syscall") if isinstance(file_paths, dict) else None,
        ("openat", "newfstatat"),
    )
    file_path_projection = {
        "state": file_paths.get("state") if isinstance(file_paths, dict) and file_paths.get("state") in {"COMPLETE", "PARTIAL"} else "UNKNOWN",
        "basis": "lexical_path_namespace_only_no_symlink_fd_or_pid_cwd_resolution",
        "reconciliation": file_paths.get("reconciliation") if isinstance(file_paths, dict) and file_paths.get("reconciliation") in {"MATCH", "MISMATCH"} else "UNKNOWN",
        "lines_by_syscall_class": path_counts,
        "bytes_by_syscall_class": path_bytes,
        "target_lines_by_syscall": path_targets_lines,
        "target_bytes_by_syscall": path_targets_bytes,
    }
    task_rows = arm.get("primary_task_statuses")
    projected_tasks = None
    if isinstance(task_rows, list):
        projected_tasks = []
        for row in task_rows:
            if not isinstance(row, dict):
                projected_tasks.append({"lens": "UNKNOWN", "status": "UNKNOWN"})
                continue
            lens = row.get("lens")
            status = row.get("status")
            projected_tasks.append({
                "lens": lens if isinstance(lens, str) and lens in {"correctness", "security", "tests"} else "UNKNOWN",
                "status": status if isinstance(status, str) and status in _TASK_STATUSES else "UNKNOWN",
            })
    claim_statuses = arm.get("claim_assessment_statuses")
    projected_claim_statuses = (
        [status if isinstance(status, str) and status in {"COMPLETE", "PARTIAL", "FAILED"} else "UNKNOWN" for status in claim_statuses]
        if isinstance(claim_statuses, list)
        else None
    )
    def bounded_nonnegative(value: Any) -> int | None:
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None

    return {
        "requested_candidate_count": expected if isinstance(expected, int) and not isinstance(expected, bool) and expected in {1, 2} else None,
        "state": computed_state,
        "observer_mode": arm.get("observer_mode") if isinstance(arm.get("observer_mode"), str) else "UNKNOWN",
        "observer_coverage": arm.get("observer_coverage") if isinstance(arm.get("observer_coverage"), str) else "UNKNOWN",
        "trace_bytes": safe_trace,
        "observer_reason": (
            arm.get("observer_reason")
            if arm.get("observer_reason") is None
            or arm.get("observer_reason") in {
                "trace_byte_cap_exceeded", "observer_unavailable", "observer_failed", "observer_timeout"
            }
            else "UNKNOWN"
        ) if isinstance(arm.get("observer_reason"), (str, type(None))) else "UNKNOWN",
        "candidate_count": arm.get("candidate_count") if isinstance(arm.get("candidate_count"), int) and not isinstance(arm.get("candidate_count"), bool) else None,
        "primary_task_statuses": projected_tasks,
        "claim_assessment_statuses": projected_claim_statuses,
        "native_advisory_status": arm.get("native_advisory_status") if isinstance(arm.get("native_advisory_status"), str) and arm.get("native_advisory_status") in {"RECEIVED", "FAILED", "NOT_RUN", "UNKNOWN"} else "UNKNOWN",
        "http_requests_received": arm.get("http_requests_received") if isinstance(arm.get("http_requests_received"), int) and not isinstance(arm.get("http_requests_received"), bool) else None,
        "server_response_writes_completed": arm.get("server_response_writes_completed") if isinstance(arm.get("server_response_writes_completed"), int) and not isinstance(arm.get("server_response_writes_completed"), bool) else None,
        "protocol_stage_counts": safe_stages,
        "request_body_bytes_by_stage": safe_stage_bytes(request_bytes),
        "response_body_bytes_by_stage": safe_stage_bytes(response_bytes),
        "trace_bytes_by_syscall": _bounded_numeric_map(trace_projection.get("bytes_by_syscall"), _TRACE_LINE_LABELS),
        "trace_lines_by_syscall": _bounded_numeric_map(trace_projection.get("lines_by_syscall"), _TRACE_LINE_LABELS),
        "trace_newline_terminated_line_bytes": bounded_nonnegative(trace_projection.get("newline_terminated_line_bytes")),
        "trace_parsed_line_count": bounded_nonnegative(trace_projection.get("parsed_line_count")),
        "trace_unattributed_or_partial_bytes": bounded_nonnegative(trace_projection.get("unattributed_or_partial_bytes")),
        "trace_parse_failure_count": bounded_nonnegative(trace_projection.get("parse_failure_count")),
        "file_path_attribution": file_path_projection,
    }


def _candidate_cardinality_comparison(one: Any, two: Any) -> dict[str, Any]:
    one_projection = _cardinality_arm_projection(one, 1)
    two_projection = _cardinality_arm_projection(two, 2)
    if not isinstance(one, dict) or not isinstance(two, dict):
        return {"state": "INVALID_RECEIPT", "arms": [one_projection, two_projection]}
    one_identity = one.get("input_identity")
    two_identity = two.get("input_identity")
    identity_match = (
        _valid_pair_input_identity(one_identity)
        and _valid_pair_input_identity(two_identity)
        and one_identity == two_identity
    )
    one_state = _cardinality_arm_state(one, 1)
    two_state = _cardinality_arm_state(two, 2)
    one_projection["state"] = one_state
    two_projection["state"] = two_state
    if not identity_match:
        state = "INPUT_IDENTITY_MISMATCH"
    elif one_state == "COMPLETE" and two_state == "COMPLETE":
        state = "COMPLETE"
    else:
        state = "INCOMPLETE"
    a = one_projection.get("trace_bytes")
    b = two_projection.get("trace_bytes")
    trace_delta = b - a if isinstance(a, int) and isinstance(b, int) else None
    request_a = one_projection.get("request_body_bytes_by_stage")
    request_b = two_projection.get("request_body_bytes_by_stage")
    response_a = one_projection.get("response_body_bytes_by_stage")
    response_b = two_projection.get("response_body_bytes_by_stage")
    return {
        "state": state,
        "input_identity_match": identity_match,
        "trace_bytes_delta_two_minus_one": trace_delta,
        "request_body_bytes_delta_two_minus_one": {
            stage: request_b.get(stage, 0) - request_a.get(stage, 0)
            for stage in _PAIR_STAGE_NAMES
        } if isinstance(request_a, dict) and isinstance(request_b, dict) else None,
        "response_body_bytes_delta_two_minus_one": {
            stage: response_b.get(stage, 0) - response_a.get(stage, 0)
            for stage in _PAIR_STAGE_NAMES
        } if isinstance(response_a, dict) and isinstance(response_b, dict) else None,
        "arms": [one_projection, two_projection],
    }


def _cardinality_baseline_allows_second_arm(arms: Any) -> bool:
    if not isinstance(arms, list) or len(arms) != 1 or not isinstance(arms[0], dict):
        return False
    first = arms[0]
    protocol_complete = (
        first.get("synthetic_protocol_path_state") == "COMPLETE"
        and first.get("protocol_exchange_state") == "SERVER_WRITES_SETTLED"
    )
    no_observer = (
        first.get("observer_mode") == "NOT_OBSERVED_PLATFORM_OR_EXPLICIT"
        and isinstance(first.get("trace_attribution"), dict)
        and first["trace_attribution"].get("state") == "UNKNOWN"
    )
    return _cardinality_arm_state(first, 1) == "COMPLETE" or (protocol_complete and no_observer)


def _cardinality_input_identity(
    runtime: dict[str, Any], prepared: Any, case: Any, limits_bytes: bytes
) -> dict[str, Any]:
    fingerprint = runtime.get("source_fingerprint", {})
    source_hashes = fingerprint.get("file_hashes", {}) if isinstance(fingerprint, dict) else {}
    module_hashes = {
        name.removeprefix("src/"): digest
        for name, digest in sorted(source_hashes.items())
        if isinstance(name, str)
        and name.startswith("src/pr_review_harness/")
        and name.endswith(".py")
        and isinstance(digest, str)
    }
    return {
        "runtime_source_commit": fingerprint.get("git_revision") if isinstance(fingerprint, dict) else None,
        "diagnostic_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "runtime_tree_sha256": runtime.get("runtime_tree_sha256"),
        "runtime_module_count": len(module_hashes),
        "runtime_module_hashes": module_hashes,
        "installed_source_match": True,
        "fixture_suite_sha256": prepared.suite_sha256,
        "generated_profile_sha256": hashlib.sha256(prepared.profile_path.read_bytes()).hexdigest(),
        "limits_sha256": hashlib.sha256(limits_bytes).hexdigest(),
        "base_sha": case.base_sha,
        "head_sha": case.head_sha,
        "snapshot_id": case.snapshot.get("snapshot_id"),
        "snapshot_hash": case.snapshot.get("snapshot_hash"),
        "observer_id": observer.OBSERVER_ID,
        "observer_source_sha256": observer._source_sha256(),
        "syscall_scope": observer.SYSCALL_SCOPE,
        "trace_cap_bytes": observer.TRACE_MAX_BYTES,
        "configured_transport": "HTTP_LOOPBACK_FAKE",
    }


def _attributed_observation(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    roots: tuple[tuple[str, str], ...] = (),
) -> tuple[dict, dict]:
    original = observer._parse_line
    attributor = _LineAttributor(original, cwd, roots)
    observer._parse_line = attributor
    try:
        result = observer.observe_cli(command, cwd=cwd, env=env, timeout_seconds=timeout)
    finally:
        observer._parse_line = original
    raw = result.get("observer", {})
    trace_bytes = raw.get("trace_bytes") if isinstance(raw.get("trace_bytes"), int) else None
    if trace_bytes is None or isinstance(trace_bytes, bool) or trace_bytes < attributor.total_line_bytes:
        attribution_state = "INCOMPLETE"
        unattributed = None
    else:
        unattributed = trace_bytes - attributor.total_line_bytes
        attribution_state = "COMPLETE" if unattributed == 0 and raw.get("coverage") == "SCOPED_COMPLETE" else "PARTIAL"
    attribution = {
        "state": attribution_state,
        "trace_bytes": trace_bytes,
        "newline_terminated_line_bytes": attributor.total_line_bytes,
        "unattributed_or_partial_bytes": unattributed,
        "parsed_line_count": sum(attributor.lines_by_label.values()),
        "parse_failure_count": attributor.parse_failures,
        "bytes_by_syscall": dict(sorted(attributor.bytes_by_label.items())),
        "lines_by_syscall": dict(sorted(attributor.lines_by_label.items())),
        "file_path_attribution": _file_path_projection(
            attributor,
            complete_trace=attribution_state == "COMPLETE",
        ),
    }
    return result, attribution


def run(
    cli: Path,
    *,
    workdir: Path | None = None,
    observe: bool = True,
    primary_response_delay_seconds: float = 0.0,
    _prepared: Any | None = None,
    _work_root: Path | None = None,
    _output_name: str = "cli-output",
    _transport: str = "http",
    _ssl_context: ssl.SSLContext | None = None,
    _ssl_cert_file: Path | None = None,
    _environment_override: dict[str, str] | None = None,
) -> dict[str, Any]:
    if (
        isinstance(primary_response_delay_seconds, bool)
        or not isinstance(primary_response_delay_seconds, (int, float))
        or not 0 <= primary_response_delay_seconds <= 15
    ):
        raise ValueError("primary_response_delay_invalid")
    if _transport not in {"http", "https"} or _output_name not in {
        "cli-output", "cli-output-http", "cli-output-https"
    }:
        raise ValueError("transport_arm_configuration_invalid")
    if (_transport == "https") != (_ssl_context is not None):
        raise ValueError("transport_tls_context_mismatch")
    if _ssl_cert_file is not None and (
        _ssl_cert_file.is_symlink() or not _ssl_cert_file.is_file()
        or _ssl_cert_file.stat().st_size > 65_536
    ):
        raise ValueError("transport_trust_input_invalid")
    if _environment_override is not None:
        expected_env = _environment()
        expected_env["SSL_CERT_FILE"] = str(_ssl_cert_file) if _ssl_cert_file is not None else expected_env.get("SSL_CERT_FILE", "")
        if _environment_override != expected_env:
            raise ValueError("transport_environment_not_isolated")
    cli = cli.resolve(strict=True)
    runtime = _runtime_provenance(cli, ROOT)
    fingerprint = runtime.get("source_fingerprint", {})
    source_hashes = fingerprint.get("file_hashes", {}) if isinstance(fingerprint, dict) else {}
    runtime_modules = {
        name.removeprefix("src/"): digest
        for name, digest in sorted(source_hashes.items())
        if isinstance(name, str)
        and name.startswith("src/pr_review_harness/")
        and name.endswith(".py")
        and isinstance(digest, str)
    }
    if not runtime_modules:
        raise RuntimeError("runtime_module_inventory_missing")
    owns_work_root = _work_root is None
    work_root = Path(tempfile.mkdtemp(prefix="selected-control-trace-", dir=workdir)) if owns_work_root else _work_root
    assert work_root is not None
    if owns_work_root:
        os.chmod(work_root, 0o700)
    server = _FakeServer(("127.0.0.1", 0), ssl_context=_ssl_context)
    server.measure_payload_bytes = _environment_override is not None
    server.primary_response_delay_seconds = float(primary_response_delay_seconds)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    try:
        thread.start()
        port = server.server_address[1]
        prepared = _prepared or prepare_suite(
            work_root / "fixture-suite",
            suite_path=ROOT / "examples/injection/fixture-suite.v2.json",
            repo_support_root=ROOT,
            repetitions=1,
            limits=_limits(),
        )
        selected_case_ids = tuple(case.case_id for case in prepared.cases if case.case_id in CASE_IDS)
        if selected_case_ids != CASE_IDS:
            raise RuntimeError("fixed_case_order_mismatch")
        case = next(case for case in prepared.cases if case.case_id == "r1-control")
        plan = plan_review(case.snapshot, prepared.profile, "AUTO")
        expected_lenses = [task.get("lens") for task in plan.get("tasks", [])]
        if len(expected_lenses) != 3 or set(expected_lenses) != {"correctness", "security", "tests"}:
            raise RuntimeError("fixed_control_scope_mismatch")
        profile_path = prepared.profile_path
        limits_path = work_root / "limits.json"
        provider_path = work_root / "provider.json"
        decision_path = work_root / "decision.json"
        output_path = work_root / _output_name
        _write_limits(limits_path)
        provider_path.write_text(
            json.dumps(
                {"kind": "openai_compatible", "provider_id": "operator_openai_compatible",
                 "base_url": f"{_transport}://127.0.0.1:{port}/v1", "model": FAKE_MODEL,
                 "api_key_env": "LLM_API_KEY"},
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        decision_path.write_text(
            json.dumps(
                {"kind": "typesafe", "endpoint": f"{_transport}://127.0.0.1:{port}/v1/systemone",
                 "model": JEV_ALIAS, "api_key_env": "JEV_API_KEY"},
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        os.chmod(limits_path, 0o600)
        os.chmod(provider_path, 0o600)
        os.chmod(decision_path, 0o600)
        command = _command(
            cli, case, profile_path, limits_path, output_path, provider_path, decision_path, dry_run=False
        )
        child_env = _environment_override if _environment_override is not None else _environment()
        if observe and sys.platform.startswith("linux"):
            observed, attribution = _attributed_observation(
                command,
                cwd=work_root,
                env=child_env,
                timeout=300,
                roots=_path_roots(cli=cli, work_root=work_root, repo_support=ROOT),
            )
            observer_mode = "LINUX_STRACE"
        else:
            observed = invoke_cli_bounded(command, cwd=work_root, env=child_env, timeout_seconds=300)
            attribution = {
                "state": "UNKNOWN",
                "trace_bytes": None,
                "newline_terminated_line_bytes": None,
                "unattributed_or_partial_bytes": None,
                "parsed_line_count": None,
                "parse_failure_count": None,
                "bytes_by_syscall": {},
                "lines_by_syscall": {},
                "file_path_attribution": {
                    "state": "UNKNOWN",
                    "basis": "lexical_path_namespace_only_no_symlink_fd_or_pid_cwd_resolution",
                    "path_argument_visibility": {
                        "openat": "path_visible_and_lexically_classified",
                        "newfstatat": "raw_hex_arguments_path_unavailable",
                    },
                    "line_bytes": "decoded_utf8_line_bytes_plus_observed_newline_byte",
                    "lines_by_syscall_class": {},
                    "bytes_by_syscall_class": {},
                    "target_lines_by_syscall": {},
                    "target_bytes_by_syscall": {},
                    "reconciliation": "UNKNOWN",
                },
            }
            observer_mode = "NOT_OBSERVED_PLATFORM_OR_EXPLICIT"
        raw_observer = observed.get("observer", {})
        cli_result = observed.get("cli_result")
        invocation = observed.get("invocation")
        invocation_status = (
            invocation.get("run_status") if isinstance(invocation, dict) else observed.get("run_status")
        )
        invocation_exit_code = invocation.get("exit_code") if isinstance(invocation, dict) else observed.get("exit_code")
        handlers_settled, active_handlers_at_snapshot = server.wait_until_idle(2.0)
        http_requests_received = server.counters.get("http_requests_received", 0)
        response_writes_completed = server.counters.get("server_response_writes_completed", 0)
        handler_errors = server.counters.get("handler_errors", 0)
        if not http_requests_received and not handler_errors:
            protocol_exchange_state = "NOT_STARTED"
        elif handlers_settled and http_requests_received == response_writes_completed and handler_errors == 0:
            protocol_exchange_state = "SERVER_WRITES_SETTLED"
        else:
            protocol_exchange_state = "INCOMPLETE"
        result_file = output_path / "r1-control.json"
        durable = None
        if result_file.exists() and result_file.stat().st_size <= 2_000_000:
            try:
                durable = json.loads(result_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                durable = None
        claim_rows = durable.get("claim_assessments") if isinstance(durable, dict) else None
        findings = durable.get("findings") if isinstance(durable, dict) else None
        candidate_count = len(findings) if isinstance(findings, list) else None
        task_status_projection, unexpected_task_result_count = _project_task_statuses(durable, plan["tasks"])
        claim_statuses = (
            [
                row.get("status")
                if isinstance(row, dict) and row.get("status") in {"COMPLETE", "PARTIAL", "FAILED"}
                else "UNKNOWN"
                for row in claim_rows
            ]
            if isinstance(claim_rows, list)
            else None
        )
        advisory = durable.get("advisory_assessment") if isinstance(durable, dict) else None
        advisory_status = (
            advisory.get("status")
            if isinstance(advisory, dict) and advisory.get("status") in {"RECEIVED", "FAILED", "NOT_RUN", "UNKNOWN"}
            else "UNKNOWN"
        )
        stage_counts = {
            name: server.counters.get(name, 0)
            for name in (
                "primary_correctness_received", "primary_security_received", "primary_tests_received",
                "semantic_adjudication_received", "native_claim_received", "native_summary_received",
                "primary_correctness_response_writes_completed", "primary_security_response_writes_completed",
                "primary_tests_response_writes_completed", "semantic_adjudication_response_writes_completed",
                "native_claim_response_writes_completed", "native_summary_response_writes_completed",
            )
        }
        expected_stage_counts = {name: 1 for name in stage_counts}
        task_success = bool(task_status_projection) and all(row["status"] == "SUCCEEDED" for row in task_status_projection)
        synthetic_protocol_path_state = (
            "COMPLETE"
            if protocol_exchange_state == "SERVER_WRITES_SETTLED"
            and stage_counts == expected_stage_counts
            and task_success
            and isinstance(durable, dict)
            and durable.get("coverage_state") == "COMPLETE"
            and claim_statuses == ["COMPLETE"]
            and advisory_status == "RECEIVED"
            and candidate_count == 1
            else "INCOMPLETE"
        )
        result = {
            "contract_version": DIAGNOSTIC_CONTRACT_VERSION,
            "fixture_case": "r1-control",
            "runtime_tree_sha256": runtime.get("runtime_tree_sha256"),
            "installed_source_match": True,
            "runtime_source_commit": fingerprint.get("git_revision") if isinstance(fingerprint, dict) else None,
            "runtime_source_tree_dirty": fingerprint.get("working_tree_dirty") if isinstance(fingerprint, dict) else None,
            "runtime_module_count": len(runtime_modules),
            "runtime_module_hashes": runtime_modules,
            "diagnostic_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "fixture_suite_sha256": hashlib.sha256((ROOT / "examples/injection/fixture-suite.v2.json").read_bytes()).hexdigest(),
            "generated_profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
            "limits_sha256": hashlib.sha256(limits_path.read_bytes()).hexdigest(),
            "base_sha": case.base_sha,
            "head_sha": case.head_sha,
            "snapshot_id": case.snapshot.get("snapshot_id"),
            "snapshot_hash": case.snapshot.get("snapshot_hash"),
            "task_lenses": expected_lenses,
            "planned_primary_tasks": len(expected_lenses),
            "observer_id": raw_observer.get("observer_id"),
            "observer_mode": observer_mode,
            "observer_source_sha256": raw_observer.get("source_sha256"),
            "strace_version": raw_observer.get("strace_version"),
            "strace_executable_sha256": raw_observer.get("strace_executable_sha256"),
            "syscall_scope": observer.SYSCALL_SCOPE,
            "trace_cap_bytes": observer.TRACE_MAX_BYTES,
            "observer_coverage": raw_observer.get("coverage", "UNKNOWN"),
            "observer_reason": raw_observer.get("reason"),
            "trace_attribution": attribution,
            "fake_http_counters": dict(sorted(server.counters.items())),
            "http_requests_received": http_requests_received,
            "server_response_writes_completed": response_writes_completed,
            "protocol_exchange_state": protocol_exchange_state,
            "protocol_stage_counts": stage_counts,
            "synthetic_protocol_path_state": synthetic_protocol_path_state,
            "unexpected_task_result_count": unexpected_task_result_count,
            "cli_invocation_status": invocation_status,
            "cli_exit_code": invocation_exit_code,
            "cli_result_present": isinstance(cli_result, dict),
            "primary_fake_response_delay_seconds": float(primary_response_delay_seconds),
            "native_fake_response_delay_seconds": 0.0,
            "fake_server_handlers_settled": handlers_settled,
            "fake_server_active_handlers_at_snapshot": active_handlers_at_snapshot,
            "disposition": durable.get("disposition") if isinstance(durable, dict) else None,
            "coverage_state": durable.get("coverage_state") if isinstance(durable, dict) else None,
            "primary_task_statuses": task_status_projection,
            "candidate_count": candidate_count,
            "claim_assessment_rows": len(claim_rows) if isinstance(claim_rows, list) else None,
            "claim_assessment_statuses": claim_statuses,
            "native_advisory_status": advisory_status,
            "configured_transport": "HTTPS_LOOPBACK_FAKE" if _transport == "https" else "HTTP_LOOPBACK_FAKE",
            "provider_adapter_defaults_preserved": True,
            "target_execution_requested": False,
            "reviewed_code_execution_observation": "UNKNOWN",
            "quality_or_https_trace_parity_claim": False,
        }
        if _environment_override is not None:
            result["transport_payload_hashes"] = {
                stage: dict(sorted(values.items()))
                for stage, values in sorted(server.payload_hashes.items())
            }
            provider_bytes = provider_path.read_bytes()
            decision_bytes = decision_path.read_bytes()
            provider_config = json.loads(provider_bytes)
            decision_config = json.loads(decision_bytes)
            normalized_provider = {
                **provider_config,
                "base_url": _normalized_loopback_endpoint(provider_config.get("base_url")),
            }
            normalized_decision = {
                **decision_config,
                "endpoint": _normalized_loopback_endpoint(decision_config.get("endpoint")),
            }
            normalized_config = {"provider": normalized_provider, "decision": normalized_decision}
            result["provider_config_sha256"] = hashlib.sha256(provider_bytes).hexdigest()
            result["decision_config_sha256"] = hashlib.sha256(decision_bytes).hexdigest()
            result["normalized_transport_config_sha256"] = hashlib.sha256(canonical_json(normalized_config)).hexdigest()
            result["run_id"] = case.case_id
            result["event_mode"] = "LOCAL_EXPLICIT_BASE_HEAD_NO_GITHUB_EVENT"
            result["event_identity"] = None
            result["task_ids"] = [task.get("task_id") for task in plan.get("tasks", [])]
        return result
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if owns_work_root:
            # These inputs and the private durable result contain only synthetic data.
            shutil.rmtree(work_root, ignore_errors=True)


def _write_loopback_certificate(work_root: Path) -> tuple[Path, Path, str]:
    """Create a short-lived self-signed loopback CA/server certificate without shell use."""
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("transport_tls_openssl_unavailable")
    key_path = work_root / "loopback-private.key"
    cert_path = work_root / "loopback-ca.pem"
    try:
        subprocess.run(
            [
                openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", str(key_path), "-out", str(cert_path), "-subj", "/CN=127.0.0.1",
                "-addext", "subjectAltName=IP:127.0.0.1",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                "-addext", "extendedKeyUsage=serverAuth",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=True,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(work_root)},
        )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("transport_tls_certificate_generation_failed") from None
    for path in (key_path, cert_path):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65_536:
            raise RuntimeError("transport_tls_certificate_output_invalid")
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o600)
    return cert_path, key_path, hashlib.sha256(cert_path.read_bytes()).hexdigest()


def _normalized_loopback_endpoint(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("transport_endpoint_invalid")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname != "127.0.0.1"
        or parsed.username or parsed.password or parsed.fragment
        or parsed.port is None
    ):
        raise ValueError("transport_endpoint_invalid")
    return urllib.parse.urlunsplit(("transport", "loopback", parsed.path, parsed.query, ""))


def _transport_server_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context


def _transport_pair_complete(arm: Any) -> bool:
    if not isinstance(arm, dict):
        return False
    trace = arm.get("trace_attribution")
    trace_bytes = trace.get("trace_bytes") if isinstance(trace, dict) else None
    expected_stages = {
        name: 1
        for name in (
            "primary_correctness_received", "primary_security_received", "primary_tests_received",
            "semantic_adjudication_received", "native_claim_received", "native_summary_received",
            "primary_correctness_response_writes_completed", "primary_security_response_writes_completed",
            "primary_tests_response_writes_completed", "semantic_adjudication_response_writes_completed",
            "native_claim_response_writes_completed", "native_summary_response_writes_completed",
        )
    }
    return (
        arm.get("observer_mode") == "LINUX_STRACE"
        and arm.get("observer_coverage") == "SCOPED_COMPLETE"
        and arm.get("observer_reason") is None
        and isinstance(trace, dict)
        and trace.get("state") == "COMPLETE"
        and isinstance(trace_bytes, int)
        and not isinstance(trace_bytes, bool)
        and 0 <= trace_bytes < observer.TRACE_MAX_BYTES
        and arm.get("protocol_exchange_state") == "SERVER_WRITES_SETTLED"
        and arm.get("protocol_stage_counts") == expected_stages
        and arm.get("http_requests_received") == 6
        and arm.get("server_response_writes_completed") == 6
        and arm.get("fake_server_handlers_settled") is True
        and arm.get("fake_server_active_handlers_at_snapshot") == 0
        and arm.get("synthetic_protocol_path_state") == "COMPLETE"
        and arm.get("coverage_state") == "COMPLETE"
        and arm.get("claim_assessment_statuses") == ["COMPLETE"]
        and arm.get("native_advisory_status") == "RECEIVED"
        and isinstance(arm.get("primary_task_statuses"), list)
        and len(arm["primary_task_statuses"]) == 3
        and all(
            isinstance(task, dict) and task.get("status") == "SUCCEEDED"
            for task in arm["primary_task_statuses"]
        )
        and arm.get("cli_invocation_status") == "CLI_COMPLETED"
        and arm.get("cli_exit_code") == 0
        and arm.get("cli_result_present") is True
        and arm.get("candidate_count") == 1
        and arm.get("unexpected_task_result_count") == 0
        and _transport_payload_identity_complete(arm.get("transport_payload_hashes"))
    )


def _transport_payload_identity_complete(value: Any) -> bool:
    stages = {
        "primary_correctness", "primary_security", "primary_tests",
        "semantic_adjudication", "native_claim", "native_summary",
    }
    if not isinstance(value, dict) or set(value) != stages:
        return False
    for row in value.values():
        if not isinstance(row, dict) or set(row) != {
            "request_bytes", "request_sha256", "response_bytes", "response_sha256"
        }:
            return False
        for size_key, cap in (("request_bytes", MAX_HTTP_REQUEST_BYTES), ("response_bytes", MAX_HTTP_RESPONSE_BYTES)):
            size = row.get(size_key)
            if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= cap:
                return False
        for hash_key in ("request_sha256", "response_sha256"):
            digest = row.get(hash_key)
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                return False
    return True


def _transport_arm_projection(arm: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "configured_transport", "trace_attribution", "observer_mode", "observer_coverage", "observer_reason",
        "protocol_exchange_state", "protocol_stage_counts", "http_requests_received",
        "server_response_writes_completed", "fake_server_handlers_settled",
        "fake_server_active_handlers_at_snapshot", "synthetic_protocol_path_state", "primary_task_statuses",
        "cli_invocation_status", "cli_exit_code", "cli_result_present", "coverage_state",
        "claim_assessment_statuses", "native_advisory_status", "candidate_count", "unexpected_task_result_count",
        "transport_payload_hashes", "provider_config_sha256", "decision_config_sha256",
        "normalized_transport_config_sha256",
        "run_id", "event_mode", "event_identity", "task_ids", "snapshot_id", "snapshot_hash",
    )
    projected = {key: arm.get(key) for key in fields}
    # Keep transport receipts on the validator's closed three-field contract.
    # The shared projection retains chunk accounting for other consumers, but
    # those internal counters are not part of this receipt schema.
    task_rows = projected.get("primary_task_statuses")
    if isinstance(task_rows, list):
        projected["primary_task_statuses"] = [
            {key: value for key, value in row.items() if key in {"task_id", "lens", "status"}}
            if isinstance(row, dict) else row
            for row in task_rows
        ]
    return projected


def _diagnostic_checkout_identity() -> dict[str, Any]:
    try:
        head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=True,
        ).stdout.decode("ascii").strip()
        dirty_result = subprocess.run(
            ["git", "-C", str(ROOT), "diff", "--quiet", "HEAD", "--", "scripts/selected_control_trace_attribution.py"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("diagnostic_source_identity_unavailable") from None
    if not re.fullmatch(r"[0-9a-f]{40}", head) or dirty_result.returncode not in {0, 1}:
        raise RuntimeError("diagnostic_source_identity_invalid")
    return {
        "diagnostic_head_sha": head,
        "diagnostic_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "diagnostic_script_differs_from_head": dirty_result.returncode == 1,
    }


def run_transport_pair(
    cli: Path,
    *,
    workdir: Path | None = None,
    observe: bool = True,
) -> dict[str, Any]:
    """Run one fixed HTTP control; try one TLS arm only after complete HTTP evidence."""
    started = time.monotonic()
    deadline = started + TRANSPORT_PAIR_DEADLINE_SECONDS
    if not observe or not sys.platform.startswith("linux"):
        raise ValueError("transport_pair_requires_linux_observer")
    cli = cli.resolve(strict=True)
    runtime = _runtime_provenance(cli, ROOT)
    fingerprint = runtime.get("source_fingerprint", {})
    source_hashes = fingerprint.get("file_hashes", {}) if isinstance(fingerprint, dict) else {}
    module_hashes = {
        name.removeprefix("src/"): digest
        for name, digest in sorted(source_hashes.items())
        if isinstance(name, str) and name.startswith("src/pr_review_harness/")
        and name.endswith(".py") and isinstance(digest, str)
    }
    if len(module_hashes) != 34:
        raise RuntimeError("runtime_module_inventory_invalid")
    checkout_identity = _diagnostic_checkout_identity()
    work_root = Path(tempfile.mkdtemp(prefix="selected-control-transport-", dir=workdir))
    os.chmod(work_root, 0o700)
    try:
        prepared = prepare_suite(
            work_root / "fixture-suite",
            suite_path=ROOT / "examples/injection/fixture-suite.v2.json",
            repo_support_root=ROOT,
            repetitions=1,
            limits=_limits(),
        )
        selected_case_ids = tuple(case.case_id for case in prepared.cases if case.case_id in CASE_IDS)
        if selected_case_ids != CASE_IDS:
            raise RuntimeError("fixed_case_order_mismatch")
        case = next(case for case in prepared.cases if case.case_id == "r1-control")
        plan = plan_review(case.snapshot, prepared.profile, "AUTO")
        tasks = plan.get("tasks") if isinstance(plan, dict) else None
        lenses = [task.get("lens") for task in tasks] if isinstance(tasks, list) else []
        if len(lenses) != 3 or set(lenses) != {"correctness", "security", "tests"}:
            raise RuntimeError("fixed_control_scope_mismatch")
        cert_path, key_path, cert_sha256 = _write_loopback_certificate(work_root)
        child_env = _environment()
        child_env["SSL_CERT_FILE"] = str(cert_path)
        common = {
            "workdir": workdir,
            "observe": True,
            "primary_response_delay_seconds": 0.0,
            "_prepared": prepared,
            "_work_root": work_root,
            "_ssl_cert_file": cert_path,
            "_environment_override": child_env,
        }
        if deadline - time.monotonic() <= 600 + observer.CLEANUP_GRACE_SECONDS:
            return {
                "contract_version": "selected-control-transport-pair.v1",
                "pair_state": "INCOMPLETE",
                "reason": "PAIR_SETUP_EXHAUSTED_ARM_BUDGET",
                **checkout_identity,
                "runtime_source_commit": fingerprint.get("git_revision") if isinstance(fingerprint, dict) else None,
                "runtime_tree_sha256": runtime.get("runtime_tree_sha256"),
                "runtime_module_count": len(module_hashes),
                "fixture_suite_sha256": prepared.suite_sha256,
                "generated_profile_sha256": hashlib.sha256(prepared.profile_path.read_bytes()).hexdigest(),
                "run_id": case.case_id,
                "event_mode": "LOCAL_EXPLICIT_BASE_HEAD_NO_GITHUB_EVENT",
                "snapshot_id": case.snapshot.get("snapshot_id"),
                "snapshot_hash": case.snapshot.get("snapshot_hash"),
                "task_ids": [task.get("task_id") for task in tasks],
                "arms": [
                    {"configured_transport": "HTTP_LOOPBACK_FAKE", "state": "NOT_RUN_PAIR_DEADLINE"},
                    {"configured_transport": "HTTPS_LOOPBACK_FAKE", "state": "NOT_RUN_PAIR_DEADLINE"},
                ],
                "tls_private_material_in_receipt": False,
                "external_provider_dispatch_requested": False,
                "target_execution_requested": False,
                "quality_or_https_trace_parity_claim": False,
            }
        http_arm = run(
            cli,
            _output_name="cli-output-http",
            _transport="http",
            _ssl_context=None,
            **common,
        )
        arms = [{"state": "COMPLETE" if _transport_pair_complete(http_arm) else "INCOMPLETE",
                 **_transport_arm_projection(http_arm)}]
        if not _transport_pair_complete(http_arm):
            arms.append({"configured_transport": "HTTPS_LOOPBACK_FAKE", "state": "NOT_RUN_HTTP_BASELINE_INCOMPLETE"})
            return {
                "contract_version": "selected-control-transport-pair.v1",
                "pair_state": "INCOMPLETE",
                "reason": "HTTP_BASELINE_INCOMPLETE_TLS_NOT_RUN",
                **checkout_identity,
                "runtime_source_commit": fingerprint.get("git_revision") if isinstance(fingerprint, dict) else None,
                "runtime_tree_sha256": runtime.get("runtime_tree_sha256"),
                "runtime_module_count": len(module_hashes),
                "runtime_module_hashes": module_hashes,
                "fixture_suite_sha256": prepared.suite_sha256,
                "generated_profile_sha256": hashlib.sha256(prepared.profile_path.read_bytes()).hexdigest(),
                "base_sha": case.base_sha,
                "head_sha": case.head_sha,
                "run_id": case.case_id,
                "event_mode": "LOCAL_EXPLICIT_BASE_HEAD_NO_GITHUB_EVENT",
                "snapshot_id": case.snapshot.get("snapshot_id"),
                "snapshot_hash": case.snapshot.get("snapshot_hash"),
                "task_ids": [task.get("task_id") for task in tasks],
                "observer_id": observer.OBSERVER_ID,
                "syscall_scope": observer.SYSCALL_SCOPE,
                "trace_cap_bytes": observer.TRACE_MAX_BYTES,
                "arms": arms,
                "tls_private_material_in_receipt": False,
                "external_provider_dispatch_requested": False,
                "target_execution_requested": False,
                "quality_or_https_trace_parity_claim": False,
                "live_failure_cause_claim": False,
            }
        remaining = deadline - time.monotonic()
        if remaining <= 300 + observer.CLEANUP_GRACE_SECONDS:
            arms.append({"configured_transport": "HTTPS_LOOPBACK_FAKE", "state": "NOT_RUN_PAIR_DEADLINE"})
            pair_state = "INCOMPLETE"
            reason = "PAIR_DEADLINE_EXHAUSTED"
            https_arm = None
        else:
            tls_context = _transport_server_context(cert_path, key_path)
            https_arm = run(
                cli,
                _output_name="cli-output-https",
                _transport="https",
                _ssl_context=tls_context,
                **common,
            )
            arms.append({"state": "COMPLETE" if _transport_pair_complete(https_arm) else "INCOMPLETE",
                         **_transport_arm_projection(https_arm)})
            shared_fields = (
                "runtime_tree_sha256", "runtime_source_commit", "runtime_source_tree_dirty",
                "runtime_module_hashes", "diagnostic_script_sha256", "fixture_suite_sha256",
                "generated_profile_sha256", "limits_sha256", "base_sha", "head_sha",
                "snapshot_id", "snapshot_hash", "task_lenses", "run_id", "event_mode",
                "event_identity", "task_ids", "primary_task_statuses", "observer_id",
                "observer_source_sha256", "strace_version", "strace_executable_sha256",
                "syscall_scope", "trace_cap_bytes",
            )
            input_identity_match = all(http_arm.get(key) == https_arm.get(key) for key in shared_fields)
            body_identity_match = http_arm.get("transport_payload_hashes") == https_arm.get("transport_payload_hashes")
            normalized_config_match = http_arm.get("normalized_transport_config_sha256") == https_arm.get("normalized_transport_config_sha256")
            both_complete = _transport_pair_complete(https_arm)
            pair_state = "COMPLETE" if both_complete and input_identity_match and body_identity_match and normalized_config_match else "INCOMPLETE"
            reason = None if pair_state == "COMPLETE" else "TLS_ARM_OR_IDENTITY_INCOMPLETE"
        comparison = None
        if https_arm is not None and pair_state == "COMPLETE":
            http_trace = http_arm.get("trace_attribution", {})
            tls_trace = https_arm.get("trace_attribution", {})
            http_syscall_bytes = http_trace.get("bytes_by_syscall", {})
            tls_syscall_bytes = tls_trace.get("bytes_by_syscall", {})
            comparison = {
                "input_identity_match": input_identity_match,
                "request_response_body_hashes_match": body_identity_match,
                "normalized_endpoint_config_match": normalized_config_match,
                "http_trace_bytes": http_trace.get("trace_bytes"),
                "https_trace_bytes": tls_trace.get("trace_bytes"),
                "trace_bytes_delta_https_minus_http": tls_trace.get("trace_bytes", 0) - http_trace.get("trace_bytes", 0),
                "trace_bytes_by_syscall_delta_https_minus_http": {
                    label: tls_syscall_bytes.get(label, 0) - http_syscall_bytes.get(label, 0)
                    for label in sorted(set(http_syscall_bytes) | set(tls_syscall_bytes))
                },
            }
        return {
            "contract_version": "selected-control-transport-pair.v1",
            "pair_state": pair_state,
            "reason": reason,
            **checkout_identity,
            "runtime_source_commit": fingerprint.get("git_revision") if isinstance(fingerprint, dict) else None,
            "runtime_tree_sha256": runtime.get("runtime_tree_sha256"),
            "runtime_module_count": len(module_hashes),
            "runtime_module_hashes": module_hashes,
            "fixture_suite_sha256": prepared.suite_sha256,
            "generated_profile_sha256": hashlib.sha256(prepared.profile_path.read_bytes()).hexdigest(),
            "base_sha": case.base_sha,
            "head_sha": case.head_sha,
            "run_id": case.case_id,
            "event_mode": "LOCAL_EXPLICIT_BASE_HEAD_NO_GITHUB_EVENT",
            "snapshot_id": case.snapshot.get("snapshot_id"),
            "snapshot_hash": case.snapshot.get("snapshot_hash"),
            "task_ids": [task.get("task_id") for task in tasks],
            "task_lenses": lenses,
            "observer_id": observer.OBSERVER_ID,
            "observer_source_sha256": observer._source_sha256(),
            "syscall_scope": observer.SYSCALL_SCOPE,
            "trace_cap_bytes": observer.TRACE_MAX_BYTES,
            "limits": {key: _limits().get(key) for key in (
                "max_provider_calls", "max_retries_per_task", "max_input_bytes_per_task",
                "max_output_bytes_per_task", "deadline_seconds",
            )} | {"max_claim_assessments_per_run": MAX_CLAIM_ASSESSMENTS_PER_RUN},
            "observer_timeout_seconds_per_arm": 300,
            "pair_deadline_seconds": TRANSPORT_PAIR_DEADLINE_SECONDS,
            "primary_response_delay_seconds": 0,
            "tls_ca_sha256": cert_sha256,
            "tls_private_material_in_receipt": False,
            "tls_verification_disabled": False,
            "arms": arms,
            "comparison": comparison,
            "external_provider_dispatch_requested": False,
            "target_execution_requested": False,
            "quality_or_https_trace_parity_claim": False,
            "live_failure_cause_claim": False,
        }
    finally:
        shutil.rmtree(work_root, ignore_errors=True)


def run_candidate_cardinality_pair(
    cli: Path,
    *,
    workdir: Path | None = None,
    observe: bool = True,
) -> dict[str, Any]:
    """Compare one versus two scripted findings on one prepared snapshot and fake server."""
    pair_started = time.monotonic()
    pair_deadline = pair_started + 660.0
    cli = cli.resolve(strict=True)
    runtime = _runtime_provenance(cli, ROOT)
    fingerprint = runtime.get("source_fingerprint", {})
    source_hashes = fingerprint.get("file_hashes", {}) if isinstance(fingerprint, dict) else {}
    runtime_modules = {
        name.removeprefix("src/"): digest
        for name, digest in sorted(source_hashes.items())
        if isinstance(name, str)
        and name.startswith("src/pr_review_harness/")
        and name.endswith(".py")
        and isinstance(digest, str)
    }
    if len(runtime_modules) != 34:
        raise RuntimeError("runtime_module_inventory_invalid")
    work_root = Path(tempfile.mkdtemp(prefix="selected-control-cardinality-", dir=workdir))
    os.chmod(work_root, 0o700)
    server = _FakeServer(("127.0.0.1", 0))
    server.measure_payload_bytes = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    try:
        thread.start()
        prepared = prepare_suite(
            work_root / "fixture-suite",
            suite_path=ROOT / "examples/injection/fixture-suite.v2.json",
            repo_support_root=ROOT,
            repetitions=1,
            limits=_limits(),
        )
        selected_case_ids = tuple(case.case_id for case in prepared.cases if case.case_id in CASE_IDS)
        if selected_case_ids != CASE_IDS:
            raise RuntimeError("fixed_case_order_mismatch")
        case = next(case for case in prepared.cases if case.case_id == "r1-control")
        plan = plan_review(case.snapshot, prepared.profile, "AUTO")
        tasks = plan.get("tasks") if isinstance(plan, dict) else None
        task_lenses = [task.get("lens") for task in tasks] if isinstance(tasks, list) else []
        if len(task_lenses) != 3 or set(task_lenses) != {"correctness", "security", "tests"}:
            raise RuntimeError("fixed_control_scope_mismatch")
        profile_path = prepared.profile_path
        limits_path = work_root / "limits.json"
        provider_path = work_root / "provider.json"
        decision_path = work_root / "decision.json"
        limits_bytes = _write_limits(limits_path)
        port = server.server_address[1]
        provider_path.write_text(
            json.dumps(
                {
                    "kind": "openai_compatible",
                    "provider_id": "operator_openai_compatible",
                    "base_url": f"http://127.0.0.1:{port}/v1",
                    "model": FAKE_MODEL,
                    "api_key_env": "LLM_API_KEY",
                },
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        decision_path.write_text(
            json.dumps(
                {
                    "kind": "typesafe",
                    "endpoint": f"http://127.0.0.1:{port}/v1/systemone",
                    "model": JEV_ALIAS,
                    "api_key_env": "JEV_API_KEY",
                },
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        for path in (limits_path, provider_path, decision_path):
            os.chmod(path, 0o600)
        input_identity = _cardinality_input_identity(runtime, prepared, case, limits_bytes)
        if not _valid_pair_input_identity(input_identity):
            raise RuntimeError("cardinality_input_identity_invalid")
        env = _environment()
        arms: list[dict[str, Any]] = []
        for cardinality in (1, 2):
            remaining = pair_deadline - time.monotonic()
            if remaining <= observer.CLEANUP_GRACE_SECONDS + 1:
                arms.append(
                    {
                        "requested_candidate_count": cardinality,
                        "input_identity": input_identity,
                        "arm_state": "DEADLINE_NOT_STARTED",
                        "observer_reason": "pair_deadline_exhausted",
                    }
                )
                continue
            if cardinality == 2:
                if not _cardinality_baseline_allows_second_arm(arms):
                    arms.append(
                        {
                            "requested_candidate_count": cardinality,
                            "input_identity": input_identity,
                            "arm_state": "NOT_RUN_BASELINE_INCOMPLETE",
                            "observer_reason": "one_candidate_baseline_incomplete",
                        }
                    )
                    break
            server.candidate_cardinality = cardinality
            server.counters = _CallCounters()
            output_path = work_root / "cli-output" / f"candidate-{cardinality}"
            command = _command(
                cli, case, profile_path, limits_path, output_path, provider_path, decision_path, dry_run=False
            )
            timeout = min(300.0, remaining - observer.CLEANUP_GRACE_SECONDS)
            if observe and sys.platform.startswith("linux"):
                observed, attribution = _attributed_observation(
                    command,
                    cwd=work_root,
                    env=env,
                    timeout=timeout,
                    roots=_path_roots(cli=cli, work_root=work_root, repo_support=ROOT),
                )
                observer_mode = "LINUX_STRACE"
            else:
                observed = invoke_cli_bounded(command, cwd=work_root, env=env, timeout_seconds=timeout)
                attribution = {
                    "state": "UNKNOWN",
                    "trace_bytes": None,
                    "unattributed_or_partial_bytes": None,
                }
                observer_mode = "NOT_OBSERVED_PLATFORM_OR_EXPLICIT"
            handlers_settled, active_handlers = server.wait_until_idle(
                min(2.0, max(0.0, pair_deadline - time.monotonic()))
            )
            counters = server.counters
            invocation = observed.get("invocation") if isinstance(observed, dict) else None
            cli_result = observed.get("cli_result") if isinstance(observed, dict) else None
            cli_status = (
                invocation.get("run_status") if isinstance(invocation, dict)
                else observed.get("run_status") if isinstance(observed, dict)
                else "UNKNOWN"
            )
            exit_code = (
                invocation.get("exit_code") if isinstance(invocation, dict)
                else observed.get("exit_code") if isinstance(observed, dict)
                else None
            )
            raw_observer = observed.get("observer") if isinstance(observed, dict) else None
            raw_observer = raw_observer if isinstance(raw_observer, dict) else {}
            result_file = output_path / "r1-control.json"
            durable = None
            try:
                metadata = result_file.lstat()
                if result_file.is_file() and not result_file.is_symlink() and metadata.st_size <= 2_000_000:
                    durable = json.loads(result_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                durable = None
            task_rows, unexpected = _project_task_statuses(durable, tasks)
            claim_rows = durable.get("claim_assessments") if isinstance(durable, dict) else None
            claim_statuses = (
                [
                    row.get("status")
                    if isinstance(row, dict) and row.get("status") in {"COMPLETE", "PARTIAL", "FAILED"}
                    else "UNKNOWN"
                    for row in claim_rows
                ]
                if isinstance(claim_rows, list)
                else None
            )
            findings = durable.get("findings") if isinstance(durable, dict) else None
            candidate_count = len(findings) if isinstance(findings, list) else None
            advisory = durable.get("advisory_assessment") if isinstance(durable, dict) else None
            advisory_status = (
                advisory.get("status")
                if isinstance(advisory, dict)
                and advisory.get("status") in {"RECEIVED", "FAILED", "NOT_RUN", "UNKNOWN"}
                else "UNKNOWN"
            )
            stage_counts = {
                name: counters.get(name, 0)
                for name in (
                    "primary_correctness_received", "primary_security_received", "primary_tests_received",
                    "semantic_adjudication_received", "native_claim_received", "native_summary_received",
                    "primary_correctness_response_writes_completed", "primary_security_response_writes_completed",
                    "primary_tests_response_writes_completed", "semantic_adjudication_response_writes_completed",
                    "native_claim_response_writes_completed", "native_summary_response_writes_completed",
                )
            }
            request_bytes = {
                stage: counters.get(f"request_body_bytes_{stage}", 0) for stage in _PAIR_STAGE_NAMES
            }
            response_bytes = {
                stage: counters.get(f"response_body_bytes_{stage}", 0) for stage in _PAIR_STAGE_NAMES
            }
            received = counters.get("http_requests_received", 0)
            writes = counters.get("server_response_writes_completed", 0)
            errors = counters.get("handler_errors", 0)
            if not received and not errors:
                exchange_state = "NOT_STARTED"
            elif handlers_settled and received == writes and errors == 0:
                exchange_state = "SERVER_WRITES_SETTLED"
            else:
                exchange_state = "INCOMPLETE"
            trace_attribution = attribution if isinstance(attribution, dict) else {"state": "UNKNOWN"}
            arm: dict[str, Any] = {
                "requested_candidate_count": cardinality,
                "input_identity": input_identity,
                "observer_mode": observer_mode,
                "observer_coverage": raw_observer.get("coverage", "UNKNOWN"),
                "observer_reason": raw_observer.get("reason"),
                "trace_attribution": trace_attribution,
                "cli_invocation_status": cli_status,
                "cli_exit_code": exit_code,
                "cli_result_present": isinstance(cli_result, dict),
                "primary_task_statuses": task_rows,
                "unexpected_task_result_count": unexpected,
                "coverage_state": durable.get("coverage_state") if isinstance(durable, dict) else None,
                "candidate_count": candidate_count,
                "claim_assessment_rows": len(claim_rows) if isinstance(claim_rows, list) else None,
                "claim_assessment_statuses": claim_statuses,
                "native_advisory_status": advisory_status,
                "http_requests_received": received,
                "server_response_writes_completed": writes,
                "protocol_exchange_state": exchange_state,
                "protocol_stage_counts": stage_counts,
                "request_body_bytes_by_stage": request_bytes,
                "response_body_bytes_by_stage": response_bytes,
                "fake_server_handlers_settled": handlers_settled,
                "fake_server_active_handlers_at_snapshot": active_handlers,
                "synthetic_protocol_path_state": (
                    "COMPLETE"
                    if exchange_state == "SERVER_WRITES_SETTLED"
                    and stage_counts == _cardinality_stage_counts(cardinality)
                    and isinstance(task_rows, list)
                    and all(row.get("status") == "SUCCEEDED" for row in task_rows)
                    and isinstance(durable, dict)
                    and durable.get("coverage_state") == "COMPLETE"
                    and claim_statuses == ["COMPLETE"] * cardinality
                    and advisory_status == "RECEIVED"
                    and candidate_count == cardinality
                    else "INCOMPLETE"
                ),
            }
            arm["arm_state"] = _cardinality_arm_state(arm, cardinality)
            arms.append(arm)
        comparison = _candidate_cardinality_comparison(arms[0], arms[1] if len(arms) > 1 else None)
        return {
            "contract_version": CARDINALITY_PAIR_CONTRACT_VERSION,
            "probe_kind": "same_snapshot_one_vs_two_scripted_candidates",
            "candidate_cardinality_is_the_only_scripted_response_change": True,
            "configured_transport": "HTTP_LOOPBACK_FAKE",
            "external_provider_dispatch_requested": False,
            "target_execution_requested": False,
            "limits": _limits(),
            "pair_deadline_seconds": 660,
            "input_identity": input_identity,
            "arms": [_cardinality_arm_projection(arm) for arm in arms],
            "comparison": comparison,
            "pair_state": comparison.get("state", "UNKNOWN"),
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        import shutil

        shutil.rmtree(work_root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True, help="exact installed pr-review executable")
    parser.add_argument("--workdir", type=Path, help="optional parent for private temporary fixture files")
    parser.add_argument("--no-observer", action="store_true", help="run the normal CLI without syscall attribution")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--candidate-cardinality-pair",
        action="store_true",
        help="run paired one- and two-candidate synthetic control arms on one prepared snapshot",
    )
    modes.add_argument(
        "--transport-pair",
        action="store_true",
        help="run one fixed HTTP control and a single TLS arm only if its complete trace is eligible",
    )
    parser.add_argument("--primary-response-delay-seconds", type=float, default=0.0,
                        help="optional delay for primary specialist responses only (0..15 seconds; native responses remain immediate)")
    args = parser.parse_args(argv)
    try:
        if args.transport_pair:
            if args.primary_response_delay_seconds != 0 or args.no_observer:
                raise ValueError("transport_pair_rejects_delay_or_missing_observer")
            result = run_transport_pair(args.cli, workdir=args.workdir, observe=True)
        elif args.candidate_cardinality_pair:
            if args.primary_response_delay_seconds != 0:
                raise ValueError("cardinality_pair_rejects_response_delay")
            result = run_candidate_cardinality_pair(
                args.cli,
                workdir=args.workdir,
                observe=not args.no_observer,
            )
        else:
            result = run(
                args.cli,
                workdir=args.workdir,
                observe=not args.no_observer,
                primary_response_delay_seconds=args.primary_response_delay_seconds,
            )
        encoded, within_limit = _bounded_summary_bytes(result)
        sys.stdout.buffer.write(encoded)
        completed = (
            result.get("pair_state") == "COMPLETE"
            if args.candidate_cardinality_pair or args.transport_pair
            else result.get("cli_invocation_status") == "CLI_COMPLETED"
        )
        return 0 if within_limit and completed else 2
    except Exception as exc:
        # Emit only a stable error type. Never print exception text or subprocess output.
        encoded, _ = _bounded_summary_bytes({"status": "FAILED", "error_type": type(exc).__name__})
        sys.stdout.buffer.write(encoded)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
