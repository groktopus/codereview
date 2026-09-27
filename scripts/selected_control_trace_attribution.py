#!/usr/bin/env python3
"""Attribute bounded observer trace bytes for the frozen synthetic control case.

This is a secretless loopback diagnostic, not a model-quality or live-HTTPS
equivalence test. It uses the normal installed CLI and a parser wrapper that
retains only fixed syscall/path-class counts and byte totals, never observed paths.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import time
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
    _command,
    _limits,
    _runtime_provenance,
    canonical_json,
)

MAX_HTTP_REQUEST_BYTES = 64_000
MAX_HTTP_RESPONSE_BYTES = 32_768
MAX_SUMMARY_BYTES = 65_536
DIAGNOSTIC_CONTRACT_VERSION = "selected-control-trace-attribution.v4"
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
_SYSTEM_PATH_ROOTS = (
    "/usr", "/lib", "/lib64", "/etc", "/proc", "/dev", "/var", "/run",
    "/opt", "/System", "/Library", "/Applications",
)
_FILE_PATH_CLASSES = (
    "CASE_WORKDIR", "CLI_ENVIRONMENT", "REPO_SUPPORT", "TEMP_ROOT", "SYSTEM_ROOT",
    "OTHER_ABSOLUTE", "UNKNOWN_RELATIVE", "UNKNOWN_SYNTAX", "UNKNOWN_UNFINISHED",
    "UNKNOWN_RESUMED", "UNKNOWN_ELLIPSIS_AMBIGUOUS",
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


def _primary_payload(request: dict[str, Any], counters: _CallCounters) -> dict[str, Any]:
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
        candidates.append(
            {
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

    def __init__(self, address):
        self.counters = _CallCounters()
        self.primary_response_delay_seconds = 0.0
        self._active_handlers = 0
        self._idle_condition = threading.Condition()
        super().__init__(address, self.handler_type())

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
                        response = _primary_payload(request, counters)
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
) -> dict[str, Any]:
    if (
        isinstance(primary_response_delay_seconds, bool)
        or not isinstance(primary_response_delay_seconds, (int, float))
        or not 0 <= primary_response_delay_seconds <= 15
    ):
        raise ValueError("primary_response_delay_invalid")
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
    work_root = Path(tempfile.mkdtemp(prefix="selected-control-trace-", dir=workdir))
    os.chmod(work_root, 0o700)
    server = _FakeServer(("127.0.0.1", 0))
    server.primary_response_delay_seconds = float(primary_response_delay_seconds)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    try:
        thread.start()
        port = server.server_address[1]
        fixture_root = work_root / "fixture-suite"
        prepared = prepare_suite(
            fixture_root,
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
        output_path = work_root / "cli-output"
        _write_limits(limits_path)
        provider_path.write_text(
            json.dumps(
                {"kind": "openai_compatible", "provider_id": "operator_openai_compatible",
                 "base_url": f"http://127.0.0.1:{port}/v1", "model": FAKE_MODEL,
                 "api_key_env": "LLM_API_KEY"},
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        decision_path.write_text(
            json.dumps(
                {"kind": "typesafe", "endpoint": f"http://127.0.0.1:{port}/v1/systemone",
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
        if observe and sys.platform.startswith("linux"):
            observed, attribution = _attributed_observation(
                command,
                cwd=work_root,
                env=_environment(),
                timeout=300,
                roots=_path_roots(cli=cli, work_root=work_root, repo_support=ROOT),
            )
            observer_mode = "LINUX_STRACE"
        else:
            observed = invoke_cli_bounded(command, cwd=work_root, env=_environment(), timeout_seconds=300)
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
        return {
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
            "configured_transport": "HTTP_LOOPBACK_FAKE",
            "provider_adapter_defaults_preserved": True,
            "target_execution_requested": False,
            "reviewed_code_execution_observation": "UNKNOWN",
            "quality_or_https_trace_parity_claim": False,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        # These inputs and the private durable result contain only synthetic data.
        import shutil

        shutil.rmtree(work_root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True, help="exact installed pr-review executable")
    parser.add_argument("--workdir", type=Path, help="optional parent for private temporary fixture files")
    parser.add_argument("--no-observer", action="store_true", help="run the normal CLI without syscall attribution")
    parser.add_argument("--primary-response-delay-seconds", type=float, default=0.0,
                        help="optional delay for primary specialist responses only (0..15 seconds; native responses remain immediate)")
    args = parser.parse_args(argv)
    try:
        result = run(
            args.cli,
            workdir=args.workdir,
            observe=not args.no_observer,
            primary_response_delay_seconds=args.primary_response_delay_seconds,
        )
        encoded, within_limit = _bounded_summary_bytes(result)
        sys.stdout.buffer.write(encoded)
        return 0 if within_limit and result.get("cli_invocation_status") == "CLI_COMPLETED" else 2
    except Exception as exc:
        # Emit only a stable error type. Never print exception text or subprocess output.
        encoded, _ = _bounded_summary_bytes({"status": "FAILED", "error_type": type(exc).__name__})
        sys.stdout.buffer.write(encoded)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
