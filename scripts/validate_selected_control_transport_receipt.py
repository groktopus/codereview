#!/usr/bin/env python3
"""Validate the finite, source-bound receipt emitted by the manual transport workflow."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any

from selected_control_trace_attribution import _transport_pair_complete

MAX_RECEIPT_BYTES = 65_536
MODULE_COUNT = 28
TOP_LEVEL = {
    "contract_version", "pair_state", "reason", "diagnostic_head_sha", "diagnostic_script_sha256",
    "diagnostic_script_differs_from_head", "runtime_source_commit", "runtime_tree_sha256",
    "runtime_module_count", "runtime_module_hashes", "fixture_suite_sha256", "generated_profile_sha256",
    "base_sha", "head_sha", "run_id", "event_mode", "snapshot_id", "snapshot_hash", "task_ids",
    "task_lenses", "observer_id", "observer_source_sha256", "syscall_scope", "trace_cap_bytes", "limits",
    "observer_timeout_seconds_per_arm", "pair_deadline_seconds", "primary_response_delay_seconds",
    "tls_ca_sha256", "tls_private_material_in_receipt", "tls_verification_disabled", "arms", "comparison",
    "external_provider_dispatch_requested", "target_execution_requested", "quality_or_https_trace_parity_claim",
    "live_failure_cause_claim",
}
ARM_FIELDS = {
    "configured_transport", "state", "trace_attribution", "observer_mode", "observer_coverage", "observer_reason",
    "protocol_exchange_state", "protocol_stage_counts", "http_requests_received",
    "server_response_writes_completed", "fake_server_handlers_settled",
    "fake_server_active_handlers_at_snapshot", "synthetic_protocol_path_state", "primary_task_statuses",
    "cli_invocation_status", "cli_exit_code", "cli_result_present", "coverage_state",
    "claim_assessment_statuses", "native_advisory_status", "candidate_count", "unexpected_task_result_count",
    "transport_payload_hashes", "provider_config_sha256", "decision_config_sha256",
    "normalized_transport_config_sha256", "run_id", "event_mode", "event_identity", "task_ids",
    "snapshot_id", "snapshot_hash",
}
TRACE_FIELDS = {
    "state", "trace_bytes", "newline_terminated_line_bytes", "unattributed_or_partial_bytes",
    "parsed_line_count", "parse_failure_count", "bytes_by_syscall", "lines_by_syscall", "file_path_attribution",
}
PATH_FIELDS = {
    "state", "state_meaning", "basis", "path_argument_visibility", "line_bytes",
    "lines_by_syscall_class", "bytes_by_syscall_class", "target_lines_by_syscall",
    "target_bytes_by_syscall", "reconciliation",
}
STAGES = {
    "primary_correctness", "primary_security", "primary_tests", "semantic_adjudication", "native_claim",
    "native_summary",
}
STAGE_COUNTS = {
    "primary_correctness_received", "primary_security_received", "primary_tests_received",
    "semantic_adjudication_received", "native_claim_received", "native_summary_received",
    "primary_correctness_response_writes_completed", "primary_security_response_writes_completed",
    "primary_tests_response_writes_completed", "semantic_adjudication_response_writes_completed",
    "native_claim_response_writes_completed", "native_summary_response_writes_completed",
}
SYSCALLS = {
    "access", "arch_prctl", "brk", "chdir", "chmod", "clone", "clone3", "close", "connect", "dup", "dup2",
    "dup3", "execve", "execveat", "exit", "exit_group", "fcntl", "fstat", "fstatat64", "futex", "getcwd",
    "getdents64", "getegid", "geteuid", "getgid", "getrandom", "getuid", "ioctl", "lseek", "madvise", "mmap",
    "mprotect", "mkdir", "mkdirat", "nanosleep", "newfstatat", "open", "openat", "openat2", "pipe", "pipe2",
    "poll", "ppoll", "prlimit64", "read", "readlink", "recvfrom", "rename", "renameat", "renameat2",
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rseq", "sendto", "set_robust_list", "socket", "stat",
    "statx", "unlink", "unlinkat", "uname", "vfork", "wait4", "waitid", "write", "OTHER", "PROCESS_END",
    "SIGNAL", "UNPARSED",
}
PATH_CLASSES = {
    "CASE_WORKDIR", "CLI_ENVIRONMENT", "REPO_SUPPORT", "TEMP_ROOT", "SYSTEM_ROOT", "OTHER_ABSOLUTE",
    "UNKNOWN_RELATIVE", "UNKNOWN_SYNTAX", "UNKNOWN_UNFINISHED", "UNKNOWN_RESUMED",
    "UNKNOWN_ELLIPSIS_AMBIGUOUS", "UNKNOWN_RAW_ARGUMENTS",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def _keys(value: Any, expected: set[str], code: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(code)


def _hash(value: Any, code: str = "receipt_hash_invalid") -> None:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise ValueError(code)


def _trace(value: Any) -> None:
    _keys(value, TRACE_FIELDS, "trace_fields_invalid")
    if value["state"] not in {"COMPLETE", "PARTIAL", "INCOMPLETE"}:
        raise ValueError("trace_state_invalid")
    for key in ("trace_bytes", "newline_terminated_line_bytes", "unattributed_or_partial_bytes", "parsed_line_count", "parse_failure_count"):
        item = value[key]
        if item is not None and (isinstance(item, bool) or not isinstance(item, int) or item < 0):
            raise ValueError("trace_count_invalid")
    for key in ("bytes_by_syscall", "lines_by_syscall"):
        values = value[key]
        if not isinstance(values, dict) or not set(values).issubset(SYSCALLS):
            raise ValueError("trace_syscalls_invalid")
        if any(isinstance(n, bool) or not isinstance(n, int) or n < 0 for n in values.values()):
            raise ValueError("trace_syscall_count_invalid")
    if value["state"] == "COMPLETE":
        if (
            value["trace_bytes"] != value["newline_terminated_line_bytes"]
            or value["unattributed_or_partial_bytes"] != 0
            or sum(value["bytes_by_syscall"].values()) != value["trace_bytes"]
            or sum(value["lines_by_syscall"].values()) != value["parsed_line_count"]
        ):
            raise ValueError("complete_trace_accounting_mismatch")
    path = value["file_path_attribution"]
    _keys(path, PATH_FIELDS, "trace_path_fields_invalid")
    if (
        path["state_meaning"] != "numeric_line_and_byte_accounting_complete_unknown_classes_are_valid"
        or path["basis"] != "lexical_path_namespace_only_no_symlink_fd_or_pid_cwd_resolution"
        or path["line_bytes"] != "decoded_utf8_line_bytes_plus_observed_newline_byte"
    ):
        raise ValueError("trace_path_basis_invalid")
    if path["state"] not in {"COMPLETE", "PARTIAL", "UNKNOWN"} or path["reconciliation"] not in {"MATCH", "MISMATCH", "UNKNOWN"}:
        raise ValueError("trace_path_state_invalid")
    if path["path_argument_visibility"] != {
        "openat": "path_visible_and_lexically_classified",
        "newfstatat": "raw_hex_arguments_path_unavailable",
    }:
        raise ValueError("trace_path_visibility_invalid")
    for key in ("lines_by_syscall_class", "bytes_by_syscall_class"):
        values = path[key]
        if not isinstance(values, dict) or not set(values).issubset({"openat", "newfstatat"}):
            raise ValueError("trace_path_counts_invalid")
        for syscall_rows in values.values():
            if not isinstance(syscall_rows, dict) or not set(syscall_rows).issubset(PATH_CLASSES):
                raise ValueError("trace_path_class_counts_invalid")
            if any(isinstance(n, bool) or not isinstance(n, int) or n < 0 for n in syscall_rows.values()):
                raise ValueError("trace_path_count_invalid")
    for key in ("target_lines_by_syscall", "target_bytes_by_syscall"):
        values = path[key]
        if not isinstance(values, dict) or set(values) != {"openat", "newfstatat"}:
            raise ValueError("trace_path_target_fields_invalid")
        if any(isinstance(n, bool) or not isinstance(n, int) or n < 0 for n in values.values()):
            raise ValueError("trace_path_target_count_invalid")
    for path_key, target_key in (
        ("lines_by_syscall_class", "target_lines_by_syscall"),
        ("bytes_by_syscall_class", "target_bytes_by_syscall"),
    ):
        if any(
            sum(path[path_key].get(syscall, {}).values()) != path[target_key][syscall]
            for syscall in ("openat", "newfstatat")
        ):
            raise ValueError("trace_path_total_mismatch")


def _arm(row: Any, transport: str) -> None:
    if not isinstance(row, dict) or not set(row).issubset(ARM_FIELDS) or row.get("configured_transport") != transport:
        raise ValueError("arm_fields_invalid")
    if row.get("state") not in {"COMPLETE", "INCOMPLETE", "NOT_RUN_HTTP_BASELINE_INCOMPLETE", "NOT_RUN_PAIR_DEADLINE"}:
        raise ValueError("arm_state_invalid")
    if row["state"].startswith("NOT_RUN_"):
        if set(row) != {"configured_transport", "state"}:
            raise ValueError("skipped_arm_fields_invalid")
        return
    if row.get("observer_mode") not in {"LINUX_STRACE", "NOT_OBSERVED_PLATFORM_OR_EXPLICIT"}:
        raise ValueError("arm_observer_mode_invalid")
    if row.get("observer_coverage") not in {"SCOPED_COMPLETE", "INCOMPLETE", "UNKNOWN"}:
        raise ValueError("arm_observer_coverage_invalid")
    if not isinstance(row.get("cli_result_present"), bool):
        raise ValueError("arm_cli_result_presence_invalid")
    if row.get("coverage_state") not in {"COMPLETE", "PARTIAL", "NOT_STARTED", "UNKNOWN"}:
        raise ValueError("arm_coverage_state_invalid")
    if row.get("native_advisory_status") not in {"RECEIVED", "FAILED", "NOT_RUN", "UNKNOWN"}:
        raise ValueError("arm_native_advisory_status_invalid")
    if not isinstance(row.get("claim_assessment_statuses"), list) or any(
        status not in {"COMPLETE", "PARTIAL", "FAILED", "UNKNOWN"}
        for status in row["claim_assessment_statuses"]
    ):
        raise ValueError("arm_claim_statuses_invalid")
    if row.get("state") == "COMPLETE" and not _transport_pair_complete(row):
        raise ValueError("complete_arm_actual_criteria_mismatch")
    _trace(row.get("trace_attribution"))
    _keys(row.get("protocol_stage_counts"), STAGE_COUNTS, "arm_stage_fields_invalid")
    if not isinstance(row.get("task_ids"), list) or len(row["task_ids"]) != 3:
        raise ValueError("arm_task_ids_invalid")
    if not isinstance(row.get("primary_task_statuses"), list) or len(row["primary_task_statuses"]) != 3:
        raise ValueError("arm_task_statuses_invalid")
    for task in row["primary_task_statuses"]:
        _keys(task, {"task_id", "lens", "status"}, "arm_task_fields_invalid")
        if task["lens"] not in {"correctness", "security", "tests"}:
            raise ValueError("arm_task_lens_invalid")
        if task["status"] not in {"SUCCEEDED", "INCOMPLETE", "MISSING_RESULT", "UNKNOWN"}:
            raise ValueError("arm_task_status_invalid")
    hashes = row.get("transport_payload_hashes")
    _keys(hashes, STAGES, "arm_payload_stages_invalid")
    for payload in hashes.values():
        _keys(payload, {"request_bytes", "request_sha256", "response_bytes", "response_sha256"}, "payload_fields_invalid")
        for field in ("request_sha256", "response_sha256"):
            _hash(payload[field])
        for field, cap in (("request_bytes", 64_000), ("response_bytes", 32_768)):
            value = payload[field]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= cap:
                raise ValueError("payload_size_invalid")
    for field in ("provider_config_sha256", "decision_config_sha256", "normalized_transport_config_sha256", "snapshot_hash"):
        _hash(row.get(field))


def validate_receipt(path: Path, source_root: Path, expected_sha: str) -> dict[str, Any]:
    if not HEX40.fullmatch(expected_sha):
        raise ValueError("expected_source_sha_invalid")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size > MAX_RECEIPT_BYTES:
        raise ValueError("receipt_file_invalid")
    row = json.loads(path.read_text(encoding="utf-8"))
    _keys(row, TOP_LEVEL, "receipt_fields_invalid")
    if row["contract_version"] != "selected-control-transport-pair.v1":
        raise ValueError("receipt_contract_invalid")
    if row["diagnostic_head_sha"] != expected_sha or row["runtime_source_commit"] != expected_sha:
        raise ValueError("receipt_source_identity_mismatch")
    if row["diagnostic_script_differs_from_head"] is not False:
        raise ValueError("diagnostic_script_dirty")
    script_hash = hashlib.sha256((source_root / "scripts/selected_control_trace_attribution.py").read_bytes()).hexdigest()
    if row["diagnostic_script_sha256"] != script_hash:
        raise ValueError("diagnostic_script_hash_mismatch")
    source_dir = source_root / "src/pr_review_harness"
    expected_modules = {
        "pr_review_harness/" + p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(source_dir.glob("*.py")) if p.is_file() and not p.is_symlink()
    }
    modules = row["runtime_module_hashes"]
    if len(expected_modules) != MODULE_COUNT or modules != expected_modules or row["runtime_module_count"] != MODULE_COUNT:
        raise ValueError("runtime_module_identity_mismatch")
    for key in ("runtime_tree_sha256", "fixture_suite_sha256", "generated_profile_sha256", "observer_source_sha256", "tls_ca_sha256"):
        _hash(row[key])
    if row["trace_cap_bytes"] != 1_048_576 or row["observer_timeout_seconds_per_arm"] != 300 or row["pair_deadline_seconds"] != 660:
        raise ValueError("receipt_trace_budget_mismatch")
    if row["limits"] != {
        "max_provider_calls": 9, "max_retries_per_task": 0, "max_input_bytes_per_task": 64_000,
        "max_output_bytes_per_task": 32_768, "deadline_seconds": 270,
        "max_claim_assessments_per_run": 4,
    }:
        raise ValueError("receipt_cli_budget_mismatch")
    if row["syscall_scope"] != ["%process", "%file", "socket", "connect", "bind", "listen", "accept", "accept4", "shutdown"]:
        raise ValueError("receipt_syscall_scope_mismatch")
    if row["tls_private_material_in_receipt"] is not False or row["tls_verification_disabled"] is not False:
        raise ValueError("receipt_tls_safety_mismatch")
    if row["external_provider_dispatch_requested"] is not False or row["target_execution_requested"] is not False:
        raise ValueError("receipt_effect_scope_mismatch")
    if row["run_id"] != "r1-control" or row["event_mode"] != "LOCAL_EXPLICIT_BASE_HEAD_NO_GITHUB_EVENT":
        raise ValueError("receipt_run_identity_mismatch")
    if row["task_lenses"] != ["correctness", "security", "tests"] or len(row["task_ids"]) != 3:
        raise ValueError("receipt_task_scope_mismatch")
    if not HEX40.fullmatch(row["base_sha"]) or not HEX40.fullmatch(row["head_sha"]):
        raise ValueError("receipt_case_identity_invalid")
    if not isinstance(row["arms"], list) or not 1 <= len(row["arms"]) <= 2:
        raise ValueError("receipt_arms_invalid")
    _arm(row["arms"][0], "HTTP_LOOPBACK_FAKE")
    if len(row["arms"]) == 2:
        _arm(row["arms"][1], "HTTPS_LOOPBACK_FAKE")
        if not row["arms"][1].get("state", "").startswith("NOT_RUN_") and row["arms"][0].get("state") != "COMPLETE":
            raise ValueError("tls_without_complete_http")
    for arm in row["arms"]:
        if arm.get("state", "").startswith("NOT_RUN_"):
            continue
        if (
            arm["run_id"] != row["run_id"]
            or arm["event_mode"] != row["event_mode"]
            or arm["task_ids"] != row["task_ids"]
            or arm["snapshot_id"] != row["snapshot_id"]
            or arm["snapshot_hash"] != row["snapshot_hash"]
            or [item.get("task_id") for item in arm["primary_task_statuses"]] != row["task_ids"]
        ):
            raise ValueError("arm_identity_binding_mismatch")
    if row["pair_state"] == "COMPLETE":
        if len(row["arms"]) != 2 or any(arm.get("state") != "COMPLETE" for arm in row["arms"]):
            raise ValueError("complete_pair_arm_mismatch")
        if not isinstance(row["comparison"], dict):
            raise ValueError("complete_pair_comparison_missing")
        if row["arms"][0]["transport_payload_hashes"] != row["arms"][1]["transport_payload_hashes"]:
            raise ValueError("complete_pair_payload_mismatch")
        if row["arms"][0]["normalized_transport_config_sha256"] != row["arms"][1]["normalized_transport_config_sha256"]:
            raise ValueError("complete_pair_config_mismatch")
    elif row["pair_state"] != "INCOMPLETE":
        raise ValueError("receipt_pair_state_invalid")
    if row["comparison"] is not None:
        _keys(row["comparison"], {
            "input_identity_match", "request_response_body_hashes_match", "normalized_endpoint_config_match",
            "http_trace_bytes", "https_trace_bytes", "trace_bytes_delta_https_minus_http",
            "trace_bytes_by_syscall_delta_https_minus_http",
        }, "comparison_fields_invalid")
        comparison = row["comparison"]
        for field in ("input_identity_match", "request_response_body_hashes_match", "normalized_endpoint_config_match"):
            if not isinstance(comparison[field], bool):
                raise ValueError("comparison_boolean_invalid")
        http_bytes = comparison["http_trace_bytes"]
        https_bytes = comparison["https_trace_bytes"]
        delta = comparison["trace_bytes_delta_https_minus_http"]
        if any(isinstance(n, bool) or not isinstance(n, int) for n in (http_bytes, https_bytes, delta)):
            raise ValueError("comparison_trace_bytes_invalid")
        if not isinstance(comparison["trace_bytes_by_syscall_delta_https_minus_http"], dict):
            raise ValueError("comparison_syscall_delta_invalid")
        syscall_delta = comparison["trace_bytes_by_syscall_delta_https_minus_http"]
        if not set(syscall_delta).issubset(SYSCALLS) or any(
            isinstance(n, bool) or not isinstance(n, int) for n in syscall_delta.values()
        ):
            raise ValueError("comparison_syscall_delta_invalid")
        left, right = row["arms"]
        if (
            http_bytes != left["trace_attribution"]["trace_bytes"]
            or https_bytes != right["trace_attribution"]["trace_bytes"]
            or delta != https_bytes - http_bytes
        ):
            raise ValueError("comparison_trace_arithmetic_mismatch")
        expected_syscall_delta = {
            key: right["trace_attribution"]["bytes_by_syscall"].get(key, 0)
            - left["trace_attribution"]["bytes_by_syscall"].get(key, 0)
            for key in sorted(
                set(left["trace_attribution"]["bytes_by_syscall"])
                | set(right["trace_attribution"]["bytes_by_syscall"])
            )
        }
        if syscall_delta != expected_syscall_delta:
            raise ValueError("comparison_syscall_arithmetic_mismatch")
        if row["pair_state"] == "COMPLETE":
            if not all(comparison[field] for field in (
                "input_identity_match", "request_response_body_hashes_match", "normalized_endpoint_config_match"
            )):
                raise ValueError("complete_pair_comparison_false")
    forbidden = (b"loopback-only-synthetic-key", b"loopback-only-synthetic-decision-key", b"PRIVATE KEY", b"-----BEGIN CERTIFICATE-----")
    raw = path.read_bytes()
    if any(marker in raw for marker in forbidden):
        raise ValueError("receipt_secret_or_pem_detected")
    return row


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    args = parser.parse_args()
    try:
        validate_receipt(args.receipt, args.source_root, args.expected_sha)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, KeyError, TypeError):
        print("transport_receipt_rejected")
        return 1
    print("transport_receipt_valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
