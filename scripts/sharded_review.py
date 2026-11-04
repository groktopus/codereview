#!/usr/bin/env python3
"""Run the full review profile over changed-file batches without erasing scope.

The script is deliberately a thin deterministic orchestrator around the
existing ``python -m pr_review_harness review`` entry point. It does not
implement review logic, call providers directly, or publish anything. Each
batch receives a generated profile that copies the trusted profile and adds
``scope_paths`` for exactly that batch, so every configured lens, risk rule,
check, and policy setting remains active for the files in the batch.

The union of all batch paths must equal the immutable diff set. A missing,
failed, or incomplete batch makes the combined artifact ``INCOMPLETE``; a
known blocker in any complete batch still yields ``REQUEST_CHANGES``.
"""

from __future__ import annotations

import argparse
import copy
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pr_review_harness.claim_reconciliation import validate_claim_reconciliation_policy  # noqa: E402
from pr_review_harness.planner import validate_profile_scope  # noqa: E402

RESULT_SCHEMA = "review-sharded-result.v1"
DEFAULT_BATCH_SIZE = 6
DEFAULT_TIMEOUT_SECONDS = 1800
MAX_BATCH_SIZE = 1000
STRIPPED_ENV_NAMES = frozenset({"GITHUB_EVENT_PATH", "GITHUB_TOKEN", "GH_TOKEN", "PUBLISH_REVIEW"})
STRIPPED_ENV_PREFIXES = ("ACTIONS_",)
_SAFE_REVISION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@^~-]{0,255}")
_SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_DISPOSITION_RANK = {"APPROVE": 0, "COMMENT": 1, "INCOMPLETE": 2, "REQUEST_CHANGES": 3}


class ShardedReviewError(ValueError):
    """A deterministic, sanitized orchestration failure."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def sanitized_env(environ: dict[str, str] | None = None) -> dict[str, str]:
    """Return an environment with publication/event credentials removed."""
    source = dict(os.environ if environ is None else environ)
    return {
        key: value
        for key, value in source.items()
        if key not in STRIPPED_ENV_NAMES and not key.startswith(STRIPPED_ENV_PREFIXES)
    }


def _git(repo: Path, *args: str) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=sanitized_env(),
    )
    if process.returncode != 0:
        raise ShardedReviewError(f"git command failed (exit {process.returncode})")
    return process.stdout


def _safe_revision(value: str) -> str:
    if not isinstance(value, str) or not _SAFE_REVISION.fullmatch(value) or value.startswith("-"):
        raise ShardedReviewError("base and head must be non-option Git revisions")
    return value


def resolve_revision(repo: Path, revision: str) -> str:
    """Resolve one revision to a full immutable commit identity."""
    raw = _git(repo, "rev-parse", "--verify", f"{_safe_revision(revision)}^{{commit}}")
    resolved = raw.decode("ascii", "strict").strip()
    if not _SHA_RE.fullmatch(resolved):
        raise ShardedReviewError("git returned an invalid commit identity")
    return resolved


def changed_files(repo: Path, base: str, head: str) -> list[str]:
    """Return the exact diff path set using a fixed Git argument array."""
    raw = _git(repo, "diff", "--name-only", "-z", f"{base}..{head}")
    paths = [item.decode("utf-8", "surrogateescape") for item in raw.split(b"\0") if item]
    for path in paths:
        if path.startswith("/") or ".." in path.split("/") or len(path.encode("utf-8", "surrogateescape")) > 4096:
            raise ShardedReviewError("git returned an unsafe changed path")
    if len(paths) != len(set(paths)):
        raise ShardedReviewError("git returned duplicate changed paths")
    return paths


def partition_paths(paths: list[str], batch_size: int) -> list[list[str]]:
    """Partition paths into ordered, disjoint batches covering the exact input."""
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= MAX_BATCH_SIZE:
        raise ShardedReviewError(f"batch size must be between 1 and {MAX_BATCH_SIZE}")
    if not isinstance(paths, list) or any(not isinstance(path, str) or not path for path in paths):
        raise ShardedReviewError("changed paths must be nonempty strings")
    batches = [list(paths[index : index + batch_size]) for index in range(0, len(paths), batch_size)]
    validate_partition(paths, batches)
    return batches


def validate_partition(paths: list[str], batches: list[list[str]]) -> None:
    """Assert exact union and no overlaps; never return a silent subset."""
    if not batches:
        if paths:
            raise ShardedReviewError("batch partition is empty for a nonempty diff")
        return
    seen: set[str] = set()
    for batch in batches:
        if not batch or len(batch) != len(set(batch)):
            raise ShardedReviewError("a batch is empty or contains duplicate paths")
        for path in batch:
            if path in seen:
                raise ShardedReviewError("a changed path appears in more than one batch")
            seen.add(path)
    flat = [path for batch in batches for path in batch]
    if Counter(flat) != Counter(paths):
        raise ShardedReviewError("batch union does not equal the changed-file set")


def escape_glob_path(path: str) -> str:
    """Escape fnmatch metacharacters so an exact path stays exact."""
    replacements = {"*": "[*]", "?": "[?]", "[": "[[]"}
    return "".join(replacements.get(character, character) for character in path)


def build_scoped_profile(profile: dict[str, Any], batch_paths: list[str]) -> dict[str, Any]:
    """Copy the full profile and restrict it to the batch's exact paths."""
    if not isinstance(profile, dict) or not isinstance(batch_paths, list) or not batch_paths:
        raise ShardedReviewError("a batch profile needs the profile object and at least one path")
    if any(not isinstance(path, str) or not path for path in batch_paths):
        raise ShardedReviewError("batch paths must be nonempty strings")
    existing = validate_profile_scope(profile)
    if existing is not None:
        outside = [path for path in batch_paths if not any(fnmatch.fnmatchcase(path, pattern) for pattern in existing)]
        if outside:
            raise ShardedReviewError("a batch path is outside the trusted profile scope")
    scoped = copy.deepcopy(profile)
    scoped["scope_paths"] = [escape_glob_path(path) for path in batch_paths]
    return scoped


def write_profile(path: Path, profile: dict[str, Any]) -> str:
    data = (json.dumps(profile, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _atomic_write(path, data)
    return _sha256_bytes(data)


def _claim_cap(profile: dict[str, Any]) -> int:
    policy = validate_claim_reconciliation_policy(profile)
    return int(policy["max_assessments"]) if policy else 0


def _error_code(raw: str) -> str | None:
    for line in reversed(raw.splitlines()):
        try:
            value = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if isinstance(value, dict) and isinstance(value.get("error"), str):
            return value["error"][:200]
    return None


def _reason_token(value: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_")[:80] or "unknown"


def _result_reasons(result: dict[str, Any] | None) -> list[str]:
    if not isinstance(result, dict):
        return []
    reasons: list[str] = []
    disposition = result.get("disposition")
    if disposition == "INCOMPLETE":
        reasons.append("shard_disposition_incomplete")
    elif disposition not in {"APPROVE", "COMMENT", "REQUEST_CHANGES"}:
        reasons.append("shard_disposition_unknown")
    if result.get("coverage_state") != "COMPLETE":
        reasons.append(f"shard_coverage_{str(result.get('coverage_state', 'UNKNOWN')).lower()}")
    if result.get("freshness") not in {None, "CURRENT"}:
        reasons.append(f"shard_freshness_{str(result.get('freshness')).lower()}")
    if result.get("policy_valid") is False:
        reasons.append("shard_policy_invalid")
    budget = result.get("budget")
    if isinstance(budget, dict) and budget.get("budget_breaches"):
        reasons.append("shard_budget_breach")
    coverage = result.get("coverage_ledger")
    if isinstance(coverage, list):
        for row in coverage:
            if isinstance(row, dict) and row.get("required", True) and row.get("state") != "COMPLETE":
                if isinstance(row.get("reason_code"), str):
                    reasons.append(f"coverage:{row['reason_code']}")
    return list(dict.fromkeys(reasons))


def _shard_record(
    *,
    shard_id: str,
    paths: list[str],
    scope_paths: list[str],
    profile_path: Path,
    profile_sha256: str,
    base_sha: str,
    head_sha: str,
    output_root: Path,
    exit_code: int | None,
    result_path: Path | None,
    result: dict[str, Any] | None,
    error: str | None,
) -> dict[str, Any]:
    reasons: list[str] = []
    if exit_code is None:
        reasons.append("shard_timeout")
    elif exit_code != 0:
        reasons.append(f"shard_exit_{exit_code}")
    if error:
        reasons.append(f"shard_error_{_reason_token(error)}")
    if result is None:
        reasons.append("missing_shard_result")
    reasons.extend(_result_reasons(result))
    reasons = list(dict.fromkeys(reasons))
    complete = exit_code == 0 and result is not None and not _result_reasons(result)
    disposition = (
        str(result.get("disposition")) if isinstance(result, dict) and result.get("disposition") else "INCOMPLETE"
    )
    coverage = (
        str(result.get("coverage_state")) if isinstance(result, dict) and result.get("coverage_state") else "UNKNOWN"
    )
    return {
        "shard_id": shard_id,
        "paths": list(paths),
        "scope_paths": list(scope_paths),
        "base_sha": base_sha,
        "head_sha": head_sha,
        "profile_path": _relative(profile_path, output_root),
        "profile_sha256": profile_sha256,
        "exit_code": exit_code,
        "status": "COMPLETE" if complete else "INCOMPLETE",
        "disposition": disposition,
        "coverage_state": coverage,
        "freshness": result.get("freshness") if isinstance(result, dict) else None,
        "result_path": _relative(result_path, output_root) if result_path is not None else None,
        "result_sha256": _sha256_bytes(result_path.read_bytes())
        if result_path is not None and result_path.is_file()
        else None,
        "findings_count": len(result.get("findings", []))
        if isinstance(result, dict) and isinstance(result.get("findings"), list)
        else 0,
        "reasons": reasons,
    }


def _relative(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _finding_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    return (
        finding.get("path"),
        location.get("side"),
        location.get("kind"),
        location.get("line"),
        finding.get("title"),
        finding.get("observation"),
    )


def _finding_strength(finding: dict[str, Any]) -> tuple[int, int]:
    status = {"UNSUPPORTED": 0, "NEEDS_EVIDENCE": 1, "ACCEPTED": 2}.get(str(finding.get("status")), 0)
    blocking = {"NON_BLOCKING": 0, "UNRESOLVED": 1, "BLOCKING": 2}.get(str(finding.get("blocking_class")), 0)
    return status, blocking


def merge_findings(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate findings while retaining the strongest record and shard ids."""
    merged: dict[tuple[Any, ...], dict[str, Any]] = {}
    for record in records:
        shard_id = str(record.get("shard_id"))
        findings = record.get("_findings")
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            key = _finding_key(finding)
            candidate = copy.deepcopy(finding)
            candidate["shard_ids"] = [shard_id]
            current = merged.get(key)
            if current is None or _finding_strength(candidate) > _finding_strength(current):
                if current is not None:
                    candidate["shard_ids"] = sorted(set(candidate["shard_ids"]) | set(current.get("shard_ids", [])))
                merged[key] = candidate
            else:
                current["shard_ids"] = sorted(set(current.get("shard_ids", [])) | {shard_id})
    return sorted(
        merged.values(),
        key=lambda finding: (
            str(finding.get("path") or ""),
            str((finding.get("location") or {}).get("line") or 0),
            str(finding.get("title") or ""),
        ),
    )


def _gap_key(gap: dict[str, Any]) -> tuple[Any, ...]:
    proposal = gap.get("proposal") if isinstance(gap.get("proposal"), dict) else {}
    target = proposal.get("target") if isinstance(proposal.get("target"), dict) else {}
    return (
        gap.get("resolved_unit_id"),
        target.get("target_path"),
        target.get("target_symbol"),
        proposal.get("rationale"),
    )


def merge_gaps(records: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    """Deduplicate context/snapshot gaps and retain every contributing shard."""
    merged: dict[tuple[Any, ...], dict[str, Any]] = {}
    for record in records:
        shard_id = str(record.get("shard_id"))
        gaps = record.get(field)
        if not isinstance(gaps, list):
            continue
        for gap in gaps:
            if not isinstance(gap, dict):
                continue
            key = _gap_key(gap) if field == "context_gaps" else tuple(_canonical(gap))
            candidate = copy.deepcopy(gap)
            candidate["shard_ids"] = [shard_id]
            current = merged.get(key)
            if current is None:
                merged[key] = candidate
                continue
            current["shard_ids"] = sorted(set(current.get("shard_ids", [])) | {shard_id})
            for id_field in ("affected_obligation_ids", "related_evidence_ids"):
                left = current.get(id_field) if isinstance(current.get(id_field), list) else []
                right = candidate.get(id_field) if isinstance(candidate.get(id_field), list) else []
                if left or right:
                    current[id_field] = list(dict.fromkeys(left + right))
    return sorted(merged.values(), key=lambda gap: _canonical(gap))


def _combined_disposition(shards: list[dict[str, Any]], completeness: str) -> str:
    dispositions = {str(shard.get("disposition")) for shard in shards}
    if "REQUEST_CHANGES" in dispositions:
        return "REQUEST_CHANGES"
    if completeness != "COMPLETE" or "INCOMPLETE" in dispositions:
        return "INCOMPLETE"
    if "COMMENT" in dispositions:
        return "COMMENT"
    if dispositions == {"APPROVE"}:
        return "APPROVE"
    return "INCOMPLETE"


def _coverage_summary(results: list[dict[str, Any] | None]) -> dict[str, Any]:
    states: Counter[str] = Counter()
    reason_codes: Counter[str] = Counter()
    required = 0
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("coverage_ledger"), list):
            continue
        for row in result["coverage_ledger"]:
            if not isinstance(row, dict) or row.get("required", True) is not True:
                continue
            required += 1
            states[str(row.get("state", "UNKNOWN"))] += 1
            if row.get("state") != "COMPLETE":
                reason_codes[str(row.get("reason_code", "UNKNOWN"))] += 1
    return {
        "required_obligations": required,
        "states": dict(sorted(states.items())),
        "incomplete_reason_codes": dict(sorted(reason_codes.items())),
    }


def assemble_result(
    *,
    repo: Path,
    base_sha: str,
    head_sha: str,
    diff_files: list[str],
    batches: list[list[str]],
    shard_records: list[dict[str, Any]],
    shard_results: list[dict[str, Any] | None],
    profile_path: Path,
    profile_sha256: str,
    profile_version: Any,
    limits_path: Path | None,
    limits_sha256: str | None,
    provider_sha256: str | None,
    batch_size: int,
) -> dict[str, Any]:
    """Build the versioned combined artifact from completed shard records."""
    completeness = (
        "COMPLETE"
        if shard_records
        and len(shard_records) == len(batches)
        and all(record.get("status") == "COMPLETE" for record in shard_records)
        else "INCOMPLETE"
    )
    incomplete_reasons = [
        {
            "shard_id": record.get("shard_id"),
            "paths": record.get("paths"),
            "reasons": record.get("reasons"),
        }
        for record in shard_records
        if record.get("status") != "COMPLETE"
    ]
    findings = merge_findings(shard_records)
    context_gaps = merge_gaps(shard_records, "context_gaps")
    snapshot_gaps = merge_gaps(shard_records, "snapshot_gaps")
    public_records = [
        {key: value for key, value in record.items() if key not in {"_findings", "context_gaps", "snapshot_gaps"}}
        for record in shard_records
    ]
    provider_identities: list[Any] = []
    for result in shard_results:
        if isinstance(result, dict) and isinstance(result.get("provider_identity"), dict):
            if result["provider_identity"] not in provider_identities:
                provider_identities.append(result["provider_identity"])
    return {
        "schema": RESULT_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "repo": str(repo),
        "base_sha": base_sha,
        "head_sha": head_sha,
        "batch_size": batch_size,
        "diff_files": diff_files,
        "diff_files_sha256": _sha256_bytes(_canonical(diff_files).encode("utf-8")),
        "partition": {
            "union_matches_diff": Counter(path for batch in batches for path in batch) == Counter(diff_files),
            "overlap_count": len([path for batch in batches for path in batch])
            - len({path for batch in batches for path in batch}),
            "batch_count": len(batches),
        },
        "profile": {
            "path": str(profile_path),
            "sha256": profile_sha256,
            "version": profile_version,
            "per_shard_scope": True,
        },
        "limits": {"path": str(limits_path) if limits_path else None, "sha256": limits_sha256},
        "provider_config_sha256": provider_sha256,
        "completeness": completeness,
        "disposition": _combined_disposition(shard_records, completeness),
        "coverage": _coverage_summary(shard_results),
        "findings": findings,
        "context_gaps": context_gaps,
        "snapshot_gaps": snapshot_gaps,
        "shards": public_records,
        "incomplete_reasons": incomplete_reasons,
        "provider_identities": provider_identities,
    }


def _build_command(
    *,
    repo: Path,
    base_sha: str,
    head_sha: str,
    profile_path: Path,
    output_dir: Path,
    run_id: str,
    mode: str,
    provider_config: Path | None,
    decision_config: Path | None,
    limits_path: Path | None,
    checks_json: Path | None,
    historical_checks_json: Path | None,
    max_claim_assessments: int,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "pr_review_harness",
        "review",
        "--repo",
        str(repo),
        "--base",
        base_sha,
        "--head",
        head_sha,
        "--profile",
        str(profile_path),
        "--output",
        str(output_dir),
        "--run-id",
        run_id,
        "--mode",
        mode,
        "--effect-policy",
        "READ_ONLY",
        "--json",
    ]
    if provider_config is not None:
        command.extend(["--provider-config", str(provider_config)])
    if decision_config is not None:
        command.extend(["--decision-config", str(decision_config)])
    if limits_path is not None:
        command.extend(["--limits", str(limits_path)])
    if checks_json is not None:
        command.extend(["--checks-json", str(checks_json)])
    if historical_checks_json is not None:
        command.extend(["--historical-checks-json", str(historical_checks_json)])
    if max_claim_assessments:
        command.extend(["--max-claim-assessments", str(max_claim_assessments)])
    return command


def _run_shard(
    command: list[str], *, repo: Path, result_path: Path, timeout_seconds: float
) -> tuple[int | None, dict[str, Any] | None, str | None]:
    env = sanitized_env()
    if SRC.is_dir():
        previous = env.get("PYTHONPATH")
        env["PYTHONPATH"] = str(SRC) + (os.pathsep + previous if previous else "")
    try:
        process = subprocess.run(
            command,
            cwd=str(repo),
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return None, None, "timeout"
    result = None
    if result_path.is_file():
        try:
            value = json.loads(result_path.read_text(encoding="utf-8"))
            result = value if isinstance(value, dict) else None
        except (OSError, json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            result = None
    error = _error_code(process.stdout) or _error_code(process.stderr)
    if process.returncode != 0 and error is None:
        error = "review_process_failed"
    return process.returncode, result, error


def run_sharded_review(
    *,
    repo: Path,
    base: str,
    head: str,
    profile: dict[str, Any],
    profile_path: Path,
    output_dir: Path,
    batch_size: int = DEFAULT_BATCH_SIZE,
    mode: str = "AUTO",
    provider_config: Path | None = None,
    decision_config: Path | None = None,
    limits_path: Path | None = None,
    checks_json: Path | None = None,
    historical_checks_json: Path | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    shard_runner: Callable[..., tuple[int | None, dict[str, Any] | None, str | None]] | None = None,
) -> dict[str, Any]:
    """Execute every batch and return a combined review-sharded-result.v1."""
    repo = Path(repo).resolve()
    base_sha = resolve_revision(repo, base)
    head_sha = resolve_revision(repo, head)
    diff_files = changed_files(repo, base_sha, head_sha)
    batches = partition_paths(diff_files, batch_size)
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if not batches:
        return assemble_result(
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            diff_files=diff_files,
            batches=batches,
            shard_records=[],
            shard_results=[],
            profile_path=profile_path,
            profile_sha256=_sha256_bytes(profile_path.read_bytes()),
            profile_version=profile.get("version", profile.get("profile_version")),
            limits_path=limits_path,
            limits_sha256=_sha256_bytes(limits_path.read_bytes()) if limits_path and limits_path.is_file() else None,
            provider_sha256=_sha256_bytes(provider_config.read_bytes())
            if provider_config and provider_config.is_file()
            else None,
            batch_size=batch_size,
        )
    cap = _claim_cap(profile)
    if cap and decision_config is None:
        raise ShardedReviewError("profile requires a decision provider for its exact claim-assessment cap")
    runner = shard_runner or _run_shard
    records: list[dict[str, Any]] = []
    results: list[dict[str, Any] | None] = []
    for index, batch in enumerate(batches):
        scoped = build_scoped_profile(profile, batch)
        shard_id = f"shard-{index:03d}"
        shard_dir = output_dir / shard_id
        shard_dir.mkdir(parents=True, exist_ok=True)
        generated_profile = shard_dir / "profile.json"
        scoped_sha = write_profile(generated_profile, scoped)
        run_id = f"{shard_id}-{_sha256_bytes(_canonical(batch).encode('utf-8'))[:8]}"
        command = _build_command(
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            profile_path=generated_profile,
            output_dir=shard_dir,
            run_id=run_id,
            mode=mode,
            provider_config=provider_config,
            decision_config=decision_config,
            limits_path=limits_path,
            checks_json=checks_json,
            historical_checks_json=historical_checks_json,
            max_claim_assessments=cap,
        )
        result_path = shard_dir / f"{run_id}.json"
        exit_code, result, error = runner(
            command,
            repo=repo,
            result_path=result_path,
            timeout_seconds=timeout_seconds,
        )
        record = _shard_record(
            shard_id=shard_id,
            paths=batch,
            scope_paths=scoped["scope_paths"],
            profile_path=generated_profile,
            profile_sha256=scoped_sha,
            base_sha=base_sha,
            head_sha=head_sha,
            output_root=output_dir,
            exit_code=exit_code,
            result_path=result_path if result_path.is_file() else None,
            result=result,
            error=error,
        )
        if isinstance(result, dict):
            record["_findings"] = result.get("findings", [])
            record["context_gaps"] = result.get("context_gaps", [])
            record["snapshot_gaps"] = result.get("snapshot_gaps", [])
        records.append(record)
        results.append(result)
    return assemble_result(
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
        diff_files=diff_files,
        batches=batches,
        shard_records=records,
        shard_results=results,
        profile_path=profile_path,
        profile_sha256=_sha256_bytes(profile_path.read_bytes()),
        profile_version=profile.get("version", profile.get("profile_version")),
        limits_path=limits_path,
        limits_sha256=_sha256_bytes(limits_path.read_bytes()) if limits_path and limits_path.is_file() else None,
        provider_sha256=_sha256_bytes(provider_config.read_bytes())
        if provider_config and provider_config.is_file()
        else None,
        batch_size=batch_size,
    )


def _write_result(path: Path, result: dict[str, Any]) -> None:
    _atomic_write(path, (json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="local Git repository")
    parser.add_argument("--base", required=True, help="base revision")
    parser.add_argument("--head", required=True, help="head revision")
    parser.add_argument("--profile", required=True, help="trusted full profile JSON")
    parser.add_argument("--provider-config", help="trusted provider configuration JSON")
    parser.add_argument("--decision-config", help="trusted claim-assessment decision configuration JSON")
    parser.add_argument("--limits", help="trusted finite limits JSON")
    parser.add_argument("--checks-json", help="event-bound GitHub check evidence")
    parser.add_argument("--historical-checks-json", help="historical GitHub check evidence for the explicit revisions")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--mode", choices=["AUTO", "LIGHT", "FOCUSED", "DEEP"], default="AUTO")
    parser.add_argument("--output", default="artifacts/sharded-review")
    parser.add_argument("--result", help="combined result path (default: <output>/review-sharded-result.json)")
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--json", action="store_true", help="emit the combined result as one JSON value")
    args = parser.parse_args(argv)
    try:
        profile_path = Path(args.profile).resolve()
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        if not isinstance(profile, dict):
            raise ShardedReviewError("profile must be a JSON object")
        result = run_sharded_review(
            repo=Path(args.repo),
            base=args.base,
            head=args.head,
            profile=profile,
            profile_path=profile_path,
            output_dir=Path(args.output),
            batch_size=args.batch_size,
            mode=args.mode,
            provider_config=Path(args.provider_config).resolve() if args.provider_config else None,
            decision_config=Path(args.decision_config).resolve() if args.decision_config else None,
            limits_path=Path(args.limits).resolve() if args.limits else None,
            checks_json=Path(args.checks_json).resolve() if args.checks_json else None,
            historical_checks_json=Path(args.historical_checks_json).resolve() if args.historical_checks_json else None,
            timeout_seconds=args.timeout_seconds,
        )
        result_path = Path(args.result) if args.result else Path(args.output) / "review-sharded-result.json"
        _write_result(result_path, result)
        if args.json:
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        else:
            print(
                f"sharded review: {result['completeness']} / {result['disposition']}; "
                f"{len(result['shards'])} shard(s); result={result_path}"
            )
        return 0 if result["completeness"] == "COMPLETE" else 1
    except (OSError, json.JSONDecodeError, ShardedReviewError, ValueError) as exc:
        message = str(exc) if isinstance(exc, ShardedReviewError) else "sharded review input is invalid"
        print(
            json.dumps({"error": message[:500], "exit_code": 2}, sort_keys=True)
            if args.json
            else f"pr-review: {message[:500]}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
