#!/usr/bin/env python3
"""Run one complete review per lens and merge the disjoint shard results.

The harness plans every configured lens over every changed unit in a single
run. For a large change that plan can exhaust the shared context or provider
budget and return partial coverage. This wrapper instead creates a temporary,
single-lens copy of the trusted profile, runs ``python -m pr_review_harness
review`` once per lens over the same immutable revisions, and merges the
results deterministically.

This module performs local process orchestration only. It does not call a
network API, execute target code, or publish a review; the only subprocess it
starts is the read-only review CLI. Missing, failed, partial, or unknown
shards never disappear and never become a clean approval.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

SCHEMA = "review-sharded-result.v1"
DEFAULT_LENSES = ("correctness", "tests", "maintainability")
DEFAULT_OUTPUT_NAME = "sharded-review.json"
DISPOSITIONS = frozenset({"APPROVE", "COMMENT", "REQUEST_CHANGES", "INCOMPLETE", "UNKNOWN", "FAILED"})
_COVERAGE_STATES = frozenset({"COMPLETE", "PARTIAL", "NOT_STARTED", "UNKNOWN"})
_LENS_FIELDS = (
    "required_lenses",
    "docs_lenses",
    "documentation_lenses",
    "default_lenses",
    "security_lenses",
)
_MAX_DIAGNOSTIC_CHARS = 600
ShardRunner = Callable[..., dict[str, Any]]


class ShardedReviewError(ValueError):
    """Invalid wrapper input or an unusable shard result."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _sha256(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: str | os.PathLike[str], label: str) -> dict[str, Any]:
    """Read a trusted JSON object without following a directory or non-regular file."""
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ShardedReviewError(f"cannot read {label} JSON") from exc
    if not isinstance(value, dict):
        raise ShardedReviewError(f"{label} must be a JSON object")
    return value


def resolve_lenses(profile: Mapping[str, Any], requested: str | None = None) -> list[str]:
    """Resolve the requested CSV or the profile's required lenses, preserving order."""
    if requested is not None:
        lenses = [item.strip() for item in requested.split(",") if item.strip()]
    else:
        configured = profile.get("required_lenses")
        lenses = list(configured) if isinstance(configured, list) and configured else list(DEFAULT_LENSES)
    if not lenses:
        raise ShardedReviewError("at least one review lens is required")
    lenses = list(dict.fromkeys(lenses))
    available = set()
    criteria = profile.get("review_criteria")
    if isinstance(criteria, Mapping):
        available.update(key for key in criteria if isinstance(key, str))
    for field in _LENS_FIELDS:
        values = profile.get(field)
        if isinstance(values, list):
            available.update(value for value in values if isinstance(value, str))
    if not available:
        available.update(DEFAULT_LENSES)
    unknown = [lens for lens in lenses if lens not in available]
    if unknown:
        supported = ", ".join(sorted(available)) or "<none>"
        raise ShardedReviewError(f"unsupported review lens: {', '.join(unknown)}; profile declares: {supported}")
    return lenses


def build_lens_profile(profile: Mapping[str, Any], lens: str) -> dict[str, Any]:
    """Return a profile copy whose only review lens is ``lens``.

    Required/docs/security/default lens lists and review criteria are filtered
    to the single lens. Risk rules are retained only when they explicitly name
    that lens; the retained rule is narrowed to it. Everything else needed by
    the planner (context, checks, policy, effects) is copied unchanged.
    """
    shard = copy.deepcopy(dict(profile))
    for field in _LENS_FIELDS:
        if field in shard:
            values = shard[field]
            if isinstance(values, list):
                shard[field] = [value for value in values if value == lens]
    shard["required_lenses"] = [lens]
    criteria = shard.get("review_criteria")
    if isinstance(criteria, Mapping):
        shard["review_criteria"] = {key: value for key, value in criteria.items() if key == lens}
    rules = shard.get("risk_rules")
    if isinstance(rules, list):
        filtered = []
        for rule in rules:
            if not isinstance(rule, Mapping):
                continue
            rule_lenses = rule.get("lenses")
            if isinstance(rule_lenses, list) and lens in rule_lenses:
                narrowed = dict(rule)
                narrowed["lenses"] = [lens]
                filtered.append(narrowed)
        shard["risk_rules"] = filtered
    return shard


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _resolve_output(path: str) -> Path:
    candidate = Path(path).expanduser()
    if candidate.suffix.lower() == ".json":
        return candidate
    return candidate / DEFAULT_OUTPUT_NAME


def _single_result(directory: Path) -> tuple[dict[str, Any], str]:
    files = sorted(candidate for candidate in directory.glob("*.json") if candidate.is_file())
    if len(files) != 1:
        raise ShardedReviewError(f"expected exactly one shard result, found {len(files)}")
    raw = files[0].read_bytes()
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ShardedReviewError("shard result is not valid JSON") from exc
    if not isinstance(result, dict):
        raise ShardedReviewError("shard result must be a JSON object")
    return result, hashlib.sha256(raw).hexdigest()


def _diagnostic(error: bytes | str | None) -> str:
    if isinstance(error, bytes):
        text = error.decode("utf-8", "replace")
    else:
        text = error or ""
    return " ".join(text.split())[:_MAX_DIAGNOSTIC_CHARS]


def _pythonpath(repo_root: Path) -> str:
    source = repo_root / "src"
    existing = os.environ.get("PYTHONPATH")
    return f"{source}{os.pathsep}{existing}" if existing else str(source)


def run_shard(
    lens: str,
    *,
    repo: str,
    base: str,
    head: str,
    profile_path: Path,
    provider_config: str | None,
    limits: str | None,
    mode: str | None,
    output_dir: Path,
    timeout_seconds: float,
    repo_root: Path,
) -> dict[str, Any]:
    """Run exactly one read-only review subprocess for a lens."""
    argv = [
        sys.executable,
        "-m",
        "pr_review_harness",
        "review",
        "--repo",
        repo,
        "--base",
        base,
        "--head",
        head,
        "--profile",
        str(profile_path),
        "--output",
        str(output_dir),
        "--effect-policy",
        "READ_ONLY",
    ]
    if provider_config:
        argv.extend(["--provider-config", provider_config])
    if limits:
        argv.extend(["--limits", limits])
    if mode:
        argv.extend(["--mode", mode])
    env = os.environ.copy()
    env["PYTHONPATH"] = _pythonpath(repo_root)
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"lens": lens, "exit_code": None, "error": "shard_timeout", "result": None, "result_sha256": None}
    except OSError:
        return {"lens": lens, "exit_code": None, "error": "shard_launch_failed", "result": None, "result_sha256": None}
    if completed.returncode != 0:
        return {
            "lens": lens,
            "exit_code": completed.returncode,
            "error": f"shard_exit_{completed.returncode}",
            "detail": _diagnostic(completed.stderr),
            "result": None,
            "result_sha256": None,
        }
    try:
        result, digest = _single_result(output_dir)
    except ShardedReviewError as exc:
        return {
            "lens": lens,
            "exit_code": 0,
            "error": str(exc),
            "detail": _diagnostic(completed.stderr),
            "result": None,
            "result_sha256": None,
        }
    return {"lens": lens, "exit_code": 0, "error": None, "result": result, "result_sha256": digest}


def _coverage(result: Mapping[str, Any]) -> str:
    value = result.get("coverage_state")
    return value if isinstance(value, str) and value in _COVERAGE_STATES else "UNKNOWN"


def _reasons(result: Mapping[str, Any], disposition: str, coverage: str) -> list[str]:
    reasons: list[str] = []
    if disposition not in {"APPROVE", "COMMENT", "REQUEST_CHANGES"}:
        reasons.append(f"shard_disposition_{disposition.lower()}")
    if coverage != "COMPLETE":
        reasons.append(f"shard_coverage_{coverage.lower()}")
    summary = result.get("completeness_summary")
    distribution = summary.get("reason_distribution") if isinstance(summary, Mapping) else None
    if isinstance(distribution, list):
        for row in distribution:
            code = row.get("canonical_code") if isinstance(row, Mapping) else None
            if isinstance(code, str) and code:
                reasons.append(f"coverage:{code}")
    budget = result.get("budget")
    breaches = budget.get("budget_breaches") if isinstance(budget, Mapping) else None
    if isinstance(breaches, list):
        reasons.extend(f"budget:{item}" for item in breaches if isinstance(item, str))
    return list(dict.fromkeys(reasons))


def _finding_key(finding: Mapping[str, Any]) -> str:
    path, title = finding.get("path"), finding.get("title")
    if isinstance(path, str) and isinstance(title, str) and (path or title):
        return f"path-title:{path}\x00{title}"
    finding_id = finding.get("finding_id")
    if isinstance(finding_id, str) and finding_id:
        return f"finding-id:{finding_id}"
    return f"finding-hash:{_sha256(finding)}"


def _gap_key(gap: Mapping[str, Any]) -> str:
    proposal_id = gap.get("proposal_id")
    if isinstance(proposal_id, str) and proposal_id:
        return f"proposal:{proposal_id}"
    reason = gap.get("reason_code")
    path = gap.get("path")
    if isinstance(reason, str) and isinstance(path, str):
        return f"reason-path:{reason}\x00{path}"
    return f"gap-hash:{_sha256(gap)}"


def _usage(shards: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    identities: dict[str, Any] = {}
    calls = 0
    calls_known = True
    billed: list[int] = []
    estimated: list[int] = []
    billed_known = True
    estimated_known = True
    for shard in shards:
        result = shard.get("result")
        if not isinstance(result, Mapping):
            calls_known = billed_known = estimated_known = False
            continue
        identity = result.get("provider_identity")
        if isinstance(identity, Mapping):
            identities[_sha256(identity)] = identity
        budget = result.get("budget")
        if not isinstance(budget, Mapping):
            calls_known = billed_known = estimated_known = False
            continue
        if isinstance(budget.get("provider_calls_reserved"), int):
            calls += budget["provider_calls_reserved"]
        else:
            calls_known = False
        known_bill = budget.get("cost_billing_known") is True
        known_estimate = budget.get("cost_estimate_known") is True
        billed_known = billed_known and known_bill
        estimated_known = estimated_known and known_estimate
        if known_bill and isinstance(budget.get("cost_billed_microunits"), int):
            billed.append(budget["cost_billed_microunits"])
        if known_estimate and isinstance(budget.get("cost_estimated_microunits"), int):
            estimated.append(budget["cost_estimated_microunits"])
    provider = {
        "identities": list(identities.values()),
        "provider_calls_reserved": calls if calls_known else "UNKNOWN",
    }
    cost = {
        "billed_microunits": sum(billed) if billed_known and billed else "UNKNOWN",
        "estimated_microunits": sum(estimated) if estimated_known and estimated else "UNKNOWN",
        "billing_known": bool(billed_known and billed),
        "estimate_known": bool(estimated_known and estimated),
    }
    return provider, cost


def merge_shards(
    lenses: Sequence[str],
    entries: Mapping[str, Mapping[str, Any]],
    *,
    repo: str,
    base: str,
    head: str,
    mode: str | None,
) -> dict[str, Any]:
    """Merge one entry per requested lens; a missing entry is an explicit failure."""
    shards: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_findings: set[str] = set()
    gaps: list[dict[str, Any]] = []
    seen_gaps: set[str] = set()
    incomplete_reasons: list[dict[str, Any]] = []
    merged_dispositions: list[str] = []
    complete = True
    for lens in lenses:
        entry = entries.get(lens)
        if entry is None:
            entry = {"lens": lens, "exit_code": None, "error": "missing_shard_result", "result": None}
        result = entry.get("result")
        result = result if isinstance(result, Mapping) else {}
        disposition = result.get("disposition")
        disposition = disposition if isinstance(disposition, str) and disposition in DISPOSITIONS else "UNKNOWN"
        coverage = _coverage(result)
        if entry.get("error"):
            disposition = "FAILED"
            coverage = "UNKNOWN"
        reasons = _reasons(result, disposition, coverage)
        if entry.get("error"):
            reasons.insert(0, str(entry["error"]))
        reasons = list(dict.fromkeys(reasons))
        shard_findings = result.get("findings")
        shard_findings = (
            [dict(item) for item in shard_findings if isinstance(item, Mapping)]
            if isinstance(shard_findings, list)
            else []
        )
        shard_gaps = result.get("context_gaps")
        shard_gaps = (
            [dict(item) for item in shard_gaps if isinstance(item, Mapping)] if isinstance(shard_gaps, list) else []
        )
        for finding in shard_findings:
            key = _finding_key(finding)
            if key not in seen_findings:
                seen_findings.add(key)
                findings.append(finding)
        for gap in shard_gaps:
            key = _gap_key(gap)
            if key not in seen_gaps:
                seen_gaps.add(key)
                gaps.append(gap)
        usable = not entry.get("error") and disposition in {"APPROVE", "COMMENT", "REQUEST_CHANGES"}
        if disposition in {"INCOMPLETE", "UNKNOWN", "FAILED"} or coverage != "COMPLETE":
            complete = False
        if not usable:
            complete = False
            incomplete_reasons.append(
                {"lens": lens, "reasons": reasons or [f"shard_disposition_{disposition.lower()}"]}
            )
        shard = {
            "lens": lens,
            "disposition": disposition,
            "coverage": coverage,
            "findings": shard_findings,
            "result_sha256": entry.get("result_sha256"),
            "exit_code": entry.get("exit_code"),
            "reasons": reasons,
        }
        if isinstance(entry.get("detail"), str) and entry["detail"]:
            shard["detail"] = entry["detail"]
        shards.append(shard)
        merged_dispositions.append(disposition)
    if any(item in {"INCOMPLETE", "UNKNOWN", "FAILED"} for item in merged_dispositions) or not complete:
        disposition = "INCOMPLETE"
    elif "REQUEST_CHANGES" in merged_dispositions:
        disposition = "REQUEST_CHANGES"
    elif "COMMENT" in merged_dispositions:
        disposition = "COMMENT"
    else:
        disposition = "APPROVE"
    provider, cost = _usage([entry for entry in entries.values() if isinstance(entry, Mapping)])
    return {
        "schema": SCHEMA,
        "created_at": _now(),
        "repo": repo,
        "base_sha": base,
        "head_sha": head,
        "mode": mode or "AUTO",
        "lenses": list(lenses),
        "shards": shards,
        "findings": findings,
        "context_gaps": gaps,
        "completeness": "COMPLETE" if complete and disposition != "INCOMPLETE" else "INCOMPLETE",
        "disposition": disposition,
        "incomplete_reasons": incomplete_reasons,
        "provider": provider,
        "cost": cost,
    }


def _timeout(limits_path: str | None) -> float:
    deadline = 300
    if limits_path:
        try:
            document = load_json(limits_path, "limits")
            value = document.get("deadline_seconds")
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                deadline = value
        except ShardedReviewError:
            pass
    return float(max(600, deadline * 3))


def run_sharded(
    config: Mapping[str, Any],
    *,
    shard_runner: ShardRunner | None = None,
) -> dict[str, Any]:
    """Prepare single-lens profiles, run each shard, and merge the results."""
    runner = shard_runner or run_shard
    profile = config["profile"]
    lenses = resolve_lenses(profile, config.get("lenses"))
    output = _resolve_output(str(config["output"]))
    repo_root = Path(__file__).resolve().parents[1]
    timeout_seconds = _timeout(config.get("limits"))
    entries: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="sharded-review-") as temporary:
        root = Path(temporary)
        for index, lens in enumerate(lenses):
            profile_path = root / f"profile-{index}-{lens}.json"
            _write_json(profile_path, build_lens_profile(profile, lens))
            shard_output = root / f"out-{index}-{lens}"
            shard_output.mkdir()
            try:
                entries[lens] = runner(
                    lens,
                    repo=config["repo"],
                    base=config["base"],
                    head=config["head"],
                    profile_path=profile_path,
                    provider_config=config.get("provider_config"),
                    limits=config.get("limits"),
                    mode=config.get("mode"),
                    output_dir=shard_output,
                    timeout_seconds=timeout_seconds,
                    repo_root=repo_root,
                )
            except Exception:
                entries[lens] = {
                    "lens": lens,
                    "exit_code": None,
                    "error": "shard_runner_failed",
                    "result": None,
                    "result_sha256": None,
                }
    combined = merge_shards(
        lenses,
        entries,
        repo=str(config["repo"]),
        base=str(config["base"]),
        head=str(config["head"]),
        mode=config.get("mode"),
    )
    _write_json(output, combined)
    combined["output_path"] = str(output)
    return combined


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sharded-review",
        description="Run one read-only review per lens and merge the shard results.",
        epilog=(
            "Example:\n"
            "  python scripts/sharded_review.py --repo ../target --base <sha> --head <sha> \\\n"
            "    --profile profiles/generic.json --provider-config provider.json \\\n"
            "    --limits limits.json --output artifacts/sharded --json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--repo", required=True, help="local Git repository or bare object repository")
    parser.add_argument("--base", required=True, help="immutable base revision")
    parser.add_argument("--head", required=True, help="immutable head revision")
    parser.add_argument("--profile", required=True, help="trusted external profile JSON")
    parser.add_argument("--provider-config", help="trusted provider configuration JSON")
    parser.add_argument("--limits", help="trusted finite limits JSON")
    parser.add_argument(
        "--output",
        required=True,
        help="combined result path (a .json path, or a directory for sharded-review.json)",
    )
    parser.add_argument("--lenses", help="comma-separated lenses; default: profile required_lenses")
    parser.add_argument("--mode", choices=["AUTO", "LIGHT", "FOCUSED", "DEEP"], help="review mode for every shard")
    parser.add_argument("--json", action="store_true", help="emit the combined result on stdout")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        profile = load_json(args.profile, "profile")
        combined = run_sharded(
            {
                "repo": args.repo,
                "base": args.base,
                "head": args.head,
                "profile": profile,
                "provider_config": args.provider_config,
                "limits": args.limits,
                "output": args.output,
                "lenses": args.lenses,
                "mode": args.mode,
            }
        )
    except (ShardedReviewError, OSError) as exc:
        message = str(exc).replace("\n", " ")[:500]
        if args.json:
            print(json.dumps({"error": message, "exit_code": 2}, sort_keys=True))
        print(f"sharded-review: {message}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(combined, sort_keys=True, separators=(",", ":")))
    else:
        print(
            f"sharded-review: {combined['disposition']} / {combined['completeness']} "
            f"across {len(combined['shards'])} lens shard(s); result: {combined['output_path']}"
        )
        for shard in combined["shards"]:
            print(f"  {shard['lens']}: {shard['disposition']} / {shard['coverage']}")
    return 0 if combined["completeness"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
