"""Local and GitHub Actions command line entry point."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .engine import EnginePreflightError
from .snapshot import SnapshotError, bind_repository_url, collect_snapshot, recent_commits

MAX_HISTORICAL_CHECKS_BYTES = 2_000_000
MAX_HISTORICAL_CHECK_RUNS = 2_000
TRUSTED_CAPTURE_WORKFLOW_REF = (
    "groktopus/codereview/.github/workflows/private-shadow-capture.yml@refs/heads/main"
)


class _ArgumentError(Exception):
    pass


class _ReviewRuntimeFailure(RuntimeError):
    """Sanitized runtime failure with an optional durable diagnostic artifact."""

    def __init__(self, diagnostic_artifact_path: str | None = None):
        super().__init__("review runtime failed")
        self.diagnostic_artifact_path = diagnostic_artifact_path


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise _ArgumentError(message)


class HistoricalFreshnessCheck:
    """Picklable historical-snapshot check without network freshness claims."""

    def __init__(self, expected_head_sha: str):
        self.expected_head_sha = expected_head_sha

    def __call__(self) -> dict:
        return {
            "freshness": "CURRENT",
            "freshness_basis": "HISTORICAL_SNAPSHOT",
            "expected_head_sha": self.expected_head_sha,
            "observed_head_sha": self.expected_head_sha,
        }


def _parser() -> argparse.ArgumentParser:
    p = _ArgumentParser(prog="pr-review", description="Evidence-led PR review harness")
    sub = p.add_subparsers(dest="command", required=True)
    review = sub.add_parser("review", help="review explicit immutable revisions")
    _common(review)
    review.add_argument("--base", help="base commit SHA or revision (required unless a PR/event input supplies it)")
    review.add_argument("--head", help="head commit SHA or revision (required unless a PR/event input supplies it)")
    review.add_argument("--github-pr", help="read current GitHub PR metadata, as owner/repository#number")
    review.add_argument("--mode", choices=["AUTO", "LIGHT", "FOCUSED", "DEEP"], default="AUTO")
    review.add_argument("--run-id")
    review.add_argument("--resume", action="store_true")
    review.add_argument("--event-file", help="GitHub Actions pull_request event JSON (read only)")
    review.add_argument("--effect-policy", choices=["READ_ONLY", "PUBLISH_REVIEW"], default="READ_ONLY")
    review.add_argument("--dry-run", action="store_true")
    review.add_argument("--prepare-only", action="store_true", help="snapshot and size exact primary requests without provider dispatch")
    review.add_argument(
        "--private-shadow-capture",
        metavar="DIR",
        help="opt in to a new private local exact-byte writer capture directory (not for Actions)",
    )
    review.add_argument(
        "--private-shadow-case-id",
        help="fixed corpus case ID for exported packets; requires --private-shadow-capture",
    )
    review.add_argument(
        "--max-claim-assessments",
        type=int,
        choices=range(5),
        default=0,
        metavar="0..4",
        help="run up to four optional TypeSafe claim assessments (requires --decision-config; default: disabled)",
    )
    recent = sub.add_parser("recent", help="review recent first-parent commit pairs")
    _common(recent)
    recent.add_argument("--count", type=int, default=5)
    recent.add_argument("--mode", choices=["AUTO", "LIGHT", "FOCUSED", "DEEP"], default="AUTO")
    recent.add_argument("--dry-run", action="store_true")
    publish = sub.add_parser(
        "publish",
        help="validate and preview a sealed GitHub PR review (live publication is unavailable)",
        epilog=(
            "Examples:\n"
            "  pr-review publish --result artifacts/run.json --publisher-config preview-policy.json --json\n\n"
            "Live publication currently fails closed: verified GitHub receipt adapters are not configured."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    publish.add_argument("--result", required=True, help="sealed durable review result JSON")
    publish.add_argument("--publisher-config", required=True, help="trusted repository/disposition preview policy JSON")
    publish.add_argument(
        "--dry-run", action="store_true", help="accepted for compatibility; publish is always preview-only"
    )
    publish.add_argument(
        "--authorize-publish",
        action="store_true",
        help="request live publication (currently unavailable without verified GitHub receipt adapters)",
    )
    publish.add_argument("--json", action="store_true", help="emit one JSON value on stdout")
    return p


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo", required=True, help="local Git repository or bare object repository")
    p.add_argument("--profile", required=True, help="external trusted profile JSON")
    p.add_argument("--provider-config", help="external provider configuration JSON")
    p.add_argument("--decision-config", help="external semantic decision provider configuration JSON")
    p.add_argument("--limits", help="external finite limits JSON (overrides documented defaults)")
    p.add_argument("--checks-json", help="versioned GitHub check-run evidence captured outside PR-controlled code")
    p.add_argument(
        "--historical-checks-json",
        help="captured check-run evidence for an explicit historical base/head pair; review command only",
    )
    p.add_argument("--output", default="artifacts", help="local output directory")
    p.add_argument("--json", action="store_true", help="emit a single JSON value on stdout")


def _load_json(path: str, label: str) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {label} JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("historical check evidence contains duplicate JSON keys")
        result[key] = value
    return result


def _validate_private_capture_target(capture_dir: str, output_dir: str) -> None:
    """Keep the opt-in local, or confine it to one trusted manual workflow."""
    if os.environ.get("GITHUB_ACTIONS", "").lower() != "true":
        return
    trusted = (
        os.environ.get("PR_REVIEW_TRUSTED_PRIVATE_CAPTURE") == "1"
        and os.environ.get("GITHUB_REPOSITORY") == "groktopus/codereview"
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_WORKFLOW_REF") == TRUSTED_CAPTURE_WORKFLOW_REF
        and re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")) is not None
    )
    runner_temp_value = os.environ.get("RUNNER_TEMP")
    if not trusted or not runner_temp_value:
        raise ValueError("private capture in Actions requires the trusted main-branch manual workflow")
    runner_temp = Path(runner_temp_value)
    requested = Path(capture_dir).expanduser()
    if not runner_temp.is_absolute() or not requested.is_absolute():
        raise ValueError("trusted private capture paths must be absolute")

    def contains_symlink(path: Path) -> bool:
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current = current / part
            if current.is_symlink():
                return True
        return False

    if contains_symlink(runner_temp) or not runner_temp.is_dir():
        raise ValueError("trusted private capture temp root is unavailable")
    temp_real = runner_temp.absolute()
    if (
        ".." in requested.parts or requested.parent.absolute() != temp_real
        or requested.exists() or contains_symlink(requested)
    ):
        raise ValueError("trusted private capture must be a new direct child of RUNNER_TEMP")
    output = Path(output_dir).expanduser().resolve()
    resolved = temp_real / requested.name
    if output == resolved or output.is_relative_to(resolved) or resolved.is_relative_to(output):
        raise ValueError("private capture and uploaded output directories must be separate")


def _reject_json_constant(_value: str) -> Any:
    raise ValueError("historical check evidence contains a non-finite JSON number")


def _parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("historical check evidence contains a non-finite JSON number")
    return parsed


def _validate_bounded_json_tree(value: Any) -> None:
    pending = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > 100_000 or depth > 64:
            raise ValueError("historical check evidence JSON structure exceeds limits")
        if isinstance(current, float) and not math.isfinite(current):
            raise ValueError("historical check evidence contains a non-finite JSON number")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)


def _load_historical_checks(path: str) -> dict:
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_HISTORICAL_CHECKS_BYTES + 1)
        if len(data) > MAX_HISTORICAL_CHECKS_BYTES:
            raise ValueError("historical check evidence exceeds the input byte limit")
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_json_float,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError("cannot read bounded historical check evidence JSON") from exc
    _validate_bounded_json_tree(value)
    if not isinstance(value, dict):
        raise ValueError("historical check evidence must be a JSON object")
    return value


def _limits() -> dict:
    return {
        "deadline_seconds": 300,
        "max_concurrent_scopes": 3,
        "max_provider_calls": 12,
        "max_retries_per_task": 0,
        "max_context_bytes": 300000,
        "max_input_bytes_per_task": 64000,
        "max_output_bytes_per_task": 16000,
        "max_output_bytes": 192000,
        "max_output_tokens": 1800,
        "max_context_retrievals": 8,
        "max_followup_tasks": 8,
    }


def _read_limits(args) -> dict:
    defaults = _limits()
    if not args.limits:
        limits = defaults
    else:
        supplied = _load_json(args.limits, "limits")
        unknown = set(supplied) - set(defaults) - {
            "max_cost_microunits",
            "max_snapshot_context_bytes",
            "schema_version",
        }
        if unknown:
            raise ValueError("unknown limits field")
        version = supplied.get("schema_version")
        if version is not None and version != "1.0":
            raise ValueError("unsupported limits schema version")
        limits = {**defaults, **supplied}
        limits.pop("schema_version", None)
    from .engine import validate_limits

    validate_limits(limits)
    return limits


def _validate_run_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
        raise ValueError("run_id must be 1 to 128 safe filename characters")
    return value


def _diagnostic_artifact_path(output_dir: str | Path, run_id: str) -> str | None:
    """Return only the derived, regular result JSON path; never inspect its contents."""
    try:
        validated_id = _validate_run_id(run_id)
        candidate = Path(output_dir) / f"{validated_id}.json"
        encoded = os.fsencode(str(candidate))
        if len(encoded) > 4096 or any(byte < 32 or byte == 127 for byte in encoded):
            return None
        if not stat.S_ISREG(candidate.lstat().st_mode):
            return None
        return str(candidate)
    except (OSError, TypeError, ValueError):
        return None


def _emit(args, value: Any) -> None:
    if args.json:
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    else:
        if isinstance(value, dict) and "summary" in value:
            print(value["summary"])
        else:
            print(json.dumps(value, indent=2, sort_keys=True))


def _event(args, base: str | None, head: str | None) -> dict | None:
    path = args.event_file or os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        return None
    try:
        obj = _load_json(path, "GitHub event")
        pr = obj["pull_request"]
        event_base = pr["base"]["sha"]
        event_head = pr["head"]["sha"]
        raw_number = obj["number"]
        if isinstance(raw_number, bool) or not isinstance(raw_number, int) or raw_number < 1:
            raise ValueError("invalid PR number")
        number = raw_number
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("GitHub event is not a pull_request event") from exc
    if (base and base != event_base) or (head and head != event_head):
        raise ValueError("requested revisions do not match the GitHub event")
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("GITHUB_REPOSITORY is required for event mode")
    return {
        "repository": repository,
        "pull_request_number": number,
        "event_id": os.environ.get("GITHUB_RUN_ID") or _sha256(Path(path).read_bytes())[:24],
        "base_sha": event_base,
        "head_sha": event_head,
    }


def _github_pr(args) -> dict | None:
    requested = getattr(args, "github_pr", None)
    if not requested:
        return None
    if args.event_file or os.environ.get("GITHUB_EVENT_PATH"):
        raise ValueError("--github-pr cannot be combined with a GitHub event")
    match = re.fullmatch(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#([1-9][0-9]*)", requested)
    if not match:
        raise ValueError("--github-pr must use owner/repository#number")
    from .github import GitHubPRAdapter

    event = GitHubPRAdapter().pull_request(match.group(1), int(match.group(2)))
    if (args.base and args.base != event["base_sha"]) or (args.head and args.head != event["head_sha"]):
        raise ValueError("requested revisions do not match the GitHub PR")
    return event


def _validate_historical_checks(profile: dict, document: dict, base: str | None, head: str | None) -> dict:
    """Validate captured check evidence without claiming current GitHub state."""
    if not isinstance(base, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", base):
        raise ValueError("historical check evidence requires an explicit full base SHA")
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
        raise ValueError("historical check evidence requires an explicit full head SHA")
    repository = profile.get("repository")
    if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("historical check evidence requires a trusted profile repository")
    if document.get("repository") != repository or document.get("head_sha") != head:
        raise ValueError("historical check evidence does not match the profile repository and selected head")
    pull_request_number = document.get("pull_request_number")
    if isinstance(pull_request_number, bool) or not isinstance(pull_request_number, int) or pull_request_number < 1:
        raise ValueError("historical check evidence requires a positive captured pull request number")
    captured_base = document.get("base_sha")
    if captured_base is not None and (
        not isinstance(captured_base, str)
        or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", captured_base)
        or captured_base != base
    ):
        raise ValueError("historical check evidence does not match the selected base")
    runs = document.get("runs")
    if not isinstance(runs, list) or len(runs) > MAX_HISTORICAL_CHECK_RUNS:
        raise ValueError("historical check evidence exceeds the bounded run count")
    bindings = []
    for binding in profile.get("required_checks", []) or []:
        if not isinstance(binding, dict):
            continue
        binding_id = binding.get("binding", binding.get("binding_id", binding.get("id", binding.get("check_id"))))
        if isinstance(binding_id, str) and binding_id:
            bindings.append({**binding, "id": binding_id})
    from .checks import ingest_check_runs

    ingest_check_runs(
        document,
        {"repository": repository, "pull_request_number": pull_request_number, "head_sha": head},
        bindings,
    )
    return {
        "repository": repository,
        "pull_request_number": pull_request_number,
        "base_sha": base,
        "head_sha": head,
        "check_document_sha256": _sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ),
    }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rebind_snapshot_evidence_references(snapshot: dict, old_to_new: dict[str, str]) -> None:
    """Rebind every structured evidence reference after changing snapshot identity.

    Fail closed on dangling references: filtering an ID would make the snapshot
    appear valid while silently dropping collected review context or an anchor.
    Content strings are deliberately left untouched.
    """
    evidence = snapshot.get("evidence")

    def rebind_ids(values: Any, field: str) -> list[str]:
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ValueError(f"snapshot {field} must be a list of evidence IDs")
        rebound = []
        for value in values:
            if value not in old_to_new:
                raise ValueError(f"snapshot {field} contains an unbound evidence ID")
            rebound.append(old_to_new[value])
        return rebound

    for unit in snapshot.get("inventory", []):
        for field in ("evidence_ids", "review_context_evidence_ids"):
            if field in unit:
                unit[field] = rebind_ids(unit[field], field)
        anchor = unit.get("file_level_location")
        if anchor is None:
            continue
        if not isinstance(anchor, dict) or anchor.get("kind") != "file":
            raise ValueError("snapshot file-level location is malformed")
        old_id = anchor.get("evidence_id")
        if not isinstance(old_id, str) or old_id not in old_to_new:
            raise ValueError("snapshot file-level location has an unbound evidence ID")
        new_id = old_to_new[old_id]
        record = evidence.get(new_id) if isinstance(evidence, dict) else None
        expected_revision = snapshot.get("base_sha") if anchor.get("side") == "BASE" else snapshot.get("head_sha")
        if (
            not isinstance(record, dict)
            or anchor.get("side") not in {"BASE", "HEAD"}
            or record.get("path") != anchor.get("path")
            or record.get("content_hash") != anchor.get("evidence_hash")
            or record.get("source_revision") != expected_revision
        ):
            raise ValueError("snapshot file-level location does not match its immutable evidence")
        anchor["evidence_id"] = new_id

    if "trusted_context_refs" in snapshot:
        snapshot["trusted_context_refs"] = rebind_ids(snapshot["trusted_context_refs"], "trusted_context_refs")


def _freshness(event: dict | None, expected_head: str):
    if event is None:
        return HistoricalFreshnessCheck(expected_head)
    from .github import GitHubFreshnessCheck

    return GitHubFreshnessCheck(event["repository"], event["pull_request_number"], expected_head)


def _claim_assessment_cap(args) -> int:
    cap = getattr(args, "max_claim_assessments", 0)
    if isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= 4:
        raise ValueError("max claim assessments must be between 0 and 4")
    if cap > 0 and not getattr(args, "decision_config", None):
        raise ValueError("positive max claim assessments requires --decision-config")
    return cap


def _claim_transport_from_config(config: dict):
    try:
        from .claim_transport import ClaimTransport

        return ClaimTransport.from_decision_config(config)
    except ImportError:
        raise ValueError("claim assessment adapter is unavailable") from None
    except Exception:
        raise ValueError("claim assessment decision configuration is invalid") from None


def _configs(args):
    profile = _load_json(args.profile, "profile")
    limits = _read_limits(args)
    provider_config = decision_config = None
    claim_assessor = None
    claim_cap = _claim_assessment_cap(args)
    try:
        from .providers import load_provider_config, make_decision_provider, make_provider

        if args.provider_config:
            provider_config = load_provider_config(args.provider_config)
        if args.decision_config:
            decision_config = load_provider_config(args.decision_config)
        claim_transport = _claim_transport_from_config(decision_config) if claim_cap > 0 else None
        provider = make_provider(provider_config) if provider_config else None
        decision_provider = make_decision_provider(decision_config) if decision_config else None
        if claim_transport is not None:
            from .claim_assessment import ClaimAssessmentAdapter

            claim_assessor = ClaimAssessmentAdapter(claim_transport, model=claim_transport.model)
    except ImportError:
        if args.provider_config or args.decision_config:
            raise ValueError("provider adapter is unavailable")
        provider = decision_provider = None
    except Exception:
        # Adapter exceptions are safe codes, but avoid surfacing configuration
        # contents or endpoint diagnostics through CLI errors.
        raise ValueError("provider configuration is invalid") from None
    return profile, limits, provider, decision_provider, claim_assessor


def _run_one(
    args,
    base: str,
    head: str,
    profile: dict,
    limits: dict,
    provider,
    decision_provider,
    run_id: str,
    event: dict | None = None,
    checks_document: dict | None = None,
    historical_check_identity: dict | None = None,
    claim_assessor=None,
    max_claim_assessments: int = 0,
) -> dict:
    capture_dir = getattr(args, "private_shadow_capture", None)
    capture_case_id = getattr(args, "private_shadow_case_id", None)
    if capture_case_id is not None and capture_dir is None:
        raise ValueError("private shadow case ID requires private shadow capture")
    if capture_dir and (
        getattr(args, "command", "review") != "review" or getattr(args, "resume", False)
        or getattr(args, "prepare_only", False) or getattr(args, "dry_run", False)
    ):
        raise ValueError("private shadow capture requires a fresh local non-resume review")
    if capture_dir:
        _validate_private_capture_target(capture_dir, args.output)
    if getattr(args, "effect_policy", "READ_ONLY") != "READ_ONLY":
        raise ValueError("PUBLISH_REVIEW is disabled")
    if (
        isinstance(max_claim_assessments, bool)
        or not isinstance(max_claim_assessments, int)
        or not 0 <= max_claim_assessments <= 4
    ):
        raise ValueError("max claim assessments must be between 0 and 4")
    if max_claim_assessments > 0 and claim_assessor is None:
        raise ValueError("positive max claim assessments requires a claim assessor")
    snapshot = collect_snapshot(args.repo, base, head, profile, limits)
    if event is not None:
        # Event identity is run provenance. Bind it before planning and refresh
        # evidence references so every reference remains tied to this snapshot.
        base_identity = snapshot["snapshot_id"]
        identity = {
            "base_snapshot_id": base_identity,
            "repository": event["repository"],
            "pull_request_number": event["pull_request_number"],
            "event_id": event["event_id"],
        }
        snapshot["snapshot_id"] = "snap-" + _sha256(json.dumps(identity, sort_keys=True).encode())[:24]
        old_to_new = {}
        for eid, item in list(snapshot["evidence"].items()):
            new_eid = (
                "ev-"
                + _sha256(
                    json.dumps(
                        {
                            "snapshot": snapshot["snapshot_id"],
                            "old_evidence_id": eid,
                            "content_hash": item["content_hash"],
                        },
                        sort_keys=True,
                    ).encode()
                )[:24]
            )
            item["evidence_id"] = new_eid
            item["snapshot_id"] = snapshot["snapshot_id"]
            old_to_new[eid] = new_eid
        snapshot["evidence"] = {old_to_new[eid]: item for eid, item in snapshot["evidence"].items()}
        _rebind_snapshot_evidence_references(snapshot, old_to_new)
        snapshot.update({k: event[k] for k in ("repository", "pull_request_number", "event_id")})
        if event.get("repository_url"):
            snapshot["repository_url"] = event["repository_url"]
        elif not snapshot.get("repository_url"):
            server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
            if re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?", server):
                snapshot["repository_url"] = f"{server}/{event['repository']}"
        if snapshot.get("repository_url"):
            bind_repository_url(snapshot, snapshot["repository_url"])
        if checks_document is not None:
            from .checks import ingest_check_runs

            bindings = []
            for binding in profile.get("required_checks", []) or []:
                if not isinstance(binding, dict):
                    continue
                binding_id = binding.get(
                    "binding", binding.get("binding_id", binding.get("id", binding.get("check_id")))
                )
                if isinstance(binding_id, str) and binding_id:
                    bindings.append({**binding, "id": binding_id})
            ingested = ingest_check_runs(checks_document, event, bindings)
            snapshot["external_check_results"] = ingested["results"]
            snapshot["external_check_evidence_hash"] = ingested["evidence_hash"]
            snapshot["evidence"].update(ingested["evidence"])
        snap_hash_payload = {k: v for k, v in snapshot.items() if k != "snapshot_hash"}
        snapshot["snapshot_hash"] = _sha256(
            json.dumps(snap_hash_payload, sort_keys=True, separators=(",", ":")).encode()
        )
    elif historical_check_identity is not None:
        # Bind the captured evidence to a deterministic historical snapshot.
        # This branch deliberately leaves ``event`` unset, so freshness stays
        # HISTORICAL_SNAPSHOT and no GitHub API adapter is constructed.
        base_identity = snapshot["snapshot_id"]
        identity = {
            "base_snapshot_id": base_identity,
            **historical_check_identity,
        }
        snapshot["snapshot_id"] = "snap-" + _sha256(json.dumps(identity, sort_keys=True).encode())[:24]
        old_to_new = {}
        for eid, item in list(snapshot["evidence"].items()):
            new_eid = (
                "ev-"
                + _sha256(
                    json.dumps(
                        {
                            "snapshot": snapshot["snapshot_id"],
                            "old_evidence_id": eid,
                            "content_hash": item["content_hash"],
                        },
                        sort_keys=True,
                    ).encode()
                )[:24]
            )
            item["evidence_id"] = new_eid
            item["snapshot_id"] = snapshot["snapshot_id"]
            old_to_new[eid] = new_eid
        snapshot["evidence"] = {old_to_new[eid]: item for eid, item in snapshot["evidence"].items()}
        _rebind_snapshot_evidence_references(snapshot, old_to_new)
        snapshot.update(
            {
                "repository": historical_check_identity["repository"],
                "pull_request_number": historical_check_identity["pull_request_number"],
            }
        )
        from .checks import ingest_check_runs

        bindings = []
        for binding in profile.get("required_checks", []) or []:
            if not isinstance(binding, dict):
                continue
            binding_id = binding.get("binding", binding.get("binding_id", binding.get("id", binding.get("check_id"))))
            if isinstance(binding_id, str) and binding_id:
                bindings.append({**binding, "id": binding_id})
        ingested = ingest_check_runs(
            checks_document,
            {
                "repository": historical_check_identity["repository"],
                "pull_request_number": historical_check_identity["pull_request_number"],
                "head_sha": historical_check_identity["head_sha"],
            },
            bindings,
        )
        snapshot["external_check_results"] = ingested["results"]
        snapshot["external_check_evidence_hash"] = ingested["evidence_hash"]
        snapshot["evidence"].update(ingested["evidence"])
        snapshot["freshness_basis"] = "HISTORICAL_SNAPSHOT"
        snap_hash_payload = {k: v for k, v in snapshot.items() if k != "snapshot_hash"}
        snapshot["snapshot_hash"] = _sha256(
            json.dumps(snap_hash_payload, sort_keys=True, separators=(",", ":")).encode()
        )
    else:
        snapshot["freshness_basis"] = "HISTORICAL_SNAPSHOT"
    if capture_dir:
        # Frozen case snapshots retain the collector's identity-independent
        # hash algorithm even when CLI freshness provenance was augmented.
        snap_hash_payload = {
            k: v for k, v in snapshot.items() if k not in {"snapshot_id", "snapshot_hash"}
        }
        snapshot["snapshot_hash"] = _sha256(
            json.dumps(snap_hash_payload, sort_keys=True, separators=(",", ":")).encode()
        )
    try:
        from .checks import GitHubCheckAdapter
        from .engine import run_review
        from .evidence import ContextRetriever
        from .planner import plan_review
    except ImportError as exc:
        raise RuntimeError("review core is unavailable") from exc
    plan = plan_review(snapshot, profile, args.mode)
    if getattr(args, "prepare_only", False):
        from . import contracts
        from .engine import _evidence_for, effective_task_input_ceiling, prepare_plan_tasks

        if provider is None or not callable(getattr(provider, "serialize_review_request", None)):
            raise ValueError("prepare-only requires an exact request serializer")
        effective_input_ceiling = effective_task_input_ceiling(limits, provider)
        prepared_tasks, skipped = prepare_plan_tasks(snapshot, plan, profile, limits, provider)
        primary = []
        for task in prepared_tasks:
            if task.get("task_kind") != "SPECIALIST_FINDINGS":
                continue
            evidence = _evidence_for(task, snapshot, effective_input_ceiling)
            body = provider.serialize_review_request(task, evidence, limits)
            request_descriptor = {
                "task_id": task["task_id"],
                "lens": task.get("lens"),
                "unit_ids": list(task.get("unit_ids", [])),
                "obligation_ids": list(task.get("obligation_ids", [task.get("obligation_id")])),
                "evidence_ids": [item.get("evidence_id") for item in evidence],
                "evidence_bindings": [
                    {
                        "evidence_id": item.get("evidence_id"),
                        "path": item.get("path"),
                        "source_revision": item.get("source_revision"),
                        "content_hash": item.get("content_hash"),
                        "source_kind": item.get("source_kind"),
                        "trust": item.get("trust"),
                        "content_bytes": len(item.get("content", "").encode("utf-8")) if isinstance(item.get("content"), str) else None,
                    }
                    for item in evidence
                ],
                "required_context_ids": list(task.get("required_context_ids", [])),
                "context_omissions": list(task.get("context_omissions", [])),
                "required_context_omissions": list(task.get("required_context_omissions", [])),
                "input_bytes": len(body),
                "input_sha256": _sha256(body),
                "admitted": len(body) <= effective_input_ceiling,
                "output_bytes_cap": min(provider.max_response_bytes, limits["max_output_bytes_per_task"]),
                "output_tokens_cap": min(provider.max_output_tokens, limits["max_output_tokens"]),
            }
            # Keep the exact engine-bound contract metadata visible in the
            # prepare receipt. Do not reconstruct bindings from the snapshot:
            # the serialized body and this descriptor must describe the same
            # planned request. Legacy requests retain their existing shape.
            if "request_input_contract" in task or "unit_evidence_bindings" in task:
                request_descriptor["request_input_contract"] = task.get("request_input_contract")
                request_descriptor["unit_evidence_bindings"] = task.get("unit_evidence_bindings")
            primary.append(request_descriptor)
        primary_calls = len(primary)
        summary_slots = 1 if decision_provider is not None else 0
        claim_slots = max_claim_assessments
        followup_slots = limits.get("max_followup_tasks", 0)
        semantic_adjudication_supported = (
            callable(getattr(provider, "adjudicate", None))
            and "SEMANTIC_ADJUDICATION" in provider.identity.get("supported_primitives", [])
        )
        candidate_adjudication_slots = (
            primary_calls * min(provider.max_output_items, contracts.MAX_ITEMS)
            if semantic_adjudication_supported else 0
        )
        remaining_call_slots_after_primary = max(0, limits["max_provider_calls"] - primary_calls)
        unit_ids = [u.get("unit_id") for u in snapshot.get("inventory", []) if isinstance(u, dict)]
        required_unit_count = len(set(unit_ids))
        covered_units = {uid for task in prepared_tasks if task.get("task_kind") == "SPECIALIST_FINDINGS" for uid in task.get("unit_ids", [])}
        admitted_obligation_ids = sorted({oid for task in prepared_tasks for oid in task.get("obligation_ids", [task.get("obligation_id")]) if oid})
        all_obligation_ids = sorted(o.get("obligation_id") for o in plan.get("coverage_obligations", []) if isinstance(o, dict) and o.get("obligation_id"))
        required_unadmitted = sorted(
            o.get("obligation_id") for o in plan.get("coverage_obligations", [])
            if isinstance(o, dict) and o.get("required") is True and o.get("obligation_id") not in admitted_obligation_ids
        )
        primary_scope_complete = not required_unadmitted
        primary_request_bytes = sum(request["input_bytes"] for request in primary)
        primary_context_fits = primary_request_bytes <= limits["max_context_bytes"]
        report = {
            "command": "review",
            "status": "PREPARED_ONLY",
            "disposition": None,
            "snapshot": {
                "snapshot_id": snapshot.get("snapshot_id"),
                "snapshot_hash": snapshot.get("snapshot_hash"),
                "evidence_index_sha256": _sha256(json.dumps(
                    [
                        {"evidence_id": eid, "content_hash": item.get("content_hash"), "path": item.get("path"), "source_revision": item.get("source_revision")}
                        for eid, item in sorted(snapshot.get("evidence", {}).items()) if isinstance(item, dict)
                    ], sort_keys=True, separators=(",", ":")
                ).encode()),
                "evidence_index": [
                    {
                        "evidence_id": eid,
                        "content_hash": item.get("content_hash"),
                        "path": item.get("path"),
                        "source_revision": item.get("source_revision"),
                        "source_kind": item.get("source_kind"),
                        "trust": item.get("trust"),
                        "content_bytes": len(item.get("content", "").encode("utf-8")) if isinstance(item.get("content"), str) else None,
                    }
                    for eid, item in sorted(snapshot.get("evidence", {}).items()) if isinstance(item, dict)
                ],
                "base_sha": snapshot.get("base_sha"),
                "head_sha": snapshot.get("head_sha"),
                "profile_version": profile.get("version", profile.get("profile_version")),
                "profile_file_sha256": _sha256(Path(args.profile).read_bytes()),
                "limits_sha256": _sha256(Path(args.limits).read_bytes()) if args.limits else None,
                "provider_identity_sha256": _sha256(json.dumps(provider.identity, sort_keys=True, separators=(",", ":")).encode()),
            },
            "scope": {
                "inventory_units": required_unit_count,
                "planned_obligations": len(plan.get("coverage_obligations", [])),
                "coverage_obligations": plan.get("coverage_obligations", []),
                "planned_tasks": len(plan.get("tasks", [])),
                "planned_task_scopes": [
                    {
                        "task_id": task.get("task_id"),
                        "task_kind": task.get("task_kind"),
                        "lens": task.get("lens"),
                        "unit_ids": list(task.get("unit_ids", [])),
                        "obligation_ids": list(task.get("obligation_ids", [task.get("obligation_id")])),
                        "required_context_ids": list(task.get("required_context_ids", [])),
                        "evidence_ids": list(task.get("evidence_ids", [])),
                    }
                    for task in plan.get("tasks", []) if isinstance(task, dict)
                ],
                "admitted_primary_tasks": len(primary),
                "admitted_obligation_ids": admitted_obligation_ids,
                "unadmitted_obligation_ids": sorted(set(all_obligation_ids) - set(admitted_obligation_ids)),
                "required_unadmitted_obligation_ids": required_unadmitted,
                "primary_scope_admission_complete": primary_scope_complete,
                "units_assigned_to_admitted_primary_tasks": len(covered_units),
                "uncovered_or_unadmitted_units": sorted(set(unit_ids) - covered_units),
                "skipped_units": list(skipped.values()),
                "required_context_gaps": [g for g in snapshot.get("gaps", []) if isinstance(g, dict) and g.get("required") is True],
                "optional_context_gaps": [g for g in snapshot.get("gaps", []) if isinstance(g, dict) and g.get("required") is not True],
            },
            "primary_requests": primary,
            "capacity": {
                "configured_max_provider_calls": limits["max_provider_calls"],
                "configured_max_context_bytes": limits["max_context_bytes"],
                "configured_max_input_bytes_per_task": limits["max_input_bytes_per_task"],
                "effective_max_input_bytes_per_task": effective_input_ceiling,
                "effective_snapshot_context_bytes": limits.get(
                    "max_snapshot_context_bytes", limits["max_context_bytes"]
                ),
                "exact_primary_call_demand": primary_calls,
                "exact_primary_serialized_input_bytes": primary_request_bytes,
                "primary_serialized_input_bytes_fit_context_cap": primary_context_fits,
                "configured_summary_advisory_call_slots": summary_slots,
                "configured_claim_assessment_call_slots": claim_slots,
                "configured_followup_task_slots": followup_slots,
                "semantic_adjudication_supported_by_primary_provider": semantic_adjudication_supported,
                "semantic_adjudication_calls_per_structurally_valid_candidate": 1,
                "candidate_count_for_semantic_adjudication": "UNKNOWN_UNTIL_PRIMARY_RESULTS",
                "max_candidate_items_per_primary_response": min(provider.max_output_items, contracts.MAX_ITEMS),
                "candidate_adjudication_candidate_upper_bound_before_call_cap": candidate_adjudication_slots,
                "remaining_global_call_slots_after_primary": remaining_call_slots_after_primary,
                "max_semantic_adjudication_calls_if_no_other_stage_uses_remaining_slots": min(
                    candidate_adjudication_slots, remaining_call_slots_after_primary
                ),
                "candidate_and_summary_request_sizes": "UNKNOWN_UNTIL_PRIMARY_RESULTS",
                "configured_optional_stage_slots_excluding_candidate_adjudication": summary_slots + claim_slots + followup_slots,
                "runtime_call_demand": "UNKNOWN_UNTIL_PRIMARY_RESULTS_AND_OPTIONAL_STAGE_ADMISSION",
                "overall_capacity": (
                    "PRIMARY_SCOPE_NOT_ADMITTED" if not primary_scope_complete
                    else "PRIMARY_CALL_DEMAND_EXCEEDS_CAP" if primary_calls > limits["max_provider_calls"]
                    else "PRIMARY_CONTEXT_DEMAND_EXCEEDS_CAP" if not primary_context_fits
                    else "UNKNOWN_RUNTIME_DEMAND_WITHIN_CAPPED_LEDGER"
                ),
                "fits_call_cap": None,
                "status": (
                    "PRIMARY_SCOPE_NOT_ADMITTED" if not primary_scope_complete
                    else "PRIMARY_DEMAND_EXCEEDS_CALL_CAP" if primary_calls > limits["max_provider_calls"]
                    else "PRIMARY_CONTEXT_DEMAND_EXCEEDS_CAP" if not primary_context_fits
                    else "DYNAMIC_STAGE_DEMAND_UNKNOWN"
                ),
            },
            "checks": {
                "historical_check_identity": historical_check_identity,
                "check_evidence_hash": snapshot.get("external_check_evidence_hash"),
                "check_results": snapshot.get("external_check_results", []),
            },
            "no_provider_calls": True,
            "no_target_code_execution": True,
        }
        return report
    output_dir = str(Path(args.output))
    review_kwargs = {}
    if claim_assessor is not None and max_claim_assessments > 0:
        review_kwargs.update(
            claim_assessor=claim_assessor,
            max_claim_assessments=max_claim_assessments,
        )
    try:
        result = run_review(
            snapshot,
            plan,
            profile,
            provider,
            decision_provider,
            limits,
            output_dir,
            run_id,
            resume=getattr(args, "resume", False),
            freshness_check=_freshness(event, snapshot["head_sha"]),
            check_adapter=GitHubCheckAdapter(),
            context_retriever=ContextRetriever(args.repo),
            private_capture_dir=capture_dir,
            private_capture_case_id=capture_case_id,
            **review_kwargs,
        )
    except EnginePreflightError:
        raise
    except Exception:
        # Once the review engine is entered, ValueError and SnapshotError can
        # describe runtime failures too. Keep their payload private and prevent
        # main() from misclassifying them as preflight rejections.
        raise _ReviewRuntimeFailure(_diagnostic_artifact_path(output_dir, run_id)) from None
    try:
        # Keep CLI result JSON-friendly and never expose provider configuration.
        result_path = Path(output_dir) / f"{run_id}.json"
        if not result_path.is_file():
            raise RuntimeError("review core returned without a durable result")
        result["artifact_path"] = str(result_path)
        result["snapshot_id"] = snapshot["snapshot_id"]
        from .engine import render_report

        report_path = Path(output_dir) / f"{run_id}.md"
        report = render_report(result)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{report_path.name}.", dir=report_path.parent)
    except Exception:
        raise _ReviewRuntimeFailure(_diagnostic_artifact_path(output_dir, run_id)) from None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(report)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, report_path)
    except Exception:
        raise _ReviewRuntimeFailure(_diagnostic_artifact_path(output_dir, run_id)) from None
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    result["report_path"] = str(report_path)
    return result


def _validate_publisher_config(config: dict) -> dict:
    allowed_keys = {
        "schema_version",
        "enabled",
        "allowed_repositories",
        "allowed_dispositions",
        "allowed_profile_versions",
        "trusted_result_root",
        "max_review_body_bytes",
    }
    if set(config) - allowed_keys or config.get("schema_version") != "1.0":
        raise ValueError("publish preview configuration schema is invalid")
    if "enabled" in config and not isinstance(config["enabled"], bool):
        raise ValueError("publish preview enabled flag is invalid")
    repositories = config.get("allowed_repositories")
    if (
        not isinstance(repositories, list)
        or not repositories
        or any(
            not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", item)
            for item in repositories
        )
    ):
        raise ValueError("publisher repository scope is invalid")
    dispositions = config.get("allowed_dispositions")
    if (
        not isinstance(dispositions, list)
        or not dispositions
        or any(
            not isinstance(item, str) or item not in {"APPROVE", "REQUEST_CHANGES", "COMMENT"} for item in dispositions
        )
    ):
        raise ValueError("publisher disposition scope is invalid")
    if "allowed_profile_versions" in config:
        profile_versions = config["allowed_profile_versions"]
        if (
            not isinstance(profile_versions, list)
            or not profile_versions
            or any(
                not isinstance(item, str) or not item or len(item.encode("utf-8")) > 128 for item in profile_versions
            )
        ):
            raise ValueError("publisher profile scope is invalid")
    if "trusted_result_root" in config:
        result_root = config["trusted_result_root"]
        if not isinstance(result_root, str) or not os.path.isabs(result_root):
            raise ValueError("trusted result root must be an absolute path")
        try:
            root_path = Path(result_root).resolve(strict=True)
        except OSError as exc:
            raise ValueError("trusted result root is unavailable") from exc
        if not root_path.is_dir():
            raise ValueError("trusted result root must be a directory")
    max_body = config.get("max_review_body_bytes", 60000)
    if isinstance(max_body, bool) or not isinstance(max_body, int) or not 1 <= max_body <= 60000:
        raise ValueError("publisher review body limit is invalid")
    return config


def _publish(args) -> tuple[int, dict]:
    """Render a stateless preview; live publication requires unavailable trusted capabilities."""
    from .publisher import PublicationRejected, preview_publication

    config = _load_json(args.publisher_config, "publisher configuration")
    config = _validate_publisher_config(config)
    try:
        result_path = Path(args.result).resolve(strict=True)
        if "trusted_result_root" in config:
            trusted_root = Path(config["trusted_result_root"]).resolve(strict=True)
            result_path.relative_to(trusted_root)
    except (OSError, ValueError) as exc:
        raise ValueError("review result is outside the configured artifact root") from exc
    if not result_path.is_file():
        raise ValueError("review result is not a regular file")
    result = _load_json(str(result_path), "review result")
    profile_version = result.get("project_profile_version")
    if "allowed_profile_versions" in config and profile_version not in config["allowed_profile_versions"]:
        raise ValueError("review profile is outside publisher authorization scope")
    request = preview_publication(result, config)
    if args.authorize_publish:
        raise PublicationRejected("stateless publication capability is unavailable")
    return 0, {
        "command": "publish",
        "status": "PREVIEW_ONLY",
        "dry_run": True,
        "live_effects_performed": False,
        "publication_capability": "UNAVAILABLE",
        "actor_identity": "NOT_CHECKED",
        "freshness": "NOT_CHECKED",
        "effect_store_accessed": False,
        "request": {
            **request,
            "review_payload": {
                **request["review_payload"],
                "body": request["review_payload"]["body"]
                + f"\n\n<!-- pr-review-harness:{request['idempotency_key']} -->",
            },
        },
    }


def _status(result: dict) -> str:
    return str(result.get("disposition", result.get("status", "UNKNOWN")))


def _public_error(exc: Exception) -> str:
    """Return a stable diagnostic without propagating arbitrary exception text."""
    if isinstance(exc, EnginePreflightError):
        return exc.reason
    if isinstance(exc, SnapshotError):
        return "snapshot_preflight_failed"
    if isinstance(exc, ValueError):
        message = str(exc)
        if message in {
            "requested revisions do not match the GitHub event",
            "requested revisions do not match the GitHub PR",
            "--github-pr must use owner/repository#number",
            "--github-pr cannot be combined with a GitHub event",
            "explicit base and head revisions are required without a PR/event input",
            "GitHub event is not a pull_request event",
            "GITHUB_REPOSITORY is required for event mode",
            "PUBLISH_REVIEW is disabled",
            "stateless publication capability is unavailable",
            "provider adapter is unavailable",
            "provider configuration is invalid",
            "cannot read profile JSON",
            "cannot read limits JSON",
        }:
            return message
        return "preflight_rejected"
    return "review_runtime_failed"


def main(argv=None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except _ArgumentError:
        json_mode = "--json" in (list(argv) if argv is not None else sys.argv[1:])
        if json_mode:
            print(json.dumps({"error": "invalid_arguments", "exit_code": 2}, separators=(",", ":")))
        else:
            print("pr-review: invalid arguments", file=sys.stderr)
        return 2
    try:
        if args.command == "publish":
            code, result = _publish(args)
            _emit(args, result)
            return code
        if getattr(args, "effect_policy", "READ_ONLY") != "READ_ONLY":
            raise ValueError("PUBLISH_REVIEW is disabled")
        claim_cap = _claim_assessment_cap(args)
        if getattr(args, "prepare_only", False):
            if args.command != "review" or args.dry_run:
                raise ValueError("--prepare-only is available only for a non-dry-run review")
            if args.github_pr or args.event_file or os.environ.get("GITHUB_EVENT_PATH"):
                raise ValueError("--prepare-only requires explicit historical revisions without a GitHub event")
            if not args.provider_config:
                raise ValueError("--prepare-only requires --provider-config for exact request sizing")
        if args.dry_run:
            if args.command == "recent" and not 1 <= args.count <= 100:
                raise ValueError("count must be between 1 and 100")
            if args.command == "review" and args.run_id:
                _validate_run_id(args.run_id)
            preview = {
                "command": args.command,
                "repository": os.path.realpath(args.repo),
                "profile_path": os.path.realpath(args.profile),
                "event_file": (getattr(args, "event_file", None) or os.environ.get("GITHUB_EVENT_PATH")),
                "provider_configured": bool(args.provider_config),
                "decision_provider_configured": bool(args.decision_config),
                "limits_path": os.path.realpath(args.limits) if args.limits else None,
                "checks_path": os.path.realpath(args.checks_json) if args.checks_json else None,
                "mode": args.mode,
                "effect_policy": "READ_ONLY",
            }
            if args.command == "review":
                preview.update(
                    {
                        "base": args.base,
                        "head": args.head,
                        "github_pr": args.github_pr,
                        "run_id": args.run_id,
                        "historical_checks_path": args.historical_checks_json,
                    }
                )
                if claim_cap > 0:
                    preview["max_claim_assessments"] = claim_cap
            else:
                preview.update({"count": args.count, "head": "HEAD"})
            _emit(args, preview)
            return 0
        profile, limits, provider, decision_provider, claim_assessor = _configs(args)
        if args.command == "review":
            if args.private_shadow_capture and (args.resume or args.prepare_only or args.dry_run):
                raise ValueError("private shadow capture is incompatible with resume, prepare-only, and dry-run")
            if args.private_shadow_capture:
                _validate_private_capture_target(args.private_shadow_capture, args.output)
            historical_check_identity = None
            if args.historical_checks_json:
                if args.checks_json:
                    raise ValueError("--checks-json and --historical-checks-json are mutually exclusive")
                if args.github_pr or args.event_file or os.environ.get("GITHUB_EVENT_PATH"):
                    raise ValueError("--historical-checks-json cannot be combined with a GitHub PR or event")
                event = None
                checks_document = _load_historical_checks(args.historical_checks_json)
                historical_check_identity = _validate_historical_checks(profile, checks_document, args.base, args.head)
            else:
                event = _github_pr(args) or _event(args, args.base, args.head)
            if event is not None:
                args.base, args.head = event["base_sha"], event["head_sha"]
            if not args.base or not args.head:
                raise ValueError("explicit base and head revisions are required without a PR/event input")
            if not args.historical_checks_json:
                if args.checks_json:
                    if event is None:
                        raise ValueError("--checks-json requires a GitHub PR or event identity")
                    checks_document = _load_json(args.checks_json, "check evidence")
                elif event:
                    from .checks import make_check_runs_document
                    from .github import GitHubPRAdapter

                    try:
                        external = GitHubPRAdapter().check_runs(event["repository"], event["head_sha"])
                        checks_document = make_check_runs_document(
                            event["repository"],
                            event["pull_request_number"],
                            event["head_sha"],
                            external["runs"],
                            complete=external["complete"],
                        )
                    except Exception:
                        # A failed read remains UNKNOWN evidence for each required
                        # binding; it cannot be converted into a passing check.
                        checks_document = make_check_runs_document(
                            event["repository"],
                            event["pull_request_number"],
                            event["head_sha"],
                            [],
                            complete=False,
                        )
                else:
                    checks_document = None
            run_id = args.run_id or str(uuid.uuid4())
            _validate_run_id(run_id)
            result = _run_one(
                args,
                args.base,
                args.head,
                profile,
                limits,
                provider,
                decision_provider,
                run_id,
                event,
                checks_document,
                historical_check_identity,
                claim_assessor,
                claim_cap,
            )
            _emit(args, result)
            return 0
        if args.historical_checks_json:
            raise ValueError("--historical-checks-json requires explicit review base and head revisions")
        pairs = recent_commits(args.repo, args.count)
        runs = []
        for pair in pairs:
            run_id = str(uuid.uuid4())
            try:
                result = _run_one(
                    args, pair["base"], pair["head"], profile, limits, provider, decision_provider, run_id
                )
                runs.append(
                    {
                        "run_id": run_id,
                        "base": pair["base"],
                        "head": pair["head"],
                        "subject": pair["subject"],
                        "disposition": _status(result),
                        "artifact_path": result["artifact_path"],
                    }
                )
            except Exception as exc:
                diagnostic_path = (
                    exc.diagnostic_artifact_path
                    if isinstance(exc, _ReviewRuntimeFailure)
                    else None
                )
                runs.append(
                    {
                        "run_id": run_id,
                        "base": pair["base"],
                        "head": pair["head"],
                        "subject": pair["subject"],
                        "disposition": "FAILED",
                        "error": _public_error(exc),
                        **({"diagnostic_artifact_path": diagnostic_path} if diagnostic_path else {}),
                    }
                )
                if diagnostic_path and not args.json:
                    print(
                        f"pr-review: review_runtime_failed; diagnostic artifact (not a completed report): {diagnostic_path}",
                        file=sys.stderr,
                    )
        _emit(
            args,
            {
                "command": "recent",
                "runs": runs,
                "summary": f"Completed {sum(r['disposition'] != 'FAILED' for r in runs)} of {len(runs)} historical review runs.",
            },
        )
        return 0 if runs and all(r["disposition"] != "FAILED" for r in runs) else 1
    except EnginePreflightError as exc:
        _emit_error(args, 2, exc.reason)
        return 2
    except (ValueError, SnapshotError) as exc:
        _emit_error(args, 2, _public_error(exc))
        return 2
    except Exception as exc:
        diagnostic = exc.diagnostic_artifact_path if isinstance(exc, _ReviewRuntimeFailure) else None
        _emit_error(args, 1, _public_error(exc), diagnostic_artifact_path=diagnostic)
        return 1


def _emit_error(args, code: int, message: str, *, diagnostic_artifact_path: str | None = None) -> None:
    safe = message.replace("\n", " ")[:500]
    payload = {"error": safe, "exit_code": code}
    if code == 1 and diagnostic_artifact_path:
        payload["diagnostic_artifact_path"] = diagnostic_artifact_path
    if getattr(args, "json", False):
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    else:
        suffix = (
            f"; diagnostic artifact (not a completed report): {diagnostic_artifact_path}"
            if code == 1 and diagnostic_artifact_path
            else ""
        )
        print(f"pr-review: {safe}{suffix}", file=sys.stderr)
