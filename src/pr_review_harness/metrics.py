"""Versioned per-run summaries and local cross-run aggregation.

The review engine already writes a rich result artifact for every run.  That
artifact answers "what happened in this run", but it is too large and too
run-specific to aggregate.  This module defines one compact, versioned record
derived from the parts of the result that are safe to retain across runs:

``review-run-summary.v1``
    Contract/profile identity, obligation completion and reasons, provider
    calls, tokens, stage latency, cost and its basis, terminal state,
    freshness, terminal timestamps, and the run id.

``review-run-metrics.v1``
    Local aggregation over stored summaries with explicit denominators and
    missing-data counts.  It is produced by ``pr-review stats`` and exported
    as JSON lines for external dashboards.

Two rules are absolute.  Unknown values stay unknown: a missing token count or
an unbilled provider call is ``None``/``UNKNOWN``, never ``0``.  And the record
never contains prompts, source text, findings, or evidence content; identity is
hashes, revisions, counts, and enum states only.

This layer is read-only.  It opens stored JSON files, computes an in-memory
aggregate, and optionally writes that aggregate or a JSON-lines export.  It
does not dispatch providers, contact a network service, or mutate results.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .completeness import SUMMARY_SCHEMA as COMPLETENESS_SUMMARY_SCHEMA
from .completeness import TAXONOMY_VERSION
from .completeness import summary_from_result as _completeness_summary_from_result

RUN_SUMMARY_SCHEMA = "review-run-summary.v1"
RUN_METRICS_SCHEMA = "review-run-metrics.v1"

TOKEN_FIELDS = ("prompt_tokens", "completion_tokens", "input_tokens", "output_tokens", "total_tokens")
COMPLETION_STATES = ("COMPLETE", "PARTIAL", "NOT_STARTED", "UNKNOWN")

# Intentionally conservative: an estimate is only "known" when the ledger says
# every provider settlement carried one.  A partial sum is not a total and is
# reported as unknown rather than silently understated.
_ESTIMATE_KNOWN = "PROVIDER_REPORTED_ESTIMATE"
_BILLED_KNOWN = "PROVIDER_REPORTED_BILLED"
_BASIS_UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Small value helpers


def _nonnegative_int(value: Any) -> int | None:
    if type(value) is int and value >= 0:
        return value
    return None


def _count(value: Any) -> int:
    number = _nonnegative_int(value)
    return 0 if number is None else number


def _nonnegative_number(value: Any) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0:
        return None
    return round(number, 2) if isinstance(value, float) else value


def _finite_number(value: Any) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return value


def _ratio_value(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0 or number > 1:
        return None
    return round(number, 6)


def _share(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 6)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _component(contracts: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    return _mapping(contracts.get(key))


def _component_field(contracts: Mapping[str, Any], key: str, field: str) -> str | None:
    value = _component(contracts, key).get(field)
    return value if isinstance(value, str) and value else None


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


# ---------------------------------------------------------------------------
# Run-summary record


def build_run_summary(result: Mapping[str, Any]) -> dict[str, Any]:
    """Derive one ``review-run-summary.v1`` record from a stored result.

    Every field is recomputed from the result so a stale embedded summary
    cannot change what the record means.  ``completeness_summary`` is used when
    present; otherwise it is rebuilt from the coverage ledger, which keeps old
    results aggregatable.
    """

    if not isinstance(result, Mapping):
        raise ValueError("result must be an object")
    coverage = result.get("coverage_ledger")
    if not isinstance(coverage, list):
        raise ValueError("result must contain a coverage_ledger array")

    completeness = result.get("completeness_summary")
    if not isinstance(completeness, Mapping):
        completeness = _completeness_summary_from_result(result)

    obligations = {
        key: _count(completeness.get(key))
        for key in (
            "required_total",
            "complete",
            "partial",
            "not_started",
            "unknown_state",
            "incomplete_total",
            "not_applicable",
            "non_required",
            "ledger_total",
        )
    }
    obligations["zero_obligations"] = bool(completeness.get("zero_obligations", False))

    reason_codes: list[dict[str, Any]] = []
    for item in completeness.get("reason_distribution") or []:
        if not isinstance(item, Mapping):
            continue
        code = _string(item.get("canonical_code"))
        if code is None:
            continue
        states = _mapping(item.get("states"))
        reason_codes.append(
            {
                "canonical_code": code,
                "obligations": _count(item.get("obligations")),
                "share_of_incomplete": _ratio_value(item.get("share_of_incomplete")),
                "share_of_required": _ratio_value(item.get("share_of_required")),
                "states": {state: _count(states.get(state)) for state in COMPLETION_STATES},
            }
        )
    reason_codes.sort(key=lambda row: (-row["obligations"], row["canonical_code"]))

    budget = _mapping(result.get("budget"))
    observability = _mapping(budget.get("provider_observability"))
    stages = {
        str(name): _mapping(row)
        for name, row in _mapping(observability.get("stages")).items()
        if isinstance(name, str) and isinstance(row, Mapping)
    }
    has_observability = bool(observability)
    calls_reserved = _nonnegative_int(budget.get("provider_calls_reserved"))
    if has_observability:
        settled_calls = sum(_count(row.get("settled_calls")) for row in stages.values())
        retries = _nonnegative_int(observability.get("retry_calls"))
        tool_calls = _nonnegative_int(observability.get("tool_calls_reserved"))
        attempted = sum(_count(row.get("request_attempted")) for row in stages.values())
        not_attempted = sum(_count(row.get("request_not_attempted")) for row in stages.values())
        attempt_unknown = sum(_count(row.get("request_attempt_unknown")) for row in stages.values())
    else:
        # Old results can have a call ledger without the observation receipts.
        settled_calls = None
        retries = None
        tool_calls = None
        attempted = None
        not_attempted = None
        attempt_unknown = None

    token_fields: dict[str, dict[str, Any]] = {}
    for field in TOKEN_FIELDS:
        reported_count = 0
        reported_sum = 0
        for row in stages.values():
            values = _mapping(_mapping(row.get("usage_fields")).get(field))
            reported_count += _count(values.get("reported_count"))
            reported_sum += _count(values.get("reported_sum"))
        token_fields[field] = {
            "reported_sum": reported_sum if reported_count > 0 else None,
            "reported_count": reported_count,
            "unknown_count": None if calls_reserved is None else max(0, calls_reserved - reported_count),
            "denominator_calls": calls_reserved,
        }

    if has_observability:
        usage_known = sum(_count(row.get("usage_known")) for row in stages.values())
        usage_partial = sum(_count(row.get("usage_partial")) for row in stages.values())
        usage_unknown = sum(_count(row.get("usage_unknown")) for row in stages.values())
    else:
        usage_known = 0
        usage_partial = 0
        usage_unknown = calls_reserved

    latency_stages: dict[str, dict[str, Any]] = {}
    for stage, row in stages.items():
        call_known = _count(row.get("call_elapsed_known"))
        http_known = _count(row.get("http_elapsed_known"))
        latency_stages[stage] = {
            "calls": _count(row.get("provider_calls_reserved")),
            "call_elapsed_ms_sum": _nonnegative_number(row.get("call_elapsed_ms_sum")) if call_known else None,
            "call_elapsed_known": call_known,
            "http_elapsed_ms_sum": _nonnegative_number(row.get("http_elapsed_ms_sum")) if http_known else None,
            "http_elapsed_known": http_known,
            "retries": _nonnegative_int(row.get("retry_calls")),
        }

    estimate_known = budget.get("cost_estimate_known") is True
    estimate_value = _nonnegative_int(budget.get("cost_estimated_microunits"))
    if not estimate_known or estimate_value is None:
        estimate_known, estimate_value = False, None
    billing_known = budget.get("cost_billing_known") is True
    billing_value = _nonnegative_int(budget.get("cost_billed_microunits"))
    if not billing_known or billing_value is None:
        billing_known, billing_value = False, None

    contracts = _mapping(result.get("effective_contracts"))
    freshness_details = _mapping(result.get("freshness_details"))
    freshness_basis = _string(freshness_details.get("freshness_basis"))
    pull_request_number = result.get("pull_request_number")
    if type(pull_request_number) is not int:
        pull_request_number = None

    summary: dict[str, Any] = {
        "schema": RUN_SUMMARY_SCHEMA,
        "identity": {
            "run_id": _string(result.get("run_id")),
            "repository": _string(result.get("repository")),
            "pull_request_number": pull_request_number,
            "snapshot_id": _string(result.get("snapshot_id")),
            "base_sha": _string(result.get("base_sha")),
            "head_sha": _string(result.get("head_sha")),
        },
        "contract": {
            "result_version": _string(result.get("contract_version")),
            "registration": _string(contracts.get("registration")),
            "registry_name": _component_field(contracts, "registry", "name"),
            "registry_version": _component_field(contracts, "registry", "version"),
            "registry_sha256": _component_field(contracts, "registry", "sha256"),
            "review_contract_name": _component_field(contracts, "review_contract", "name"),
            "review_contract_version": _component_field(contracts, "review_contract", "version"),
            "profile_name": _component_field(contracts, "profile", "name"),
            "profile_version": _component_field(contracts, "profile", "version"),
            "limits_name": _component_field(contracts, "limits", "name"),
            "limits_version": _component_field(contracts, "limits", "version"),
        },
        "profile": {
            "project_profile_version": _string(result.get("project_profile_version")),
        },
        "run": {
            "created_at": _string(result.get("created_at")),
            "completed_at": _string(result.get("completed_at")),
            "terminal_state": _string(result.get("disposition")),
            "coverage_state": _string(result.get("coverage_state")),
            "freshness": {
                "state": _string(result.get("freshness")) or "UNKNOWN",
                "basis": freshness_basis,
            },
        },
        "obligations": obligations,
        "completion": {
            "completeness_schema": COMPLETENESS_SUMMARY_SCHEMA,
            "taxonomy_version": _string(completeness.get("taxonomy_version")) or TAXONOMY_VERSION,
            "complete_ratio": _ratio_value(completeness.get("complete_ratio")),
            "resolved_ratio": _ratio_value(completeness.get("resolved_ratio")),
            "reason_distribution_denominator": _count(completeness.get("reason_distribution_denominator")),
            "unclassified_obligations": _count(completeness.get("unclassified_obligations")),
        },
        "reason_codes": reason_codes,
        "providers": {
            "calls_reserved": calls_reserved,
            "calls_settled": settled_calls,
            "retries": retries,
            "tool_calls_reserved": tool_calls,
            "request_attempted": attempted,
            "request_not_attempted": not_attempted,
            "request_attempt_unknown": attempt_unknown,
        },
        "tokens": {
            "denominator_calls": calls_reserved,
            "usage_states": {
                "known_calls": usage_known,
                "partial_calls": usage_partial,
                "unknown_calls": usage_unknown,
            },
            "fields": token_fields,
        },
        "latency": {
            "run_elapsed_ms": _nonnegative_number(result.get("run_elapsed_ms")),
            "by_stage": latency_stages,
        },
        "cost": {
            "currency": None,
            "reserved_microunits": _nonnegative_int(budget.get("cost_reserved_microunits")),
            "limit_microunits": _nonnegative_int(budget.get("cost_limit_microunits")),
            "estimate": {
                "microunits": estimate_value,
                "known": estimate_known,
                "basis": _ESTIMATE_KNOWN if estimate_known else _BASIS_UNKNOWN,
            },
            "billing": {
                "microunits": billing_value,
                "known": billing_known,
                "basis": _BILLED_KNOWN if billing_known else _BASIS_UNKNOWN,
            },
        },
    }
    return summary


def summary_is_well_formed(summary: Any, result: Mapping[str, Any] | None = None) -> bool:
    """Structural check used before trusting an embedded record.

    This is not a substitute for the published JSON Schema, but it rejects
    truncated/foreign records so aggregation rebuilds from the result instead
    of contributing arbitrary or zero-valued fields.
    """

    if not isinstance(summary, Mapping) or summary.get("schema") != RUN_SUMMARY_SCHEMA:
        return False
    identity = summary.get("identity")
    run = summary.get("run")
    obligations = summary.get("obligations")
    tokens = summary.get("tokens")
    latency = summary.get("latency")
    cost = summary.get("cost")
    if not (
        isinstance(identity, Mapping)
        and isinstance(identity.get("run_id"), str)
        and identity["run_id"]
        and isinstance(run, Mapping)
        and isinstance(run.get("terminal_state"), str)
        and isinstance(obligations, Mapping)
        and isinstance(tokens, Mapping)
        and isinstance(tokens.get("fields"), Mapping)
        and isinstance(latency, Mapping)
        and isinstance(cost, Mapping)
        and isinstance(cost.get("estimate"), Mapping)
        and isinstance(cost.get("billing"), Mapping)
    ):
        return False
    for key in (
        "required_total",
        "complete",
        "partial",
        "not_started",
        "unknown_state",
        "not_applicable",
        "incomplete_total",
    ):
        value = obligations.get(key)
        if not isinstance(value, int) or value < 0:
            return False
    if result is not None:
        if result.get("run_id") and identity["run_id"] != result.get("run_id"):
            return False
        ledger = result.get("coverage_ledger")
        if isinstance(ledger, list):
            required = sum(
                1 for row in ledger if isinstance(row, Mapping) and row.get("required", True) is not False
            )
            if obligations["required_total"] != required:
                return False
    return True


def summary_from_result(result: Mapping[str, Any]) -> dict[str, Any]:
    """Return the embedded summary when valid, else derive a fresh one.

    Results that still carry a coverage ledger are always rebuilt so a stale or
    foreign embedded record (for example after resume) cannot be reused.
    """

    embedded = result.get("run_summary") if isinstance(result, Mapping) else None
    if not isinstance(result.get("coverage_ledger"), list) and summary_is_well_formed(embedded, result):
        return dict(embedded)
    return build_run_summary(result)


# ---------------------------------------------------------------------------
# Input collection and windowing


def read_results(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    """Read stored result JSON files without mutating or normalizing them."""

    results: list[dict[str, Any]] = []
    for path in paths:
        location = Path(path)
        try:
            raw = location.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"cannot read result: {location}") from exc
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"result is not valid JSON: {location}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"result must be a JSON object: {location}")
        results.append(value)
    return results


def summarize_results(results: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Build summaries and count whether each came from the result artifact."""

    summaries: list[dict[str, Any]] = []
    embedded = 0
    derived = 0
    for result in results:
        embedded_summary = result.get("run_summary")
        if not isinstance(result.get("coverage_ledger"), list) and summary_is_well_formed(
            embedded_summary, result
        ):
            summaries.append(dict(embedded_summary))
            embedded += 1
        else:
            summaries.append(build_run_summary(result))
            derived += 1
    return summaries, {"embedded": embedded, "derived": derived}


def parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp into an aware UTC datetime."""

    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def filter_run_summaries(
    summaries: Sequence[Mapping[str, Any]],
    *,
    since: str | None = None,
    until: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Apply an inclusive ``created_at`` window and count exclusions.

    A run with no trustworthy ``created_at`` cannot be proven to belong to a
    requested window, so it is excluded and counted.  Without a window it is
    included and counted as missing-data instead.
    """

    since_time = parse_timestamp(since) if since is not None else None
    if since is not None and since_time is None:
        raise ValueError("invalid --since timestamp")
    until_time = parse_timestamp(until) if until is not None else None
    if until is not None and until_time is None:
        raise ValueError("invalid --until timestamp")

    selected: list[dict[str, Any]] = []
    excluded = {"before_since": 0, "after_until": 0, "missing_created_at": 0}
    windowed = since is not None or until is not None
    for summary in summaries:
        created = parse_timestamp(_mapping(summary.get("run")).get("created_at"))
        if created is None:
            if windowed:
                excluded["missing_created_at"] += 1
                continue
            selected.append(dict(summary))
            continue
        if since_time is not None and created < since_time:
            excluded["before_since"] += 1
            continue
        if until_time is not None and created > until_time:
            excluded["after_until"] += 1
            continue
        selected.append(dict(summary))
    return selected, excluded


# ---------------------------------------------------------------------------
# Aggregation


def _percentile(values: Sequence[float | int], quantile: float) -> float | int | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(quantile * len(ordered)))
    return round(ordered[rank - 1], 2)


def _sum_known(values: Iterable[int | None]) -> tuple[int | None, int, int]:
    total = 0
    known = 0
    missing = 0
    for value in values:
        number = _nonnegative_int(value)
        if number is None:
            missing += 1
            continue
        total += number
        known += 1
    return (total if known else None), known, missing


def aggregate_run_summaries(
    summaries: Sequence[Mapping[str, Any]],
    *,
    since: str | None = None,
    until: str | None = None,
    generated_at: str | None = None,
    excluded: Mapping[str, int] | None = None,
    input_total: int | None = None,
    summary_sources: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Aggregate selected run summaries with explicit denominators.

    Counts are obligation-weighted where the denominator is obligations and
    run-weighted where the denominator is runs.  Every ratio carries the
    denominator it used, and every optional observation carries ``n``.
    """

    excluded_counts = {
        "before_since": _count(_mapping(excluded).get("before_since")),
        "after_until": _count(_mapping(excluded).get("after_until")),
        "missing_created_at": _count(_mapping(excluded).get("missing_created_at")),
    }
    excluded_total = sum(excluded_counts.values())
    included = len(summaries)
    total = input_total if type(input_total) is int and input_total >= included else included + excluded_total

    obligations = {
        key: sum(_count(_mapping(summary.get("obligations")).get(key)) for summary in summaries)
        for key in (
            "required_total",
            "complete",
            "partial",
            "not_started",
            "unknown_state",
            "incomplete_total",
            "not_applicable",
        )
    }
    zero_obligation_runs = sum(
        1 for summary in summaries if _mapping(summary.get("obligations")).get("zero_obligations") is True
    )
    runs_with_required = sum(
        1 for summary in summaries if _count(_mapping(summary.get("obligations")).get("required_total")) > 0
    )
    runs_fully_complete = 0
    for summary in summaries:
        row = _mapping(summary.get("obligations"))
        required = _count(row.get("required_total"))
        if required > 0 and _count(row.get("complete")) == required:
            runs_fully_complete += 1

    completion = {
        "required_obligations_total": obligations["required_total"],
        "complete_obligations": obligations["complete"],
        "partial_obligations": obligations["partial"],
        "not_started_obligations": obligations["not_started"],
        "unknown_state_obligations": obligations["unknown_state"],
        "incomplete_obligations_total": obligations["incomplete_total"],
        "not_applicable_obligations": obligations["not_applicable"],
        "complete_ratio_by_obligations": _share(obligations["complete"], obligations["required_total"]),
        "resolved_ratio_by_obligations": _share(
            obligations["complete"] + obligations["partial"], obligations["required_total"]
        ),
        "runs_with_required_obligations": runs_with_required,
        "runs_fully_complete": runs_fully_complete,
        "completion_rate_by_runs": _share(runs_fully_complete, runs_with_required),
        "runs_with_zero_obligations": zero_obligation_runs,
    }

    reasons: dict[str, dict[str, Any]] = {}
    for summary in summaries:
        for item in summary.get("reason_codes") or []:
            if not isinstance(item, Mapping):
                continue
            code = _string(item.get("canonical_code"))
            if code is None:
                continue
            bucket = reasons.setdefault(
                code,
                {
                    "canonical_code": code,
                    "obligations": 0,
                    "runs_affected": 0,
                    "states": {state: 0 for state in COMPLETION_STATES},
                },
            )
            bucket["obligations"] += _count(item.get("obligations"))
            bucket["runs_affected"] += 1
            states = _mapping(item.get("states"))
            for state in COMPLETION_STATES:
                bucket["states"][state] += _count(states.get(state))
    reason_rows = []
    for bucket in reasons.values():
        reason_rows.append(
            {
                **bucket,
                "share_of_incomplete": _share(bucket["obligations"], obligations["incomplete_total"]),
            }
        )
    reason_rows.sort(key=lambda row: (-row["obligations"], row["canonical_code"]))

    def distribution(values: Iterable[str | None]) -> list[dict[str, Any]]:
        counts: dict[str, int] = {}
        for value in values:
            key = value if isinstance(value, str) and value else "UNKNOWN"
            counts[key] = counts.get(key, 0) + 1
        return [
            {"value": key, "runs": count, "share": _share(count, included)}
            for key, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        ]

    terminal_states = distribution(
        _mapping(summary.get("run")).get("terminal_state") for summary in summaries
    )
    freshness_states = distribution(
        _mapping(_mapping(summary.get("run")).get("freshness")).get("state") for summary in summaries
    )

    provider_totals = {}
    for key in ("calls_reserved", "calls_settled", "retries", "tool_calls_reserved"):
        total_known, known, missing = _sum_known(
            _mapping(summary.get("providers")).get(key) for summary in summaries
        )
        provider_totals[key] = {"total": total_known, "known_runs": known, "missing_runs": missing}
    provider_totals["request_attempt_unknown"] = {
        "value": _sum_known(
            _mapping(summary.get("providers")).get("request_attempt_unknown") for summary in summaries
        )[0]
    }

    token_fields: dict[str, dict[str, Any]] = {}
    for field in TOKEN_FIELDS:
        reported_sum = 0
        reported_count = 0
        unknown_count = 0
        denominator = 0
        runs_with_reports = 0
        for summary in summaries:
            values = _mapping(_mapping(_mapping(_mapping(summary.get("tokens")).get("fields")).get(field)))
            reported_sum += _count(values.get("reported_sum"))
            reported_count += _count(values.get("reported_count"))
            unknown_count += _count(values.get("unknown_count"))
            denominator += _count(values.get("denominator_calls"))
            if _count(values.get("reported_count")) > 0:
                runs_with_reports += 1
        token_fields[field] = {
            "reported_sum": reported_sum if reported_count > 0 else None,
            "reported_count": reported_count,
            "unknown_count": unknown_count,
            "denominator_calls": denominator,
            "runs_with_reports": runs_with_reports,
            "complete_for_all_calls": bool(denominator) and unknown_count == 0,
        }

    run_elapsed = [
        number
        for number in (
            _finite_number(_mapping(summary.get("latency")).get("run_elapsed_ms"))
            for summary in summaries
        )
        if number is not None and number >= 0
    ]
    stage_values: dict[str, list[float | int]] = {}
    stage_http_values: dict[str, list[float | int]] = {}
    stage_observations: dict[str, int] = {}
    stage_http_observations: dict[str, int] = {}
    for summary in summaries:
        for stage, row in _mapping(_mapping(summary.get("latency")).get("by_stage")).items():
            if not isinstance(row, Mapping):
                continue
            key = str(stage)
            call_sum = _nonnegative_number(row.get("call_elapsed_ms_sum"))
            if call_sum is not None and _count(row.get("call_elapsed_known")) > 0:
                stage_values.setdefault(key, []).append(call_sum)
                stage_observations[key] = stage_observations.get(key, 0) + _count(row.get("call_elapsed_known"))
            http_sum = _nonnegative_number(row.get("http_elapsed_ms_sum"))
            if http_sum is not None and _count(row.get("http_elapsed_known")) > 0:
                stage_http_values.setdefault(key, []).append(http_sum)
                stage_http_observations[key] = stage_http_observations.get(key, 0) + _count(
                    row.get("http_elapsed_known")
                )

    by_stage: dict[str, dict[str, Any]] = {}
    for stage in sorted(set(stage_values) | set(stage_http_values)):
        values = stage_values.get(stage, [])
        by_stage[stage] = {
            "n_runs": len(values),
            "call_observations": stage_observations.get(stage, 0),
            "call_elapsed_ms_sum": sum(values) if values else None,
            "p50_run_stage_ms": _percentile(values, 0.5),
            "p95_run_stage_ms": _percentile(values, 0.95),
            "http_n_runs": len(stage_http_values.get(stage, [])),
            "http_call_observations": stage_http_observations.get(stage, 0),
            "http_elapsed_ms_sum": sum(stage_http_values[stage]) if stage_http_values.get(stage) else None,
            "http_p50_run_stage_ms": _percentile(stage_http_values.get(stage, []), 0.5),
            "http_p95_run_stage_ms": _percentile(stage_http_values.get(stage, []), 0.95),
        }

    estimate_values = []
    billing_values = []
    estimate_basis: dict[str, int] = {}
    billing_basis: dict[str, int] = {}
    estimate_unknown = 0
    billing_unknown = 0
    for summary in summaries:
        cost = _mapping(summary.get("cost"))
        estimate = _mapping(cost.get("estimate"))
        billing = _mapping(cost.get("billing"))
        basis = _string(estimate.get("basis")) or _BASIS_UNKNOWN
        estimate_basis[basis] = estimate_basis.get(basis, 0) + 1
        if estimate.get("known") is True and _nonnegative_int(estimate.get("microunits")) is not None:
            estimate_values.append(_nonnegative_int(estimate.get("microunits")))
        else:
            estimate_unknown += 1
        billing_basis_value = _string(billing.get("basis")) or _BASIS_UNKNOWN
        billing_basis[billing_basis_value] = billing_basis.get(billing_basis_value, 0) + 1
        if billing.get("known") is True and _nonnegative_int(billing.get("microunits")) is not None:
            billing_values.append(_nonnegative_int(billing.get("microunits")))
        else:
            billing_unknown += 1

    profiles: dict[str, dict[str, Any]] = {}
    for summary in summaries:
        version = _string(_mapping(summary.get("profile")).get("project_profile_version")) or "UNKNOWN"
        row = profiles.setdefault(version, {"project_profile_version": version, "runs": 0, "required": 0, "complete": 0})
        row["runs"] += 1
        row["required"] += _count(_mapping(summary.get("obligations")).get("required_total"))
        row["complete"] += _count(_mapping(summary.get("obligations")).get("complete"))
    profile_rows = []
    for row in profiles.values():
        profile_rows.append({**row, "complete_ratio_by_obligations": _share(row["complete"], row["required"])})
    profile_rows.sort(key=lambda row: (-row["runs"], row["project_profile_version"]))

    contracts: dict[tuple[str, str], int] = {}
    for summary in summaries:
        contract = _mapping(summary.get("contract"))
        key = (
            _string(contract.get("review_contract_name")) or "UNKNOWN",
            _string(contract.get("review_contract_version")) or "UNKNOWN",
        )
        contracts[key] = contracts.get(key, 0) + 1
    contract_rows = [
        {"review_contract": f"{name}@{version}", "runs": count}
        for (name, version), count in sorted(contracts.items(), key=lambda item: (-item[1], item[0]))
    ]

    missing_data = {
        "run_elapsed_ms_missing": sum(
            1 for summary in summaries if _mapping(summary.get("latency")).get("run_elapsed_ms") is None
        ),
        "stage_latency_missing": sum(
            1 for summary in summaries if not _mapping(_mapping(summary.get("latency")).get("by_stage"))
        ),
        "provider_calls_missing": provider_totals["calls_reserved"]["missing_runs"],
        "tokens_all_unknown": sum(
            1
            for summary in summaries
            if _count(_mapping(summary.get("tokens")).get("denominator_calls")) > 0
            and all(
                _count(
                    _mapping(_mapping(_mapping(summary.get("tokens")).get("fields")).get(field)).get(
                        "reported_count"
                    )
                )
                == 0
                for field in TOKEN_FIELDS
            )
        ),
        "runs_without_provider_calls": sum(
            1
            for summary in summaries
            if _count(_mapping(summary.get("tokens")).get("denominator_calls")) == 0
        ),
        "cost_estimate_unknown": estimate_unknown,
        "cost_billing_unknown": billing_unknown,
        "created_at_missing": sum(
            1 for summary in summaries if parse_timestamp(_mapping(summary.get("run")).get("created_at")) is None
        ),
        "terminal_state_missing": sum(
            1 for summary in summaries if _string(_mapping(summary.get("run")).get("terminal_state")) is None
        ),
        "profile_version_missing": sum(
            1
            for summary in summaries
            if _string(_mapping(summary.get("profile")).get("project_profile_version")) is None
        ),
        "contract_identity_missing": sum(
            1
            for summary in summaries
            if _string(_mapping(summary.get("contract")).get("review_contract_name")) is None
        ),
        "freshness_unknown": sum(
            1
            for summary in summaries
            if _mapping(_mapping(summary.get("run")).get("freshness")).get("state") in (None, "UNKNOWN")
        ),
    }

    return {
        "schema": RUN_METRICS_SCHEMA,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "window": {"since": since, "until": until},
        "runs": {
            "input": total,
            "included": included,
            "excluded": excluded_total,
            **excluded_counts,
            "summary_records_embedded": _count(_mapping(summary_sources).get("embedded")),
            "summary_records_derived": _count(_mapping(summary_sources).get("derived")),
        },
        "denominators": {
            "obligations": obligations["required_total"],
            "incomplete_obligations": obligations["incomplete_total"],
            "runs": included,
            "runs_with_required_obligations": runs_with_required,
            "provider_calls": _mapping(provider_totals["calls_reserved"]).get("total"),
        },
        "completion": completion,
        "reason_distribution": reason_rows,
        "terminal_state_distribution": terminal_states,
        "freshness_distribution": freshness_states,
        "providers": provider_totals,
        "tokens": {
            "denominator_calls": sum(
                _count(_mapping(summary.get("tokens")).get("denominator_calls")) for summary in summaries
            ),
            "fields": token_fields,
            "usage_states": {
                state: sum(
                    _count(_mapping(_mapping(summary.get("tokens")).get("usage_states")).get(state))
                    for summary in summaries
                )
                for state in ("known_calls", "partial_calls", "unknown_calls")
            },
        },
        "latency": {
            "run_elapsed_ms": {
                "n": len(run_elapsed),
                "p50": _percentile(run_elapsed, 0.5),
                "p95": _percentile(run_elapsed, 0.95),
                "sum": sum(run_elapsed) if run_elapsed else None,
            },
            "by_stage": by_stage,
        },
        "cost": {
            "currency": None,
            "estimate": {
                "known_runs": len(estimate_values),
                "unknown_runs": estimate_unknown,
                "microunits_total_known": sum(estimate_values) if estimate_values else None,
                "complete_for_all_runs": bool(included) and estimate_unknown == 0,
                "basis_distribution": [
                    {"basis": basis, "runs": count}
                    for basis, count in sorted(estimate_basis.items(), key=lambda item: (-item[1], item[0]))
                ],
            },
            "billing": {
                "known_runs": len(billing_values),
                "unknown_runs": billing_unknown,
                "microunits_total_known": sum(billing_values) if billing_values else None,
                "complete_for_all_runs": bool(included) and billing_unknown == 0,
                "basis_distribution": [
                    {"basis": basis, "runs": count}
                    for basis, count in sorted(billing_basis.items(), key=lambda item: (-item[1], item[0]))
                ],
            },
        },
        "profiles": profile_rows,
        "contracts": contract_rows,
        "missing_data": missing_data,
    }


# ---------------------------------------------------------------------------
# Rendering and export


def _ratio_text(value: Any) -> str:
    number = _finite_number(value)
    return f"{number * 100:.1f}%" if number is not None else "UNKNOWN"


def render_stats_text(stats: Mapping[str, Any]) -> str:
    """Render a compact human summary; every rate names its denominator."""

    runs = _mapping(stats.get("runs"))
    completion = _mapping(stats.get("completion"))
    window = _mapping(stats.get("window"))
    window_text = []
    if window.get("since"):
        window_text.append(f"since {window['since']}")
    if window.get("until"):
        window_text.append(f"until {window['until']}")
    scope = ", ".join(window_text) or "all stored results"
    excluded = _count(runs.get("excluded"))
    excluded_bits = [
        f"{name} {_count(runs.get(name))}"
        for name in ("before_since", "after_until", "missing_created_at")
        if _count(runs.get(name))
    ]
    excluded_text = f"; {excluded} excluded ({', '.join(excluded_bits)})" if excluded else ""
    lines = [
        f"Run metrics ({RUN_METRICS_SCHEMA}) {scope}: included {_count(runs.get('included'))} of "
        f"{_count(runs.get('input'))} results{excluded_text}."
    ]

    required = _count(completion.get("required_obligations_total"))
    lines.append(
        "Completion: "
        f"{_count(completion.get('complete_obligations'))}/{required} required obligations complete "
        f"({_ratio_text(completion.get('complete_ratio_by_obligations'))}); "
        f"{_count(completion.get('partial_obligations'))} partial, "
        f"{_count(completion.get('not_started_obligations'))} not started, "
        f"{_count(completion.get('unknown_state_obligations'))} unknown; "
        f"{_count(completion.get('not_applicable_obligations'))} not applicable; "
        f"{_count(completion.get('runs_fully_complete'))}/{_count(completion.get('runs_with_required_obligations'))} "
        f"runs fully complete ({_ratio_text(completion.get('completion_rate_by_runs'))}); "
        f"{_count(completion.get('runs_with_zero_obligations'))} zero-obligation runs."
    )

    reasons = stats.get("reason_distribution") or []
    reason_text = "; ".join(
        f"{row.get('canonical_code')} {_count(row.get('obligations'))} ({_count(row.get('runs_affected'))} runs)"
        for row in reasons[:8]
        if isinstance(row, Mapping)
    )
    lines.append(
        f"Reasons (denominator {_count(_mapping(stats.get('denominators')).get('incomplete_obligations'))} "
        f"incomplete obligations): {reason_text or 'none'}."
    )

    def distribution_text(key: str) -> str:
        rows = stats.get(key) or []
        parts = [
            f"{row.get('value')} {_count(row.get('runs'))} ({_ratio_text(row.get('share'))})"
            for row in rows
            if isinstance(row, Mapping)
        ]
        return ", ".join(parts) or "none"

    lines.append(f"Terminal states (denominator {_count(runs.get('included'))} runs): {distribution_text('terminal_state_distribution')}.")
    lines.append(f"Freshness (denominator {_count(runs.get('included'))} runs): {distribution_text('freshness_distribution')}.")

    providers = _mapping(stats.get("providers"))

    def provider_total(key: str) -> str:
        row = _mapping(providers.get(key))
        total = row.get("total")
        return "UNKNOWN" if total is None else str(total)

    lines.append(
        f"Provider calls: {provider_total('calls_reserved')} reserved, {provider_total('calls_settled')} settled, "
        f"{provider_total('retries')} retries, {provider_total('tool_calls_reserved')} local tool calls "
        f"(missing call data in {_count(_mapping(providers.get('calls_reserved')).get('missing_runs'))} runs)."
    )

    token_fields = _mapping(_mapping(stats.get("tokens")).get("fields"))
    token_parts = []
    for field in ("prompt_tokens", "completion_tokens", "total_tokens"):
        row = _mapping(token_fields.get(field))
        if row.get("reported_sum") is None:
            token_parts.append(f"{field} UNKNOWN")
        else:
            token_parts.append(
                f"{field} {row['reported_sum']} ({_count(row.get('reported_count'))}/"
                f"{_count(row.get('denominator_calls'))} calls reported)"
            )
    lines.append(f"Tokens: {', '.join(token_parts)}.")

    latency = _mapping(stats.get("latency"))
    elapsed = _mapping(latency.get("run_elapsed_ms"))
    latency_parts = [
        f"run wall p50 {elapsed.get('p50') if elapsed.get('p50') is not None else 'UNKNOWN'} ms, "
        f"p95 {elapsed.get('p95') if elapsed.get('p95') is not None else 'UNKNOWN'} ms (n={_count(elapsed.get('n'))})"
    ]
    for stage, row in sorted(_mapping(latency.get("by_stage")).items()):
        if not isinstance(row, Mapping):
            continue
        latency_parts.append(
            f"{stage} p50 {row.get('p50_run_stage_ms')} ms, p95 {row.get('p95_run_stage_ms')} ms "
            f"(n={_count(row.get('n_runs'))}, {_count(row.get('call_observations'))} call observations)"
        )
    lines.append(f"Latency: {'; '.join(latency_parts)}.")

    cost = _mapping(stats.get("cost"))
    estimate = _mapping(cost.get("estimate"))
    billing = _mapping(cost.get("billing"))
    estimate_basis = ", ".join(
        f"{row.get('basis')} {_count(row.get('runs'))}"
        for row in estimate.get("basis_distribution") or []
        if isinstance(row, Mapping)
    )
    lines.append(
        f"Cost: estimate {estimate.get('microunits_total_known') if estimate.get('microunits_total_known') is not None else 'UNKNOWN'} "
        f"microunits known for {_count(estimate.get('known_runs'))} runs, unknown for "
        f"{_count(estimate.get('unknown_runs'))} runs (basis: {estimate_basis or 'none'}); "
        f"billing {billing.get('microunits_total_known') if billing.get('microunits_total_known') is not None else 'UNKNOWN'} "
        f"microunits known for {_count(billing.get('known_runs'))} runs, unknown for "
        f"{_count(billing.get('unknown_runs'))} runs; currency UNKNOWN."
    )

    missing = _mapping(stats.get("missing_data"))
    missing_bits = [f"{key} {_count(value)}" for key, value in missing.items() if _count(value)]
    lines.append(f"Missing data: {', '.join(missing_bits) if missing_bits else 'none'}.")
    return "\n".join(lines)


def write_run_summaries_jsonl(summaries: Sequence[Mapping[str, Any]], path: str | Path) -> int:
    """Write one ``review-run-summary.v1`` record per line, sorted and compact."""

    location = Path(path)
    encoded = "".join(
        json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
        for summary in summaries
    )
    location.write_text(encoded, encoding="utf-8")
    return len(summaries)
