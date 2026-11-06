"""Machine-readable contract/version registry (CA-3).

The registry is the single authority for which review contract, profile, and
limits combination is supported, which versions are deprecated, and which are
archived evidence.  Selection scripts and engine preflight both read this
module so an operator never has to infer status from filenames.

Failure model: every rejection is a :class:`ContractRegistryError` carrying a
stable ``code``.  Preflight maps those codes to an
``EnginePreflightError("invalid_review_request", ...)`` and dispatch never
starts.  Historical profile files are never rewritten: their bytes stay
immutable because evidence manifests bind their SHA-256.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

REGISTRY_VERSION = "contract-registry.v1"
REGISTRY_FILENAME = "contract_registry.json"
STATUSES = ("supported", "deprecated", "archived", "experimental")
KINDS = (
    "review-contract",
    "review-profile",
    "review-profile-template",
    "review-limits",
    "claim-assessment",
    "canary-receipt",
    "model-output",
    "model-input",
    "context",
    "policy",
    "artifact",
    "registry",
)
MAX_REGISTRY_BYTES = 512_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ENTRY_KEYS = {
    "kind",
    "name",
    "version",
    "status",
    "owner",
    "replaced_by",
    "source_path",
    "source_sha256",
    "source_symbol",
    "invariants",
}
_OPTIONAL_KEYS = {
    "combination",
    "mismatch_error",
    "checks",
    "deprecation",
    "archived",
    "repository",
    "values",
    "applies_to",
    "notes",
}
_POLICY_KEYS = {"announcement", "replacement_path", "compatibility_window", "removal_evidence"}
_DEPRECATION_KEYS = {
    "announced_on",
    "announcement_ref",
    "replacement_path",
    "compatibility_window",
    "removal_evidence",
}
_ARCHIVED_KEYS = {"archived_on", "archival_note", "evidence_paths"}
_CHECK_OPERATORS = {"equals", "contains", "absent", "length_equals", "equals_exact"}
_CLAIM_MODES = {"default", "PR_MERGE_BASE", "legacy"}


class ContractRegistryError(ValueError):
    """A closed, stable contract-registry failure code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def default_registry_path() -> Path:
    """Return the trusted registry path; an explicit override exists for tests."""
    override = os.environ.get("PR_REVIEW_CONTRACT_REGISTRY")
    if override:
        return Path(override)
    return Path(__file__).resolve().with_name(REGISTRY_FILENAME)


def _read_regular_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_REGISTRY_BYTES:
            raise ContractRegistryError("registry_unavailable")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(descriptor, "rb") as stream:
            raw = stream.read(MAX_REGISTRY_BYTES + 1)
    except ContractRegistryError:
        raise
    except OSError:
        raise ContractRegistryError("registry_unavailable") from None
    if len(raw) > MAX_REGISTRY_BYTES:
        raise ContractRegistryError("registry_unavailable")
    return raw


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractRegistryError("registry_invalid")
        result[key] = value
    return result


def _parse_registry(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ContractRegistryError("registry_invalid")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ContractRegistryError("registry_invalid") from None
    if not isinstance(value, dict):
        raise ContractRegistryError("registry_invalid")
    return value


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def registry_digest(registry: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(registry)).hexdigest()


def load_registry(path: Path | str | None = None) -> dict[str, Any]:
    """Load and fully validate the registry.  Never returns a partial view."""
    target = Path(path) if path is not None else default_registry_path()
    registry = _parse_registry(_read_regular_file(target))
    validate_registry(registry)
    return registry


def _is_scalar_or_container(value: Any, *, depth: int = 0) -> bool:
    if depth > 16:
        return False
    if value is None or isinstance(value, (bool, int, float, str)):
        return True
    if isinstance(value, list):
        return all(_is_scalar_or_container(item, depth=depth + 1) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _is_scalar_or_container(item, depth=depth + 1) for key, item in value.items()
        )
    return False


def _validate_source(entry: dict[str, Any], *, root: Path | None) -> None:
    source_path = entry.get("source_path")
    if source_path is not None and (
        not isinstance(source_path, str)
        or not source_path
        or source_path.startswith(("/", ".."))
        or ".." in source_path.split("/")
    ):
        raise ContractRegistryError("registry_invalid")
    source_sha256 = entry.get("source_sha256")
    if source_sha256 is not None and (not isinstance(source_sha256, str) or not _SHA256.fullmatch(source_sha256)):
        raise ContractRegistryError("registry_invalid")
    source_symbol = entry.get("source_symbol")
    if source_symbol is not None and (not isinstance(source_symbol, str) or not source_symbol.strip()):
        raise ContractRegistryError("registry_invalid")
    if source_sha256 is not None and source_path is not None and root is not None:
        try:
            observed = hashlib.sha256(_read_regular_file(Path(root) / source_path)).hexdigest()
        except ContractRegistryError:
            raise ContractRegistryError("registry_source_mismatch") from None
        if observed != source_sha256:
            raise ContractRegistryError("registry_source_mismatch")


def _validate_checks(entry: dict[str, Any]) -> None:
    checks = entry.get("checks")
    if checks is None:
        return
    if not isinstance(checks, list) or not checks:
        raise ContractRegistryError("registry_invalid")
    for clause in checks:
        if not isinstance(clause, dict) or set(clause) - {"path"} - _CHECK_OPERATORS:
            raise ContractRegistryError("registry_invalid")
        if not isinstance(clause.get("path"), str) or not clause["path"]:
            raise ContractRegistryError("registry_invalid")
        operators = [name for name in _CHECK_OPERATORS if name in clause]
        if len(operators) != 1:
            raise ContractRegistryError("registry_invalid")
        operator = operators[0]
        if operator == "absent":
            if clause[operator] is not True:
                raise ContractRegistryError("registry_invalid")
        elif operator == "length_equals":
            if isinstance(clause[operator], bool) or not isinstance(clause[operator], int) or clause[operator] < 0:
                raise ContractRegistryError("registry_invalid")
        elif not _is_scalar_or_container(clause[operator]):
            raise ContractRegistryError("registry_invalid")


def _validate_deprecation(entry: dict[str, Any]) -> None:
    deprecation = entry.get("deprecation")
    if not isinstance(deprecation, dict) or set(deprecation) - {"terminal", "terminal_reason"} != _DEPRECATION_KEYS:
        raise ContractRegistryError("registry_invalid")
    window = deprecation["compatibility_window"]
    if (
        not isinstance(window, dict)
        or set(window) != {"starts", "ends"}
        or not all(isinstance(window[key], str) and window[key] for key in ("starts", "ends"))
        or window["starts"] > window["ends"]
    ):
        raise ContractRegistryError("registry_invalid")
    if not isinstance(deprecation["removal_evidence"], list) or not deprecation["removal_evidence"]:
        raise ContractRegistryError("registry_invalid")
    if not all(isinstance(item, str) and item.strip() for item in deprecation["removal_evidence"]):
        raise ContractRegistryError("registry_invalid")
    for key in ("announced_on", "announcement_ref", "replacement_path"):
        if not isinstance(deprecation[key], str) or not deprecation[key].strip():
            raise ContractRegistryError("registry_invalid")
    if deprecation.get("terminal") is True and entry.get("replaced_by") is not None:
        raise ContractRegistryError("registry_invalid")
    if deprecation.get("terminal") not in (None, True):
        raise ContractRegistryError("registry_invalid")


def _validate_archived(entry: dict[str, Any]) -> None:
    archived = entry.get("archived")
    if not isinstance(archived, dict) or set(archived) != _ARCHIVED_KEYS:
        raise ContractRegistryError("registry_invalid")
    for key in ("archived_on", "archival_note"):
        if not isinstance(archived[key], str) or not archived[key].strip():
            raise ContractRegistryError("registry_invalid")
    if (
        not isinstance(archived["evidence_paths"], list)
        or not archived["evidence_paths"]
        or not all(isinstance(item, str) and item.strip() for item in archived["evidence_paths"])
    ):
        raise ContractRegistryError("registry_invalid")


def validate_registry(registry: dict[str, Any], *, root: Path | str | None = None) -> None:
    """Validate shape, status matrix, references, and pinned source digests."""
    if set(registry) != {
        "registry_version",
        "owner",
        "supported_combination",
        "targets",
        "deprecation_policy",
        "contracts",
    }:
        raise ContractRegistryError("registry_invalid")
    if registry["registry_version"] != REGISTRY_VERSION:
        raise ContractRegistryError("registry_invalid")
    if not isinstance(registry["owner"], str) or not registry["owner"].strip():
        raise ContractRegistryError("registry_invalid")
    policy = registry["deprecation_policy"]
    if not isinstance(policy, dict) or set(policy) != _POLICY_KEYS:
        raise ContractRegistryError("registry_invalid")
    if not isinstance(policy["removal_evidence"], list) or not policy["removal_evidence"]:
        raise ContractRegistryError("registry_invalid")
    for key in ("announcement", "replacement_path", "compatibility_window"):
        if not isinstance(policy[key], str) or not policy[key].strip():
            raise ContractRegistryError("registry_invalid")

    contracts = registry["contracts"]
    if not isinstance(contracts, list) or not contracts:
        raise ContractRegistryError("registry_invalid")
    seen: set[tuple[str, str]] = set()
    for entry in contracts:
        if not isinstance(entry, dict):
            raise ContractRegistryError("registry_invalid")
        keys = set(entry)
        if keys - _ENTRY_KEYS - _OPTIONAL_KEYS or _ENTRY_KEYS - keys:
            raise ContractRegistryError("registry_invalid")
        if entry["kind"] not in KINDS:
            raise ContractRegistryError("registry_invalid")
        if (
            not isinstance(entry["name"], str)
            or not entry["name"].strip()
            or not isinstance(entry["version"], str)
            or not entry["version"].strip()
            or not isinstance(entry["owner"], str)
            or not entry["owner"].strip()
        ):
            raise ContractRegistryError("registry_invalid")
        if entry["status"] not in STATUSES:
            raise ContractRegistryError("registry_invalid_status")
        if not isinstance(entry["invariants"], dict) or not _is_scalar_or_container(entry["invariants"]):
            raise ContractRegistryError("registry_invalid")
        identity = (entry["kind"], entry["name"])
        if identity in seen:
            raise ContractRegistryError("registry_duplicate_entry")
        seen.add(identity)
        _validate_source(entry, root=Path(root) if root is not None else None)
        _validate_checks(entry)
        if entry["status"] == "deprecated":
            if entry.get("archived") is not None:
                raise ContractRegistryError("registry_invalid")
            _validate_deprecation(entry)
        elif entry["status"] == "archived":
            if entry.get("deprecation") is not None:
                raise ContractRegistryError("registry_invalid")
            _validate_archived(entry)
        else:
            if entry.get("deprecation") is not None or entry.get("archived") is not None:
                raise ContractRegistryError("registry_invalid")
            if entry["replaced_by"] is not None:
                raise ContractRegistryError("registry_invalid")
        if entry["kind"] == "review-contract":
            combination = entry.get("combination")
            if not isinstance(combination, dict) or set(combination) != {
                "target_repository",
                "profile",
                "limits",
                "max_claim_assessments",
            }:
                raise ContractRegistryError("registry_invalid")
            if (
                not isinstance(combination["target_repository"], str)
                or not isinstance(combination["profile"], str)
                or not isinstance(combination["limits"], str)
                or isinstance(combination["max_claim_assessments"], bool)
                or not isinstance(combination["max_claim_assessments"], int)
                or not 0 <= combination["max_claim_assessments"] <= 4
            ):
                raise ContractRegistryError("registry_invalid")
            if not isinstance(entry.get("mismatch_error"), str) or not entry["mismatch_error"].strip():
                raise ContractRegistryError("registry_invalid")
        elif entry.get("combination") is not None or entry.get("mismatch_error") is not None:
            raise ContractRegistryError("registry_invalid")
        if entry["kind"] == "review-profile":
            if not isinstance(entry.get("repository"), str) or not entry["repository"].strip():
                raise ContractRegistryError("registry_invalid")
        if entry["kind"] == "review-limits":
            if not isinstance(entry.get("values"), dict) or not _is_scalar_or_container(entry["values"]):
                raise ContractRegistryError("registry_invalid")
        if entry["kind"] == "claim-assessment":
            if entry.get("applies_to") not in _CLAIM_MODES:
                raise ContractRegistryError("registry_invalid")

    index = {(entry["kind"], entry["name"]): entry for entry in contracts}
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for entry in contracts:
        by_kind.setdefault(entry["kind"], []).append(entry)

    def _entry(kind: str, name: Any) -> dict[str, Any]:
        if not isinstance(name, str) or (kind, name) not in index:
            raise ContractRegistryError("registry_unknown_reference")
        return index[(kind, name)]

    # Replacement targets must exist, be of the same kind, and not be archived.
    for entry in contracts:
        replacement = entry["replaced_by"]
        if replacement is None:
            if entry["status"] == "deprecated" and entry["deprecation"].get("terminal") is not True:
                raise ContractRegistryError("registry_invalid")
            continue
        target = _entry(entry["kind"], replacement)
        # Archived generations may point at the next archived generation; a
        # selectable contract may never be replaced by archived evidence.
        if target is entry or (entry["status"] != "archived" and target["status"] == "archived"):
            raise ContractRegistryError("registry_unknown_reference")

    # Every review contract must reference non-archived profile/limits entries.
    for entry in by_kind.get("review-contract", []):
        combination = entry["combination"]
        profile = _entry("review-profile", combination["profile"])
        limits = _entry("review-limits", combination["limits"])
        for component in (profile, limits):
            if component["status"] == "archived":
                raise ContractRegistryError("registry_invalid")
        if profile["repository"] != combination["target_repository"]:
            raise ContractRegistryError("registry_invalid")

    supported_contracts = [entry for entry in by_kind.get("review-contract", []) if entry["status"] == "supported"]
    supported_profiles = [entry for entry in by_kind.get("review-profile", []) if entry["status"] == "supported"]
    supported_limits = [entry for entry in by_kind.get("review-limits", []) if entry["status"] == "supported"]
    if len(supported_contracts) != 1 or len(supported_profiles) != 1 or len(supported_limits) != 1:
        raise ContractRegistryError("registry_supported_matrix")
    combination = registry["supported_combination"]
    if not isinstance(combination, dict) or set(combination) != {
        "review_contract",
        "profile",
        "limits",
        "target_repository",
    }:
        raise ContractRegistryError("registry_invalid")
    if (
        combination["review_contract"] != supported_contracts[0]["name"]
        or combination["profile"] != supported_profiles[0]["name"]
        or combination["limits"] != supported_limits[0]["name"]
        or combination["target_repository"] != supported_contracts[0]["combination"]["target_repository"]
    ):
        raise ContractRegistryError("registry_supported_matrix")
    if (
        supported_contracts[0]["combination"]["profile"] != supported_profiles[0]["name"]
        or supported_contracts[0]["combination"]["limits"] != supported_limits[0]["name"]
    ):
        raise ContractRegistryError("registry_supported_matrix")

    targets = registry["targets"]
    if not isinstance(targets, dict) or not targets:
        raise ContractRegistryError("registry_invalid")
    for repository, target in targets.items():
        if not isinstance(repository, str) or not isinstance(target, dict):
            raise ContractRegistryError("registry_invalid")
        if set(target) != {"default_review_contract", "review_contracts"}:
            raise ContractRegistryError("registry_invalid")
        names = target["review_contracts"]
        if not isinstance(names, list) or not names or len(names) != len(set(names)):
            raise ContractRegistryError("registry_invalid")
        for name in names:
            entry = _entry("review-contract", name)
            if entry["combination"]["target_repository"] != repository or entry["status"] == "archived":
                raise ContractRegistryError("registry_invalid")
        if target["default_review_contract"] not in names:
            raise ContractRegistryError("registry_invalid")


def entry_index(registry: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(entry["kind"], entry["name"]): entry for entry in registry["contracts"]}


def get_entry(registry: dict[str, Any], kind: str, name: str) -> dict[str, Any]:
    entry = entry_index(registry).get((kind, name))
    if entry is None:
        raise ContractRegistryError("registry_unknown_reference")
    return entry


def supported_combination(registry: dict[str, Any]) -> dict[str, Any]:
    return dict(registry["supported_combination"])


def default_contract_for_target(registry: dict[str, Any], target_repository: str) -> str | None:
    target = registry["targets"].get(target_repository)
    if not isinstance(target, dict):
        return None
    return target["default_review_contract"]


def review_profile_entry(registry: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any] | None:
    """Find the registry profile carrying this exact repository/version identity."""
    repository = profile.get("repository")
    version = profile.get("version", profile.get("profile_version"))
    if not isinstance(repository, str) or not isinstance(version, str):
        return None
    for entry in registry["contracts"]:
        if entry["kind"] != "review-profile":
            continue
        if entry.get("repository") == repository and entry["version"] == version:
            return entry
    return None


def _component(entry: dict[str, Any] | None) -> dict[str, Any]:
    if entry is None:
        return {
            "name": None,
            "version": None,
            "status": "unregistered",
            "owner": None,
            "replaced_by": None,
            "source_path": None,
            "source_sha256": None,
        }
    return {
        "name": entry["name"],
        "version": entry["version"],
        "status": entry["status"],
        "owner": entry["owner"],
        "replaced_by": entry["replaced_by"],
        "source_path": entry["source_path"],
        "source_sha256": entry["source_sha256"],
        **(
            {"deprecation": entry["deprecation"]}
            if entry["status"] == "deprecated" and isinstance(entry.get("deprecation"), dict)
            else {}
        ),
    }


def _claim_assessment_entry(
    registry: dict[str, Any], version: str | None, comparison_mode: str | None
) -> dict[str, Any]:
    candidates = [entry for entry in registry["contracts"] if entry["kind"] == "claim-assessment"]
    if isinstance(version, str):
        for entry in candidates:
            if entry["name"] == version:
                return entry
        raise ContractRegistryError("contract_unknown_component")
    mode = "PR_MERGE_BASE" if comparison_mode == "PR_MERGE_BASE" else "default"
    for entry in candidates:
        if entry["applies_to"] == mode:
            return entry
    raise ContractRegistryError("contract_unknown_component")


def _artifact_component(
    registry: dict[str, Any], kind: str, name: str | None, *, allowed_statuses: tuple[str, ...] = STATUSES
) -> dict[str, Any] | None:
    if name is None:
        return None
    try:
        entry = get_entry(registry, kind, name)
    except ContractRegistryError:
        raise ContractRegistryError("contract_unknown_component") from None
    if entry["status"] not in allowed_statuses:
        raise ContractRegistryError("contract_archived" if entry["status"] == "archived" else "contract_deprecated")
    return _component(entry)


def _verify_component_status(entry: dict[str, Any], *, allow_deprecated: bool, allow_archived: bool = False) -> None:
    if entry["status"] == "archived" and not allow_archived:
        raise ContractRegistryError("contract_archived")
    if entry["status"] == "deprecated" and not allow_deprecated:
        raise ContractRegistryError("contract_deprecated")


def limits_entry_for(registry: dict[str, Any], limits: dict[str, Any]) -> dict[str, Any] | None:
    """Find the most specific registered limits entry satisfied by ``limits``.

    The CLI strips ``schema_version``, so the comparison ignores it.  The most
    specific entry wins, which distinguishes the v1 override from v2/v3.
    """
    best: dict[str, Any] | None = None
    best_keys = -1
    for entry in registry["contracts"]:
        if entry["kind"] != "review-limits":
            continue
        values = {key: value for key, value in entry["values"].items() if key != "schema_version"}
        if all(limits.get(key) == value for key, value in values.items()) and len(values) > best_keys:
            best, best_keys = entry, len(values)
    return best


def validate_profile_checks(profile: dict[str, Any], contract_entry: dict[str, Any]) -> None:
    """Enforce non-limits contract checks at preflight.

    Limits are enforced separately against the registered limits entry because
    the engine receives limits without ``schema_version``.
    """
    checks = [clause for clause in contract_entry.get("checks", []) if clause["path"] != "limits"]
    if checks:
        validate_contract_checks(profile, {}, {"checks": checks})


def effective_contract_set(
    registry: dict[str, Any],
    profile: dict[str, Any],
    limits: dict[str, Any],
    *,
    comparison_mode: str | None = None,
    claim_assessment_version: str | None = None,
    max_claim_assessments: int | None = None,
    allow_deprecated: bool = True,
    allow_archived: bool = False,
) -> dict[str, Any]:
    """Return the audited contract set for one run.

    Registered profiles are held to their exact combination: limits, claim cap,
    and profile invariants all fail closed.  Archived profiles/limits are
    rejected unless ``allow_archived`` is explicitly set by a historical
    reproduction path; their recorded status is ``archived``, never
    ``unregistered``.  A genuinely unregistered synthetic fixture is recorded
    as ``unregistered`` so the engine remains usable as a library.
    """
    registry_component = _component(get_entry(registry, "registry", REGISTRY_VERSION))
    registry_component["sha256"] = registry_digest(registry)

    claim_entry = _claim_assessment_entry(registry, claim_assessment_version, comparison_mode)
    _verify_component_status(claim_entry, allow_deprecated=allow_deprecated)

    profile_entry = review_profile_entry(registry, profile)
    limits_entry = limits_entry_for(registry, limits)
    archived_components = [
        entry for entry in (profile_entry, limits_entry) if entry is not None and entry["status"] == "archived"
    ]
    if archived_components and not allow_archived:
        raise ContractRegistryError("contract_archived")

    contract: dict[str, Any] | None = None
    if profile_entry is not None and profile_entry["status"] != "archived":
        contract = next(
            (
                entry
                for entry in registry["contracts"]
                if entry["kind"] == "review-contract" and entry["combination"]["profile"] == profile_entry["name"]
            ),
            None,
        )

    if contract is not None:
        combination = contract["combination"]
        for entry in (contract, profile_entry, limits_entry):
            if entry is None:
                raise ContractRegistryError("contract_limits_mismatch")
            _verify_component_status(entry, allow_deprecated=allow_deprecated, allow_archived=allow_archived)
        historical_limits = bool(
            allow_archived
            and limits_entry is not None
            and limits_entry["status"] == "archived"
            and contract["status"] != "supported"
        )
        if not historical_limits:
            if limits_entry is None or limits_entry["name"] != combination["limits"]:
                raise ContractRegistryError("contract_limits_mismatch")
            for key, expected in limits_entry["values"].items():
                if key == "schema_version":
                    continue
                if limits.get(key) != expected:
                    raise ContractRegistryError("contract_limits_mismatch")
        if max_claim_assessments is not None and max_claim_assessments != combination["max_claim_assessments"]:
            raise ContractRegistryError("contract_claim_cap_mismatch")
        validate_profile_checks(profile, contract)
        registration = "registered"
    elif profile_entry is not None and profile_entry["status"] == "archived":
        registration = "archived"
    elif profile_entry is not None and profile_entry["status"] == "experimental":
        registration = "experimental"
    else:
        # A profile that presents a registry identity (repository + status) on a
        # known target must resolve to a registered version.  Synthetic fixtures
        # without that identity remain usable as library inputs.
        identity_claims_registry = isinstance(profile.get("repository"), str) and isinstance(
            profile.get("profile_status"), str
        )
        if identity_claims_registry and profile["repository"] in registry["targets"] and profile_entry is None:
            raise ContractRegistryError("contract_unregistered_profile")
        registration = "unregistered"

    claim_reconciliation = profile.get("claim_reconciliation")
    reconciliation_version = claim_reconciliation.get("version") if isinstance(claim_reconciliation, dict) else None
    context_selection = profile.get("context_selection")
    context_version = context_selection.get("version") if isinstance(context_selection, dict) else None
    context_target_manifest = profile.get("context_target_manifest")
    manifest_version = context_target_manifest.get("version") if isinstance(context_target_manifest, dict) else None
    component = (
        _component(profile_entry)
        if profile_entry is not None
        else {
            "name": profile.get("version", profile.get("profile_version")),
            "version": profile.get("version", profile.get("profile_version")),
            "status": registration if registration == "unregistered" else "unregistered",
            "owner": None,
            "replaced_by": None,
            "source_path": None,
            "source_sha256": None,
        }
    )
    return {
        "registration": registration,
        "registry": registry_component,
        "review_contract": _component(contract),
        "profile": component,
        "limits": _component(limits_entry),
        "claim_assessment": _component(claim_entry),
        "claim_reconciliation": _artifact_component(
            registry, "policy", reconciliation_version, allowed_statuses=("supported", "deprecated")
        ),
        "specialist_findings": _component(get_entry(registry, "model-output", "specialist-findings.v4")),
        "adjudication": _component(get_entry(registry, "model-output", "semantic-adjudication.v3")),
        "specialist_input": _component(get_entry(registry, "model-input", "specialist-input.v2")),
        "context_selection": _artifact_component(
            registry, "context", context_version, allowed_statuses=("supported", "deprecated")
        ),
        "context_target_manifest": _artifact_component(
            registry, "context", manifest_version, allowed_statuses=("supported", "deprecated")
        ),
        "context_followup": _component(get_entry(registry, "model-input", "context-followup.v1")),
        "target_profile_bindings": _component(get_entry(registry, "policy", "target-profile-bindings.v1")),
        "run_artifact": _component(get_entry(registry, "artifact", "review-result.v0.1")),
    }


def _resolve_path(document: dict[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = document
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def validate_contract_checks(profile: dict[str, Any], limits: dict[str, Any], contract_entry: dict[str, Any]) -> None:
    """Enforce the machine-readable ``checks`` clauses for one review contract."""
    for clause in contract_entry.get("checks", []):
        path = clause["path"]
        root, _, rest = path.partition(".")
        document = limits if root == "limits" else profile
        remaining = rest if root == "limits" else path
        if root == "limits" and not rest:
            present, actual = True, limits
        else:
            present, actual = _resolve_path(document, remaining)
        if "absent" in clause:
            if present:
                raise ContractRegistryError("contract_invariant_mismatch")
            continue
        if not present:
            raise ContractRegistryError("contract_invariant_mismatch")
        if "equals" in clause and actual != clause["equals"]:
            raise ContractRegistryError("contract_invariant_mismatch")
        if "equals_exact" in clause and actual != clause["equals_exact"]:
            raise ContractRegistryError("contract_invariant_mismatch")
        if "contains" in clause and (not isinstance(actual, list) or clause["contains"] not in actual):
            raise ContractRegistryError("contract_invariant_mismatch")
        if "length_equals" in clause and (
            not isinstance(actual, (list, dict, str)) or len(actual) != clause["length_equals"]
        ):
            raise ContractRegistryError("contract_invariant_mismatch")


def receipt_contract_set(registry: dict[str, Any], protocol_version: str) -> dict[str, Any]:
    """Return the contract identity for a publication/canary receipt.

    Publication runtime keeps its own emission path; this helper gives receipts
    and tests one authoritative view without importing the runtime.
    """
    entry = get_entry(registry, "canary-receipt", protocol_version)
    if entry["status"] == "archived":
        raise ContractRegistryError("contract_archived")
    return {
        "registry": {
            **_component(get_entry(registry, "registry", REGISTRY_VERSION)),
            "sha256": registry_digest(registry),
        },
        "canary_receipt": _component(entry),
    }
