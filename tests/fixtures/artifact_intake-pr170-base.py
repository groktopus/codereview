"""Bounded, side-effect-free intake for the fixed review publication bundle.

This module parses untrusted bytes as data. It does not download artifacts,
verify signatures itself, stage files, authorize publication, or perform writes.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import stat
import tempfile
import time
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import BinaryIO, Mapping, Protocol

RESULT_FILENAME = "review-result.json"
MANIFEST_FILENAME = "provenance.json"
_EXPECTED_FILENAMES = frozenset({RESULT_FILENAME, MANIFEST_FILENAME})
_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "repository_id",
        "repository",
        "pull_request_number",
        "base_sha",
        "head_sha",
        "upstream_run_id",
        "upstream_run_attempt",
        "caller_workflow_id",
        "caller_workflow_path",
        "caller_workflow_ref",
        "caller_workflow_sha",
        "called_harness_repository",
        "called_harness_path",
        "called_harness_sha",
        "profile_version",
        "profile_sha256",
        "provider_configuration_identity",
        "review_run_id",
        "result_file_sha256",
        "result_hash",
        "created_at",
        "contract_versions",
    }
)
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_CHUNK_BYTES = 64 * 1024
_MAX_JSON_NESTING = 64
_MAX_JSON_STRUCTURAL_TOKENS = 200_000


class ArtifactIntakeError(ValueError):
    """Safe, stable error code for a rejected artifact bundle."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class AttestationState(StrEnum):
    UNAVAILABLE = "UNAVAILABLE"
    VERIFIED = "VERIFIED"


@dataclass(frozen=True)
class IntakeLimits:
    """Hard bounds for compressed input, expansion, file count and JSON."""

    max_archive_bytes: int = 8 * 1024 * 1024
    max_total_expanded_bytes: int = 16 * 1024 * 1024
    max_result_bytes: int = 15 * 1024 * 1024
    max_manifest_bytes: int = 64 * 1024
    max_path_bytes: int = 128
    max_compression_ratio: int = 1000
    max_read_seconds: float = 20.0


@dataclass(frozen=True)
class ArtifactTransportDigest:
    """Trusted adapter's digest claim about the exact downloaded ZIP bytes.

    `source` is descriptive provenance, not proof. A production caller must
    establish that its artifact API reports SHA-256 over these exact transport
    bytes before using the `github_artifact_api` value.
    """

    source: str
    subject: str
    algorithm: str
    hex_digest: str


@dataclass(frozen=True)
class ArtifactIdentity:
    """Expected manifest identity assembled from trusted config and API reads."""

    repository_id: int
    repository: str
    pull_request_number: int
    base_sha: str
    head_sha: str
    upstream_run_id: int
    upstream_run_attempt: int
    caller_workflow_id: int
    caller_workflow_path: str
    caller_workflow_ref: str
    caller_workflow_sha: str
    called_harness_repository: str
    called_harness_path: str
    called_harness_sha: str
    profile_version: str
    profile_sha256: str
    provider_configuration_identity: str
    contract_versions: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class AttestationIdentity:
    """Normalized signer and run claims emitted by a trusted verifier."""

    issuer: str
    repository_id: int
    repository: str
    workflow_id: int
    workflow_path: str
    workflow_ref: str
    workflow_sha: str
    run_id: int
    run_attempt: int
    called_harness_repository: str
    called_harness_path: str
    called_harness_sha: str


@dataclass(frozen=True)
class VerifiedAttestation:
    """Structured proof returned only by the explicitly trusted verifier.

    The type is a protocol boundary, not cryptographic evidence by itself. The
    verifier must authenticate the signature and claims before constructing it.
    """

    identity: AttestationIdentity
    subject_sha256: tuple[tuple[str, str], ...]


class TrustedAttestationVerifier(Protocol):
    """Injected trusted signature verifier; the intake module has no default."""

    def verify(
        self,
        *,
        archive_sha256: str,
        subjects: Mapping[str, str],
        expected_identity: AttestationIdentity,
    ) -> VerifiedAttestation: ...


@dataclass(frozen=True)
class IntakeReceipt:
    """Validated byte package. Accessors parse fresh dicts from immutable bytes."""

    archive_sha256: str
    archive_size_bytes: int
    transport_digest_source: str
    result_sha256: str
    manifest_sha256: str
    result_hash: str
    attestation_state: AttestationState
    _result_bytes: bytes
    _manifest_bytes: bytes

    @property
    def result(self) -> dict:
        return _parse_json_object(self._result_bytes, "result_json_invalid")

    @property
    def manifest(self) -> dict:
        return _parse_json_object(self._manifest_bytes, "manifest_json_invalid")


def _canonical_hash(value: dict) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _reject_constant(_value: str):
    raise ValueError("non-finite JSON number")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON number")
    return result


def _check_json_structure(raw: bytes) -> None:
    """Bound JSON complexity before the standard parser allocates containers."""
    depth = 0
    tokens = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
            tokens += 1
        elif byte in (0x7B, 0x5B):  # { [
            depth += 1
            tokens += 1
            if depth > _MAX_JSON_NESTING:
                raise ArtifactIntakeError("json_nesting_limit_exceeded")
        elif byte in (0x7D, 0x5D):  # } ]
            depth -= 1
            tokens += 1
            if depth < 0:
                raise ArtifactIntakeError("json_structure_invalid")
        elif byte in (0x2C, 0x3A):  # , :
            tokens += 1
        if tokens > _MAX_JSON_STRUCTURAL_TOKENS:
            raise ArtifactIntakeError("json_complexity_limit_exceeded")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _parse_json_object(raw: bytes, error_code: str) -> dict:
    try:
        text = raw.decode("utf-8", errors="strict")
        _check_json_structure(raw)
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except ArtifactIntakeError:
        raise
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError, OverflowError):
        raise ArtifactIntakeError(error_code) from None
    if not isinstance(value, dict):
        raise ArtifactIntakeError(error_code)
    return value


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _valid_sha(value: object, *, git: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    return bool((_GIT_SHA if git else _HEX_64).fullmatch(value))


def _nonempty(value: object, maximum: int = 512) -> bool:
    if not isinstance(value, str) or not value or _CONTROL.search(value):
        return False
    try:
        return len(value.encode("utf-8")) <= maximum
    except UnicodeEncodeError:
        return False


def _valid_identity(identity: ArtifactIdentity) -> bool:
    versions = identity.contract_versions
    valid_versions = (
        isinstance(versions, tuple)
        and len(versions) == 2
        and all(
            isinstance(item, tuple) and len(item) == 2 and all(isinstance(part, str) for part in item)
            for item in versions
        )
    )
    if valid_versions:
        try:
            valid_versions = dict(versions) == {"artifact_manifest": "1.0", "review_result": "1.0"}
        except (TypeError, ValueError):
            valid_versions = False
    return (
        _positive_int(identity.repository_id)
        and isinstance(identity.repository, str)
        and bool(_REPOSITORY.fullmatch(identity.repository))
        and _positive_int(identity.pull_request_number)
        and _valid_sha(identity.base_sha, git=True)
        and _valid_sha(identity.head_sha, git=True)
        and _positive_int(identity.upstream_run_id)
        and _positive_int(identity.upstream_run_attempt)
        and _positive_int(identity.caller_workflow_id)
        and all(
            _nonempty(value)
            for value in (
                identity.caller_workflow_path,
                identity.caller_workflow_ref,
                identity.called_harness_repository,
                identity.called_harness_path,
                identity.profile_version,
                identity.provider_configuration_identity,
            )
        )
        and _valid_sha(identity.caller_workflow_sha, git=True)
        and _valid_sha(identity.called_harness_sha, git=True)
        and _valid_sha(identity.profile_sha256)
        and valid_versions
    )


def _valid_attestation_identity(identity: AttestationIdentity) -> bool:
    return (
        _nonempty(identity.issuer, 2048)
        and _positive_int(identity.repository_id)
        and isinstance(identity.repository, str)
        and bool(_REPOSITORY.fullmatch(identity.repository))
        and _positive_int(identity.workflow_id)
        and _nonempty(identity.workflow_path)
        and _nonempty(identity.workflow_ref)
        and _valid_sha(identity.workflow_sha, git=True)
        and _positive_int(identity.run_id)
        and _positive_int(identity.run_attempt)
        and isinstance(identity.called_harness_repository, str)
        and bool(_REPOSITORY.fullmatch(identity.called_harness_repository))
        and _nonempty(identity.called_harness_path)
        and _valid_sha(identity.called_harness_sha, git=True)
    )


def _valid_transport_digest(value: ArtifactTransportDigest) -> bool:
    if not isinstance(value, ArtifactTransportDigest):
        return False
    return (
        isinstance(value.source, str)
        and value.source in {"github_artifact_api", "test_fixture"}
        and isinstance(value.subject, str)
        and value.subject == "downloaded_zip_bytes"
        and isinstance(value.algorithm, str)
        and value.algorithm == "sha256"
        and _valid_sha(value.hex_digest)
    )


def _read_compressed_bounded(source: BinaryIO, limits: IntakeLimits, deadline: float) -> tuple[BinaryIO, int, str]:
    if not hasattr(source, "read"):
        raise ArtifactIntakeError("archive_source_invalid")
    try:
        spool = tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode="w+b")
    except OSError:
        raise ArtifactIntakeError("archive_spool_unavailable") from None
    digest = hashlib.sha256()
    total = 0
    while True:
        if time.monotonic() >= deadline:
            spool.close()
            raise ArtifactIntakeError("archive_read_deadline_exceeded")
        try:
            chunk = source.read(min(_CHUNK_BYTES, limits.max_archive_bytes - total + 1))
        except Exception:
            spool.close()
            raise ArtifactIntakeError("archive_read_failed") from None
        if time.monotonic() >= deadline:
            spool.close()
            raise ArtifactIntakeError("archive_read_deadline_exceeded")
        if not isinstance(chunk, (bytes, bytearray)):
            spool.close()
            raise ArtifactIntakeError("archive_source_invalid")
        if not chunk:
            break
        total += len(chunk)
        if total > limits.max_archive_bytes:
            spool.close()
            raise ArtifactIntakeError("archive_compressed_limit_exceeded")
        digest.update(chunk)
        try:
            spool.write(chunk)
        except OSError:
            spool.close()
            raise ArtifactIntakeError("archive_spool_failed") from None
    if total < 22:
        spool.close()
        raise ArtifactIntakeError("archive_invalid")
    try:
        spool.seek(0)
        archive_header = spool.read(4)
        spool.seek(0)
    except OSError:
        spool.close()
        raise ArtifactIntakeError("archive_spool_failed") from None
    if archive_header != b"PK\x03\x04":
        spool.close()
        raise ArtifactIntakeError("archive_invalid")
    return spool, total, digest.hexdigest()


def _normalized_member(info: zipfile.ZipInfo, max_path_bytes: int) -> str:
    name = getattr(info, "orig_filename", info.filename)
    if (
        not isinstance(name, str)
        or not name
        or len(name.encode("utf-8", errors="surrogatepass")) > max_path_bytes
        or "\x00" in name
        or "\\" in name
        or name.startswith("/")
        or re.match(r"^[A-Za-z]:", name)
    ):
        raise ArtifactIntakeError("archive_path_invalid")
    normalized = unicodedata.normalize("NFC", name)
    path = PurePosixPath(normalized)
    if any(part in {"", ".", ".."} for part in path.parts) or path.is_absolute():
        # Return a normalized identity for duplicate detection only after
        # rejecting traversal/absolute names.
        raise ArtifactIntakeError("archive_path_invalid")
    return "/".join(path.parts).casefold()


def _validate_member(info: zipfile.ZipInfo) -> None:
    if info.is_dir() or info.flag_bits & (0x1 | 0x40):
        raise ArtifactIntakeError("archive_member_type_unsupported")
    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
        raise ArtifactIntakeError("archive_compression_unsupported")
    mode = (info.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(mode)
    if file_type not in {0, stat.S_IFREG}:
        raise ArtifactIntakeError("archive_member_type_unsupported")
    if isinstance(info.file_size, bool) or not isinstance(info.file_size, int) or info.file_size < 0:
        raise ArtifactIntakeError("archive_member_size_invalid")
    if not isinstance(info.compress_size, int) or info.compress_size < 0:
        raise ArtifactIntakeError("archive_member_size_invalid")


def _read_member_bounded(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    max_bytes: int,
    total_expanded: int,
    limits: IntakeLimits,
    deadline: float,
) -> bytes:
    if info.file_size > max_bytes:
        raise ArtifactIntakeError("archive_json_limit_exceeded")
    if info.compress_size == 0 and info.file_size:
        raise ArtifactIntakeError("archive_compression_ratio_exceeded")
    if info.compress_size and info.file_size > info.compress_size * limits.max_compression_ratio:
        raise ArtifactIntakeError("archive_compression_ratio_exceeded")
    output = bytearray()
    try:
        with archive.open(info, "r") as stream:
            while True:
                if time.monotonic() >= deadline:
                    raise ArtifactIntakeError("archive_read_deadline_exceeded")
                remaining = min(max_bytes - len(output), limits.max_total_expanded_bytes - total_expanded - len(output))
                chunk = stream.read(min(_CHUNK_BYTES, max(1, remaining + 1)))
                if time.monotonic() >= deadline:
                    raise ArtifactIntakeError("archive_read_deadline_exceeded")
                if not chunk:
                    break
                if (
                    len(output) + len(chunk) > max_bytes
                    or total_expanded + len(output) + len(chunk) > limits.max_total_expanded_bytes
                ):
                    raise ArtifactIntakeError("archive_expanded_limit_exceeded")
                output.extend(chunk)
    except ArtifactIntakeError:
        raise
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError, ValueError, zlib.error, NotImplementedError):
        raise ArtifactIntakeError("archive_member_invalid") from None
    if len(output) != info.file_size:
        raise ArtifactIntakeError("archive_member_size_mismatch")
    return bytes(output)


def _timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _manifest_for_identity(identity: ArtifactIdentity) -> dict:
    return {
        "schema_version": "1.0",
        "repository_id": identity.repository_id,
        "repository": identity.repository,
        "pull_request_number": identity.pull_request_number,
        "base_sha": identity.base_sha,
        "head_sha": identity.head_sha,
        "upstream_run_id": identity.upstream_run_id,
        "upstream_run_attempt": identity.upstream_run_attempt,
        "caller_workflow_id": identity.caller_workflow_id,
        "caller_workflow_path": identity.caller_workflow_path,
        "caller_workflow_ref": identity.caller_workflow_ref,
        "caller_workflow_sha": identity.caller_workflow_sha,
        "called_harness_repository": identity.called_harness_repository,
        "called_harness_path": identity.called_harness_path,
        "called_harness_sha": identity.called_harness_sha,
        "profile_version": identity.profile_version,
        "profile_sha256": identity.profile_sha256,
        "provider_configuration_identity": identity.provider_configuration_identity,
        "contract_versions": dict(identity.contract_versions),
    }


def _validate_manifest(manifest: dict, identity: ArtifactIdentity, result_bytes: bytes, result: dict) -> str:
    if set(manifest) != _MANIFEST_KEYS or manifest.get("schema_version") != "1.0":
        raise ArtifactIntakeError("manifest_contract_invalid")
    expected = _manifest_for_identity(identity)
    for key, value in expected.items():
        if manifest.get(key) != value or (isinstance(value, int) and isinstance(manifest.get(key), bool)):
            raise ArtifactIntakeError("manifest_identity_mismatch")
    if not isinstance(manifest.get("review_run_id"), str) or not manifest["review_run_id"]:
        raise ArtifactIntakeError("manifest_contract_invalid")
    if manifest["review_run_id"] != result.get("run_id"):
        raise ArtifactIntakeError("review_run_identity_mismatch")
    if not _timestamp(manifest.get("created_at")):
        raise ArtifactIntakeError("manifest_contract_invalid")
    result_digest = hashlib.sha256(result_bytes).hexdigest()
    if manifest.get("result_file_sha256") != result_digest or not _valid_sha(manifest.get("result_file_sha256")):
        raise ArtifactIntakeError("result_file_digest_mismatch")
    result_hash = manifest.get("result_hash")
    if not _valid_sha(result_hash) or result_hash != result.get("result_hash"):
        raise ArtifactIntakeError("result_hash_mismatch")
    if not _valid_sha(result.get("result_hash")):
        raise ArtifactIntakeError("result_hash_invalid")
    unsigned = {key: value for key, value in result.items() if key != "result_hash"}
    if _canonical_hash(unsigned) != result_hash:
        raise ArtifactIntakeError("result_hash_invalid")
    result_identity = {
        "repository": identity.repository,
        "pull_request_number": identity.pull_request_number,
        "base_sha": identity.base_sha,
        "head_sha": identity.head_sha,
        "project_profile_version": identity.profile_version,
    }
    for key, expected_value in result_identity.items():
        observed = result.get(key)
        if observed != expected_value or (isinstance(expected_value, int) and isinstance(observed, bool)):
            raise ArtifactIntakeError("result_identity_mismatch")
    if not _positive_int(result.get("pull_request_number")):
        raise ArtifactIntakeError("result_identity_invalid")
    if not isinstance(result.get("run_id"), str) or not result["run_id"]:
        raise ArtifactIntakeError("result_identity_invalid")
    return result_hash


def _validate_verification(
    proof: object,
    identity: AttestationIdentity,
    subjects: Mapping[str, str],
) -> bool:
    if not isinstance(proof, VerifiedAttestation):
        raise ArtifactIntakeError("attestation_proof_invalid")
    if not _valid_attestation_identity(proof.identity) or proof.identity != identity:
        raise ArtifactIntakeError("attestation_identity_mismatch")
    if not isinstance(proof.subject_sha256, tuple):
        raise ArtifactIntakeError("attestation_subjects_invalid")
    try:
        observed = dict(proof.subject_sha256)
    except (TypeError, ValueError):
        raise ArtifactIntakeError("attestation_subjects_invalid") from None
    if len(observed) != len(proof.subject_sha256) or observed != dict(subjects):
        raise ArtifactIntakeError("attestation_subjects_mismatch")
    if any(not _valid_sha(value) for value in observed.values()):
        raise ArtifactIntakeError("attestation_subjects_invalid")
    return True


def intake_artifact_bundle(
    source: BinaryIO,
    identity: ArtifactIdentity,
    transport_digest: ArtifactTransportDigest,
    *,
    trusted_attestation_identity: AttestationIdentity,
    attestation_verifier: TrustedAttestationVerifier | None = None,
    limits: IntakeLimits = IntakeLimits(),
) -> IntakeReceipt:
    """Read, hash, parse, and cross-check a two-file ZIP without side effects.

    `identity`, `transport_digest`, and the expected signer identity must be
    assembled by trusted service code from independently fetched run/PR/API
    state and fixed operator policy. A missing verifier yields an UNAVAILABLE
    attestation state; it never promotes the bundle to service admission.
    """
    if not isinstance(identity, ArtifactIdentity) or not _valid_identity(identity):
        raise ArtifactIntakeError("expected_identity_invalid")
    if not _valid_transport_digest(transport_digest):
        raise ArtifactIntakeError("transport_digest_contract_invalid")
    if not isinstance(trusted_attestation_identity, AttestationIdentity) or not _valid_attestation_identity(
        trusted_attestation_identity
    ):
        raise ArtifactIntakeError("trusted_attestation_identity_invalid")
    if (
        trusted_attestation_identity.repository_id != identity.repository_id
        or trusted_attestation_identity.repository != identity.repository
        or trusted_attestation_identity.workflow_id != identity.caller_workflow_id
        or trusted_attestation_identity.workflow_path != identity.caller_workflow_path
        or trusted_attestation_identity.workflow_ref != identity.caller_workflow_ref
        or trusted_attestation_identity.workflow_sha != identity.caller_workflow_sha
        or trusted_attestation_identity.run_id != identity.upstream_run_id
        or trusted_attestation_identity.run_attempt != identity.upstream_run_attempt
        or trusted_attestation_identity.called_harness_repository != identity.called_harness_repository
        or trusted_attestation_identity.called_harness_path != identity.called_harness_path
        or trusted_attestation_identity.called_harness_sha != identity.called_harness_sha
    ):
        raise ArtifactIntakeError("trusted_attestation_identity_mismatch")
    if (
        not isinstance(limits, IntakeLimits)
        or isinstance(limits.max_archive_bytes, bool)
        or not isinstance(limits.max_archive_bytes, int)
        or not 22 <= limits.max_archive_bytes <= 8 * 1024 * 1024
        or isinstance(limits.max_total_expanded_bytes, bool)
        or not isinstance(limits.max_total_expanded_bytes, int)
        or not 1 <= limits.max_total_expanded_bytes <= 16 * 1024 * 1024
        or isinstance(limits.max_result_bytes, bool)
        or not isinstance(limits.max_result_bytes, int)
        or not 1 <= limits.max_result_bytes <= 15 * 1024 * 1024
        or isinstance(limits.max_manifest_bytes, bool)
        or not isinstance(limits.max_manifest_bytes, int)
        or not 1 <= limits.max_manifest_bytes <= 64 * 1024
        or isinstance(limits.max_path_bytes, bool)
        or not isinstance(limits.max_path_bytes, int)
        or not 1 <= limits.max_path_bytes <= 128
        or isinstance(limits.max_compression_ratio, bool)
        or not isinstance(limits.max_compression_ratio, int)
        or not 1 <= limits.max_compression_ratio <= 1000
        or isinstance(limits.max_read_seconds, bool)
        or not isinstance(limits.max_read_seconds, (int, float))
        or not 0 < limits.max_read_seconds <= 300
    ):
        raise ArtifactIntakeError("intake_limits_invalid")

    deadline = time.monotonic() + limits.max_read_seconds
    spool, archive_size, archive_hash = _read_compressed_bounded(source, limits, deadline)
    try:
        if archive_hash != transport_digest.hex_digest:
            raise ArtifactIntakeError("artifact_transport_digest_mismatch")
        try:
            archive = zipfile.ZipFile(spool, "r")
        except (zipfile.BadZipFile, OSError, ValueError):
            raise ArtifactIntakeError("archive_invalid") from None
        with archive:
            infos = archive.infolist()
            if len(infos) != 2:
                raise ArtifactIntakeError("archive_file_count_invalid")
            normalized_names = []
            for info in infos:
                normalized_names.append(_normalized_member(info, limits.max_path_bytes))
                _validate_member(info)
            if len(set(normalized_names)) != len(normalized_names):
                raise ArtifactIntakeError("archive_duplicate_path")
            by_name = {info.filename: info for info in infos}
            if set(by_name) != _EXPECTED_FILENAMES:
                raise ArtifactIntakeError("archive_files_invalid")
            sizes = {RESULT_FILENAME: limits.max_result_bytes, MANIFEST_FILENAME: limits.max_manifest_bytes}
            extracted: dict[str, bytes] = {}
            expanded = 0
            for filename in (RESULT_FILENAME, MANIFEST_FILENAME):
                raw = _read_member_bounded(archive, by_name[filename], sizes[filename], expanded, limits, deadline)
                extracted[filename] = raw
                expanded += len(raw)
                if expanded > limits.max_total_expanded_bytes:
                    raise ArtifactIntakeError("archive_expanded_limit_exceeded")
        result = _parse_json_object(extracted[RESULT_FILENAME], "result_json_invalid")
        manifest = _parse_json_object(extracted[MANIFEST_FILENAME], "manifest_json_invalid")
        if time.monotonic() >= deadline:
            raise ArtifactIntakeError("archive_read_deadline_exceeded")
        result_hash = _validate_manifest(manifest, identity, extracted[RESULT_FILENAME], result)
        manifest_hash = hashlib.sha256(extracted[MANIFEST_FILENAME]).hexdigest()
        subjects = {
            RESULT_FILENAME: hashlib.sha256(extracted[RESULT_FILENAME]).hexdigest(),
            MANIFEST_FILENAME: manifest_hash,
        }
        state = AttestationState.UNAVAILABLE
        if attestation_verifier is not None:
            try:
                proof = attestation_verifier.verify(
                    archive_sha256=archive_hash,
                    subjects=subjects,
                    expected_identity=trusted_attestation_identity,
                )
            except Exception:
                # Never expose verifier exception text: vendor errors may carry
                # paths, tokens, request fragments, or signed claims.
                raise ArtifactIntakeError("attestation_verification_failed") from None
            if time.monotonic() >= deadline:
                raise ArtifactIntakeError("archive_read_deadline_exceeded")
            _validate_verification(proof, trusted_attestation_identity, subjects)
            state = AttestationState.VERIFIED
        return IntakeReceipt(
            archive_sha256=archive_hash,
            archive_size_bytes=archive_size,
            transport_digest_source=transport_digest.source,
            result_sha256=subjects[RESULT_FILENAME],
            manifest_sha256=manifest_hash,
            result_hash=result_hash,
            attestation_state=state,
            _result_bytes=extracted[RESULT_FILENAME],
            _manifest_bytes=extracted[MANIFEST_FILENAME],
        )
    finally:
        spool.close()
