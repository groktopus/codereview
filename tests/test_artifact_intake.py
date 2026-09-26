import hashlib
import io
import json
import stat
import zipfile

import pytest

from pr_review_harness.artifact_intake import (
    MANIFEST_FILENAME,
    RESULT_FILENAME,
    ArtifactIdentity,
    ArtifactIntakeError,
    ArtifactTransportDigest,
    AttestationIdentity,
    AttestationState,
    IntakeLimits,
    VerifiedAttestation,
    intake_artifact_bundle,
)

HEAD = "a" * 40
BASE = "b" * 40
PROFILE_HASH = "c" * 64
CALLER_SHA = "d" * 40
HARNESS_SHA = "e" * 40
RUN = 731245
ATTEMPT = 2


def identities():
    identity = ArtifactIdentity(
        repository_id=8123,
        repository="owner/repo",
        pull_request_number=44,
        base_sha=BASE,
        head_sha=HEAD,
        upstream_run_id=RUN,
        upstream_run_attempt=ATTEMPT,
        caller_workflow_id=563,
        caller_workflow_path=".github/workflows/pr-analysis.yml",
        caller_workflow_ref="refs/heads/main",
        caller_workflow_sha=CALLER_SHA,
        called_harness_repository="harness/repo",
        called_harness_path=".github/workflows/review.yml",
        called_harness_sha=HARNESS_SHA,
        profile_version="repo-profile-v3",
        profile_sha256=PROFILE_HASH,
        provider_configuration_identity="provider-config-sha256:" + "f" * 64,
        contract_versions=(("artifact_manifest", "1.0"), ("review_result", "1.0")),
    )
    attestation = AttestationIdentity(
        issuer="https://token.actions.githubusercontent.com",
        repository_id=identity.repository_id,
        repository=identity.repository,
        workflow_id=identity.caller_workflow_id,
        workflow_path=identity.caller_workflow_path,
        workflow_ref=identity.caller_workflow_ref,
        workflow_sha=identity.caller_workflow_sha,
        run_id=identity.upstream_run_id,
        run_attempt=identity.upstream_run_attempt,
        called_harness_repository=identity.called_harness_repository,
        called_harness_path=identity.called_harness_path,
        called_harness_sha=identity.called_harness_sha,
    )
    return identity, attestation


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def make_bundle(*, identity=None, result_raw=None, result_changes=None, manifest_changes=None, entries=None):
    identity = identity or identities()[0]
    result = {
        "run_id": "review-run-01",
        "repository": identity.repository,
        "pull_request_number": identity.pull_request_number,
        "base_sha": identity.base_sha,
        "head_sha": identity.head_sha,
        "project_profile_version": identity.profile_version,
        "disposition": "COMMENT",
    }
    result.update(result_changes or {})
    result["result_hash"] = hashlib.sha256(
        canonical({k: v for k, v in result.items() if k != "result_hash"})
    ).hexdigest()
    result_raw = canonical(result) if result_raw is None else result_raw
    manifest = {
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
        "review_run_id": result.get("run_id"),
        "result_file_sha256": hashlib.sha256(result_raw).hexdigest(),
        "result_hash": result["result_hash"],
        "created_at": "2026-09-26T17:00:00Z",
        "contract_versions": dict(identity.contract_versions),
    }
    manifest.update(manifest_changes or {})
    manifest_raw = canonical(manifest)
    if entries is None:
        entries = [(RESULT_FILENAME, result_raw), (MANIFEST_FILENAME, manifest_raw)]
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in entries:
            archive.writestr(name, raw)
    bundle = stream.getvalue()
    digest = ArtifactTransportDigest(
        source="test_fixture",
        subject="downloaded_zip_bytes",
        algorithm="sha256",
        hex_digest=hashlib.sha256(bundle).hexdigest(),
    )
    return bundle, digest


class FixtureVerifier:
    def __init__(self, identity, *, transform=None, raise_error=False):
        self.identity = identity
        self.transform = transform
        self.raise_error = raise_error
        self.called = False

    def verify(self, *, archive_sha256, subjects, expected_identity):
        self.called = True
        if self.raise_error:
            raise RuntimeError("simulated verifier secret=do-not-copy")
        proof_identity = self.transform(self.identity) if self.transform else self.identity
        return VerifiedAttestation(proof_identity, tuple(sorted(subjects.items())))


def intake(bundle, digest, *, identity=None, attestation=None, limits=None, source=None):
    expected, trusted_signer = identities()
    if identity is not None:
        expected = identity
    if attestation is None:
        attestation = trusted_signer
    return intake_artifact_bundle(
        source or io.BytesIO(bundle),
        expected,
        digest,
        trusted_attestation_identity=attestation,
        limits=limits or IntakeLimits(),
    )


def test_valid_fixed_bundle_is_parsed_but_unattested_is_not_production_admission():
    bundle, digest = make_bundle()
    receipt = intake(bundle, digest)
    assert receipt.attestation_state is AttestationState.UNAVAILABLE
    assert receipt.archive_sha256 == digest.hex_digest
    assert receipt.archive_size_bytes == len(bundle)
    assert receipt.transport_digest_source == "test_fixture"
    assert receipt.result["run_id"] == "review-run-01"
    assert receipt.manifest["upstream_run_id"] == RUN
    assert receipt.result_hash == receipt.manifest["result_hash"]
    altered = receipt.result
    altered["disposition"] = "APPROVE"
    assert receipt.result["disposition"] == "COMMENT"


def test_injected_verifier_must_bind_exact_two_subjects_signer_and_run():
    bundle, digest = make_bundle()
    expected, signer = identities()
    verifier = FixtureVerifier(signer)
    receipt = intake_artifact_bundle(
        io.BytesIO(bundle),
        expected,
        digest,
        trusted_attestation_identity=signer,
        attestation_verifier=verifier,
    )
    assert verifier.called
    assert receipt.attestation_state is AttestationState.VERIFIED


def test_boolean_or_wrong_shape_verifier_result_is_not_an_attestation():
    bundle, digest = make_bundle()
    expected, signer = identities()

    class BooleanVerifier:
        def verify(self, **_kwargs):
            return True

    with pytest.raises(ArtifactIntakeError, match="attestation_proof_invalid"):
        intake_artifact_bundle(
            io.BytesIO(bundle),
            expected,
            digest,
            trusted_attestation_identity=signer,
            attestation_verifier=BooleanVerifier(),
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"workflow_id": 999},
        {"run_attempt": 3},
        {"repository_id": 999},
        {"workflow_sha": "9" * 40},
    ],
)
def test_verifier_proof_for_wrong_trusted_signer_or_run_is_rejected(changes):
    bundle, digest = make_bundle()
    expected, signer = identities()
    verifier = FixtureVerifier(signer, transform=lambda value: AttestationIdentity(**{**value.__dict__, **changes}))
    with pytest.raises(ArtifactIntakeError, match="attestation_identity_mismatch"):
        intake_artifact_bundle(
            io.BytesIO(bundle),
            expected,
            digest,
            trusted_attestation_identity=signer,
            attestation_verifier=verifier,
        )


def test_verifier_subject_hash_must_bind_manifest_and_result_bytes():
    bundle, digest = make_bundle()
    expected, signer = identities()

    class WrongSubjectVerifier:
        def verify(self, *, archive_sha256, subjects, expected_identity):
            return VerifiedAttestation(expected_identity, ((RESULT_FILENAME, "0" * 64), (MANIFEST_FILENAME, "1" * 64)))

    with pytest.raises(ArtifactIntakeError, match="attestation_subjects_mismatch"):
        intake_artifact_bundle(
            io.BytesIO(bundle),
            expected,
            digest,
            trusted_attestation_identity=signer,
            attestation_verifier=WrongSubjectVerifier(),
        )


def test_verifier_errors_are_minimized_and_fail_closed():
    bundle, digest = make_bundle()
    expected, signer = identities()
    verifier = FixtureVerifier(signer, raise_error=True)
    with pytest.raises(ArtifactIntakeError, match="attestation_verification_failed") as caught:
        intake_artifact_bundle(
            io.BytesIO(bundle),
            expected,
            digest,
            trusted_attestation_identity=signer,
            attestation_verifier=verifier,
        )
    assert "secret" not in str(caught.value)


def test_transport_digest_must_match_exact_downloaded_zip_bytes():
    bundle, digest = make_bundle()
    wrong = ArtifactTransportDigest(digest.source, digest.subject, digest.algorithm, "0" * 64)
    with pytest.raises(ArtifactIntakeError, match="artifact_transport_digest_mismatch"):
        intake(bundle, wrong)


def test_self_consistent_forged_manifest_is_rejected_against_trusted_api_identity():
    # The result, its internal hash, manifest result digest, and transport
    # digest are all recomputed. Only the trusted expected profile hash differs.
    bundle, digest = make_bundle(manifest_changes={"profile_sha256": "8" * 64})
    with pytest.raises(ArtifactIntakeError, match="manifest_identity_mismatch"):
        intake(bundle, digest)


def test_valid_digest_artifact_from_wrong_run_is_rejected():
    bundle, digest = make_bundle(manifest_changes={"upstream_run_id": RUN + 1})
    assert hashlib.sha256(bundle).hexdigest() == digest.hex_digest
    with pytest.raises(ArtifactIntakeError, match="manifest_identity_mismatch"):
        intake(bundle, digest)


def test_result_run_id_and_result_seal_are_crosschecked():
    bundle, digest = make_bundle(manifest_changes={"review_run_id": "other-review"})
    with pytest.raises(ArtifactIntakeError, match="review_run_identity_mismatch"):
        intake(bundle, digest)

    bundle, digest = make_bundle(result_changes={"head_sha": "9" * 40})
    with pytest.raises(ArtifactIntakeError, match="result_identity_mismatch"):
        intake(bundle, digest)


@pytest.mark.parametrize(
    ("raw", "expected_code"),
    [
        (b'{"outer":{"key":1,"key":2}}', "result_json_invalid"),
        (b'{"value":NaN}', "result_json_invalid"),
        (b'{"value":Infinity}', "result_json_invalid"),
        (b'{"value":1e9999}', "result_json_invalid"),
        (b'{"value":"\xff"}', "result_json_invalid"),
    ],
    ids=["duplicate_nested_key", "nan", "infinity", "float_overflow", "invalid_utf8"],
)
def test_json_rejects_duplicate_keys_nonfinite_values_bad_utf8_and_deep_nesting(raw, expected_code):
    bundle, digest = make_bundle(result_raw=raw)
    with pytest.raises(ArtifactIntakeError, match=expected_code):
        intake(bundle, digest)


def test_json_rejects_excessive_nesting_with_a_bounded_error():
    raw = b'{"value":' + b"[" * 10000 + b"0" + b"]" * 10000 + b"}"
    bundle, digest = make_bundle(result_raw=raw)
    with pytest.raises(ArtifactIntakeError, match="json_nesting_limit_exceeded"):
        intake(bundle, digest)


def test_json_rejects_excessive_container_items_before_object_allocation():
    raw = b'{"items":[' + b",".join([b"0"] * 200100) + b"]}"
    bundle, digest = make_bundle(result_raw=raw)
    with pytest.raises(ArtifactIntakeError, match="json_complexity_limit_exceeded"):
        intake(bundle, digest)


@pytest.mark.parametrize(
    ("members", "expected_code"),
    [
        ([("../review-result.json", b"{}"), (MANIFEST_FILENAME, b"{}")], "archive_path_invalid"),
        ([("/review-result.json", b"{}"), (MANIFEST_FILENAME, b"{}")], "archive_path_invalid"),
        ([("C:/review-result.json", b"{}"), (MANIFEST_FILENAME, b"{}")], "archive_path_invalid"),
        ([("review-result.json", b"{}"), ("./review-result.json", b"{}")], "archive_duplicate_path"),
        ([("review-result.json", b"{}"), ("REVIEW-RESULT.JSON", b"{}")], "archive_duplicate_path"),
        ([("review-result.json/", b""), (MANIFEST_FILENAME, b"{}")], "archive_member_type_unsupported"),
    ],
)
def test_zip_names_and_directory_entries_fail_closed(members, expected_code):
    bundle, digest = make_bundle(entries=members)
    with pytest.raises(ArtifactIntakeError, match=expected_code):
        intake(bundle, digest)


def test_zip_rejects_extra_regular_files_even_when_required_files_exist():
    bundle, _ = make_bundle()
    with zipfile.ZipFile(io.BytesIO(bundle), "r") as archive:
        entries = [(entry.filename, archive.read(entry)) for entry in archive.infolist()]
    entries.append(("README.txt", b"unexpected"))
    bundle, digest = make_bundle(entries=entries)
    with pytest.raises(ArtifactIntakeError, match="archive_file_count_invalid"):
        intake(bundle, digest)


def test_zip_rejects_symlinks_and_unsupported_compression():
    result, _ = make_bundle()
    with zipfile.ZipFile(io.BytesIO(result), "r") as original:
        data = {entry.filename: original.read(entry) for entry in original.infolist()}
    stream = io.BytesIO()
    symlink = zipfile.ZipInfo(RESULT_FILENAME)
    symlink.create_system = 3
    symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(symlink, data[RESULT_FILENAME])
        archive.writestr(MANIFEST_FILENAME, data[MANIFEST_FILENAME])
    bundle = stream.getvalue()
    digest = ArtifactTransportDigest(
        "test_fixture", "downloaded_zip_bytes", "sha256", hashlib.sha256(bundle).hexdigest()
    )
    with pytest.raises(ArtifactIntakeError, match="archive_member_type_unsupported"):
        intake(bundle, digest)

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_BZIP2) as archive:
        archive.writestr(RESULT_FILENAME, data[RESULT_FILENAME])
        archive.writestr(MANIFEST_FILENAME, data[MANIFEST_FILENAME])
    bundle = stream.getvalue()
    digest = ArtifactTransportDigest(
        "test_fixture", "downloaded_zip_bytes", "sha256", hashlib.sha256(bundle).hexdigest()
    )
    with pytest.raises(ArtifactIntakeError, match="archive_compression_unsupported"):
        intake(bundle, digest)


@pytest.mark.parametrize("file_type", [stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO])
def test_zip_rejects_nonregular_file_types(file_type):
    bundle, _ = make_bundle()
    with zipfile.ZipFile(io.BytesIO(bundle), "r") as original:
        entries = {entry.filename: original.read(entry) for entry in original.infolist()}
    stream = io.BytesIO()
    special = zipfile.ZipInfo(RESULT_FILENAME)
    special.create_system = 3
    special.external_attr = (file_type | 0o600) << 16
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(special, entries[RESULT_FILENAME])
        archive.writestr(MANIFEST_FILENAME, entries[MANIFEST_FILENAME])
    archive_bytes = stream.getvalue()
    digest = ArtifactTransportDigest(
        "test_fixture", "downloaded_zip_bytes", "sha256", hashlib.sha256(archive_bytes).hexdigest()
    )
    with pytest.raises(ArtifactIntakeError, match="archive_member_type_unsupported"):
        intake(archive_bytes, digest)


def test_zip_rejects_encrypted_entries_before_decompression():
    bundle, _ = make_bundle()
    altered = bytearray(bundle)
    cursor = 0
    while True:
        local = altered.find(b"PK\x03\x04", cursor)
        central = altered.find(b"PK\x01\x02", cursor)
        candidates = [(local, 6), (central, 8)]
        position, flag_offset = min((item for item in candidates if item[0] >= 0), default=(-1, -1))
        if position < 0:
            break
        flag_position = position + flag_offset
        flags = int.from_bytes(altered[flag_position : flag_position + 2], "little") | 1
        altered[flag_position : flag_position + 2] = flags.to_bytes(2, "little")
        cursor = position + 4
    archive_bytes = bytes(altered)
    digest = ArtifactTransportDigest(
        "test_fixture", "downloaded_zip_bytes", "sha256", hashlib.sha256(archive_bytes).hexdigest()
    )
    with pytest.raises(ArtifactIntakeError, match="archive_member_type_unsupported"):
        intake(archive_bytes, digest)


class TrackingStream(io.BytesIO):
    def __init__(self, content):
        super().__init__(content)
        self.total_read = 0
        self.max_requested = 0

    def read(self, size=-1):
        self.max_requested = max(self.max_requested, size)
        value = super().read(size)
        self.total_read += len(value)
        return value


def test_compressed_archive_limit_is_enforced_during_streaming_read():
    source = TrackingStream(b"x" * 1000)
    with pytest.raises(ArtifactIntakeError, match="archive_compressed_limit_exceeded"):
        intake_artifact_bundle(
            source,
            identities()[0],
            ArtifactTransportDigest("test_fixture", "downloaded_zip_bytes", "sha256", "0" * 64),
            trusted_attestation_identity=identities()[1],
            limits=IntakeLimits(max_archive_bytes=64),
        )
    assert source.total_read == 65
    assert source.max_requested == 65


def test_expanded_archive_limit_is_enforced_while_decompressing():
    bundle, digest = make_bundle()
    with pytest.raises(ArtifactIntakeError, match="archive_expanded_limit_exceeded"):
        intake(
            bundle,
            digest,
            limits=IntakeLimits(max_total_expanded_bytes=1024),
        )


def test_duplicate_normalized_json_path_not_hidden_by_distinct_zip_names():
    bundle, digest = make_bundle(entries=[("review-result.json", b"{}"), ("Review-Result.json", b"{}")])
    with pytest.raises(ArtifactIntakeError, match="archive_duplicate_path"):
        intake(bundle, digest)
