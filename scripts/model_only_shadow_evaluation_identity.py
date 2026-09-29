"""Identity policy for the frozen model-only shadow screening corpora."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

IDENTITIES = {
    "model-only-shadow-pr457-v1": {
        "case_id": "PR-457",
        "plan_path": "experiments/model-only-shadow-live-pr457-plan-v2.json",
        "corpus_path": "examples/evaluation/model-only-shadow-pr457-v2/corpus.json",
        "plan_schema": "model-only-shadow-live-writer-plan.v1",
    },
    "model-only-shadow-pr457-v2": {
        "case_id": "PR-457",
        "plan_path": "experiments/model-only-shadow-live-pr457-plan-v3.json",
        "corpus_path": "examples/evaluation/model-only-shadow-pr457-v3/corpus.json",
        "plan_schema": "model-only-shadow-live-writer-plan.v2",
    },
    "model-only-shadow-pr464-v1": {
        "case_id": "PR-464",
        "plan_path": "experiments/model-only-shadow-live-pr464-plan-v2.json",
        "corpus_path": "examples/evaluation/model-only-shadow-pr464-v2/corpus.json",
        "plan_schema": "model-only-shadow-live-writer-plan.v1",
    },
    "model-only-shadow-pr464-v2": {
        "case_id": "PR-464",
        "plan_path": "experiments/model-only-shadow-live-pr464-plan-v3.json",
        "corpus_path": "examples/evaluation/model-only-shadow-pr464-v3/corpus.json",
        "plan_schema": "model-only-shadow-live-writer-plan.v2",
    },
}
MANIFEST_FIELDS = {
    "schema", "corpus_id", "dataset_version", "case_id", "repository", "base_sha", "head_sha",
    "snapshot_id", "snapshot_sha256", "profile_version", "profile_sha256", "evidence_index_sha256",
    "historical_checks_sha256", "check_evidence_sha256", "plan_path", "plan_sha256", "corpus_path",
    "corpus_sha256", "reviewer_kind", "evaluation_status", "gold_labels", "accuracy_claims", "interpretation",
}


class IdentityError(ValueError):
    pass


def plan_path_for(corpus_id: object) -> str | None:
    identity = IDENTITIES.get(corpus_id) if isinstance(corpus_id, str) else None
    return identity["plan_path"] if identity is not None else None


def corpus_path_for(corpus_id: object) -> str | None:
    identity = IDENTITIES.get(corpus_id) if isinstance(corpus_id, str) else None
    return identity["corpus_path"] if identity is not None else None


def _canonical_sha(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def validate_identity(corpus: dict[str, Any], manifest: dict[str, Any], plan: dict[str, Any],
                      plan_raw: bytes, packet: dict[str, Any]) -> None:
    corpus_id = corpus.get("corpus_id")
    expected = IDENTITIES.get(corpus_id) if isinstance(corpus_id, str) else None
    if expected is None or not isinstance(manifest, dict) or set(manifest) != MANIFEST_FIELDS:
        raise IdentityError("evaluation_identity_manifest_invalid")
    plan_path = expected["plan_path"]
    plan_sha = hashlib.sha256(plan_raw).hexdigest()
    if (manifest.get("schema") != "model-only-shadow-evaluation-identity.v1"
            or manifest.get("reviewer_kind") != "model_teacher"
            or manifest.get("evaluation_status") != "FROZEN_INPUTS_NO_MODEL_OUTPUTS"
            or manifest.get("gold_labels") != {"status": "UNAVAILABLE", "packets_present": 0}
            or manifest.get("accuracy_claims") != "NOT_ESTIMABLE_FROM_THIS_CORPUS"
            or manifest.get("corpus_id") != corpus_id
            or manifest.get("dataset_version") != corpus.get("dataset_version")
            or manifest.get("case_id") != expected["case_id"]
            or manifest.get("plan_path") != plan_path
            or manifest.get("corpus_path") != expected["corpus_path"]
            or manifest.get("corpus_sha256") != _canonical_sha(corpus)
            or manifest.get("plan_sha256") != plan_sha):
        raise IdentityError("evaluation_identity_manifest_mismatch")
    plan_case = plan.get("case") if isinstance(plan, dict) else None
    if (not isinstance(plan_case, dict)
            or plan.get("schema") != expected["plan_schema"]
            or any(manifest.get(manifest_key) != plan_case.get(plan_key) for manifest_key, plan_key in (
                ("case_id", "case_id"), ("repository", "repository"), ("base_sha", "base_sha"),
                ("head_sha", "head_sha"), ("snapshot_id", "snapshot_id"),
                ("snapshot_sha256", "snapshot_sha256"), ("profile_version", "profile_version"),
                ("profile_sha256", "profile_file_sha256"), ("evidence_index_sha256", "evidence_index_sha256"),
                ("historical_checks_sha256", "historical_checks_sha256"),
                ("check_evidence_sha256", "check_evidence_sha256"),
            ))):
        raise IdentityError("evaluation_identity_manifest_mismatch")
    cases = corpus.get("cases")
    if not isinstance(cases, list) or len(cases) != 1 or not isinstance(cases[0], dict):
        raise IdentityError("evaluation_identity_manifest_mismatch")
    identity = cases[0].get("identity")
    if not isinstance(identity, dict):
        raise IdentityError("evaluation_identity_manifest_mismatch")
    repository = identity.get("repository")
    profile = identity.get("profile")
    source_manifest = identity.get("source_manifest")
    if (not isinstance(repository, dict) or not isinstance(profile, dict) or not isinstance(source_manifest, dict)
            or manifest.get("repository") != f"{repository.get('owner')}/{repository.get('name')}"
            or manifest.get("base_sha") != identity.get("base_sha")
            or manifest.get("head_sha") != identity.get("head_sha")
            or manifest.get("snapshot_id") != identity.get("snapshot_id")
            or manifest.get("profile_version") != profile.get("version")
            or manifest.get("profile_sha256") != profile.get("sha256")
            or identity.get("case_id") != manifest.get("case_id")
            or source_manifest.get("manifest_id") != Path(plan_path).stem
            or source_manifest.get("sha256") != plan_sha):
        raise IdentityError("evaluation_identity_manifest_mismatch")
    snapshot = packet.get("snapshot")
    if not isinstance(snapshot, dict) or packet.get("case_id") != manifest["case_id"] or any(
        snapshot.get(packet_key) != manifest.get(manifest_key)
        for packet_key, manifest_key in (
            ("snapshot_id", "snapshot_id"), ("snapshot_hash", "snapshot_sha256"),
            ("base_sha", "base_sha"), ("head_sha", "head_sha"),
            ("profile_version", "profile_version"), ("profile_hash", "profile_sha256"),
        )
    ):
        raise IdentityError("case_snapshot_corpus_mismatch")
