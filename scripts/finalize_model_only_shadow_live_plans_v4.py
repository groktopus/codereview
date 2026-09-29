#!/usr/bin/env python3
"""Freeze active PR-457/PR-464 v4 plans and evaluation identities.

Run after committing the integrated runtime. Inputs are the JSON outputs from
the exact provider-free prepare command used by the private capture workflow.
The finalizer checks that the checkout source tree equals the requested commit,
then binds plans, verifier constants, active case policy, and v4 evaluation
identity copies to those inputs and that immutable source revision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "src/pr_review_harness"
POLICY_PATH = ROOT / "scripts/shadow_case_policy.py"
VERIFIER_PATH = ROOT / "scripts/verify_model_only_shadow_live_preflight.py"
LIMITS_PATH = ROOT / "experiments/model-only-shadow-live-writer-limits-v1.json"
PROVIDER_PATH = ROOT / "experiments/model-only-shadow-live-writer-provider-v1.json"
CASES: dict[str, dict[str, Any]] = {
    "PR-457": {
        "plan": "experiments/model-only-shadow-live-pr457-plan-v4.json",
        "old_plan": "experiments/model-only-shadow-live-pr457-plan-v2.json",
        "corpus": "examples/evaluation/model-only-shadow-pr457-v4/corpus.json",
        "manifest": "examples/evaluation/model-only-shadow-pr457-v4/manifest.json",
        "old_corpus": "examples/evaluation/model-only-shadow-pr457-v2/corpus.json",
        "old_manifest": "examples/evaluation/model-only-shadow-pr457-v2/manifest.json",
        "calls": 6, "request_total": 469539, "request_max": 118490, "audit_cap": 120000,
        "snapshot_id": "snap-24293f430e4f8006a52bac18",
        "snapshot_sha256": "14bd673c2c77ffc59875c957c095b32e262d534fb581f3ec38aaf94898a19fea",
        "evidence_index_sha256": "10badb5f0c9325e55aa093788cfe6d2d45eaf8e66aef6c207a2dddc8a6bace95",
        "profile_version": "slopsearx-realcase-eval-v2-pr457-context240-window16k",
        "profile_sha256": "c3b5f82b0d2d38e3173f836a06af1b39afd8b47b81609caab5bae0e842435918",
        "historical_checks_sha256": "187bb52d825d1fa08872e4ef0b278fd0e6d9257721a459a6b6890ea8230a5977",
        "check_evidence_sha256": "7daee7f1c2e89a49c37cda4b5b204d636cf6219720df436c300d778f9fab3311",
        "scope_obligations": 14,
    },
    "PR-464": {
        "plan": "experiments/model-only-shadow-live-pr464-plan-v4.json",
        "old_plan": "experiments/model-only-shadow-live-pr464-plan-v2.json",
        "corpus": "examples/evaluation/model-only-shadow-pr464-v4/corpus.json",
        "manifest": "examples/evaluation/model-only-shadow-pr464-v4/manifest.json",
        "old_corpus": "examples/evaluation/model-only-shadow-pr464-v2/corpus.json",
        "old_manifest": "examples/evaluation/model-only-shadow-pr464-v2/manifest.json",
        "calls": 10, "request_total": 893359, "request_max": 96462, "audit_cap": 96000,
        "snapshot_id": "snap-e20deb18f2ac6cb39c6ebafd",
        "snapshot_sha256": "e45e9327fcb1ad37d6c37155fb40499f3179fc8dfd73d16a8d261f3a18691868",
        "evidence_index_sha256": "0b75fca3258bd3d75ed3d260467ec130f639f2afc59519e5f603f4d4a176e30c",
        "profile_version": "slopsearx-realcase-eval-v2-pr464-context240-window16k",
        "profile_sha256": "66e65ad3eec3e9311ff9df820ec4eba85baea236a1d56256781475455c6e0ea8",
        "historical_checks_sha256": "7198ac6bf02d3887fb065205e4ffbd48d435657027d4d5fa73168bdc900c359f",
        "check_evidence_sha256": "7187d1097d94930be5b3faf1a584cd409ecaae3f9f33789bfd6df78f5a451e7b",
        "scope_obligations": 22,
    },
}
PROVIDER_IDENTITY = {
    "status": "PLANNED_NOT_OBSERVED_SECRET_VALUES_OPAQUE",
    "writer_provider_id": "operator_openai_compatible",
    "writer_base_url": "https://inference-api.nousresearch.com/v1",
    "writer_model": "openai/gpt-6-luna",
    "writer_credential_env": "LLM_API_KEY",
}
PREPARE_BUDGET = {
    "writer_max_provider_calls": 10, "writer_max_retries_per_task": 0,
    "writer_max_request_bytes": 128000, "writer_max_response_bytes": 32768,
    "writer_max_output_tokens": 1800, "writer_deadline_seconds": 600,
    "writer_max_concurrent_scopes": 4, "writer_followup_slots": 0,
    "writer_claim_assessment_slots": 0, "writer_summary_slots": 0,
    "writer_optional_stage_slots": 0, "audit_max_provider_calls": 3,
    "audit_max_response_bytes_per_call": 64000,
    "audit_max_output_tokens_per_llm_call": 1800,
    "audit_max_deadline_seconds_per_call": 90, "audit_max_retries": 0,
    "total_provider_calls_max": 13, "total_provider_deadline_seconds_max": 870,
    "target_code_execution": False, "publication_enabled": False,
}


class FinalizeError(ValueError):
    pass


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def _read(path: Path, max_bytes: int = 4_000_000) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise FinalizeError("prepare_output_exceeds_limit")
    try:
        value = json.loads(raw, parse_constant=lambda _v: (_ for _ in ()).throw(FinalizeError("invalid_json")))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise FinalizeError("prepare_output_invalid_json") from None
    if not isinstance(value, dict):
        raise FinalizeError("prepare_output_invalid_shape")
    return value, raw


def _source_identity(revision: str) -> tuple[int, str]:
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                              capture_output=True, text=True, timeout=10).stdout.strip()
        tree = subprocess.run(["git", "rev-parse", f"{revision}^{{commit}}"], cwd=ROOT, check=True,
                              capture_output=True, text=True, timeout=10).stdout.strip()
        names_raw = subprocess.run(["git", "ls-tree", "-r", "--name-only", tree, "--", "src/pr_review_harness"],
                                   cwd=ROOT, check=True, capture_output=True, timeout=10).stdout
    except (subprocess.SubprocessError, OSError):
        raise FinalizeError("runtime_revision_unavailable") from None
    if head != tree or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise FinalizeError("runtime_worktree_revision_mismatch")
    current: dict[str, str] = {}
    for path in sorted(SOURCE_DIR.glob("*.py")):
        if path.is_file():
            current[f"src/pr_review_harness/{path.name}"] = _sha(path.read_bytes())
    names = [name.decode() for name in names_raw.splitlines() if name.endswith(b".py")]
    committed: dict[str, str] = {}
    for name in names:
        try:
            raw = subprocess.run(["git", "show", f"{tree}:{name}"], cwd=ROOT, check=True,
                                 capture_output=True, timeout=10).stdout
        except (subprocess.SubprocessError, OSError):
            raise FinalizeError("runtime_module_unavailable") from None
        committed[name] = _sha(raw)
    def digest(items: dict[str, str]) -> str:
        value = {name.removeprefix("src/"): sha for name, sha in sorted(items.items())}
        return _sha(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
    current_hash, committed_hash = digest(current), digest(committed)
    if current_hash != committed_hash or len(current) != len(committed):
        raise FinalizeError("runtime_worktree_module_tree_mismatch")
    return len(current), current_hash


def _plan(case_id: str, prepared: dict[str, Any], source_revision: str,
          module_count: int, module_tree: str) -> dict[str, Any]:
    case = CASES[case_id]
    if (
        prepared.get("command") != "review" or prepared.get("status") != "PREPARED_ONLY"
        or prepared.get("no_provider_calls") is not True
        or prepared.get("no_target_code_execution") is not True
        or prepared.get("disposition") is not None
    ):
        raise FinalizeError("provider_free_prepare_required")
    snapshot = prepared.get("snapshot")
    checks = prepared.get("checks")
    scope = prepared.get("scope")
    capacity = prepared.get("capacity")
    if not all(isinstance(x, dict) for x in (snapshot, checks, scope, capacity)):
        raise FinalizeError("prepare_identity_invalid")
    expected_snapshot = {
        "base_sha": "53dbafd9207eed175228c594058af85ed8e9bd0e" if case_id == "PR-457" else "20a743f0434a1843aa00068483f608f1e213b2af",
        "head_sha": "595f143607961d21d162efe76518d86e416d2548" if case_id == "PR-457" else "bffc26f9e4bf95aca0c252e88a2396d03ece854c",
        "snapshot_id": case["snapshot_id"], "snapshot_hash": case["snapshot_sha256"],
        "evidence_index_sha256": case["evidence_index_sha256"],
        "profile_version": case["profile_version"], "profile_file_sha256": case["profile_sha256"],
    }
    if any(snapshot.get(key) != value for key, value in expected_snapshot.items()):
        raise FinalizeError("prepare_snapshot_mismatch")
    if (checks.get("historical_check_identity", {}).get("check_document_sha256") != case["historical_checks_sha256"]
            or checks.get("check_evidence_hash") != case["check_evidence_sha256"]
            or len(scope.get("coverage_obligations", [])) != case["scope_obligations"]):
        raise FinalizeError("prepare_case_evidence_mismatch")
    requests = prepared.get("primary_requests")
    if not isinstance(requests, list) or len(requests) != case["calls"]:
        raise FinalizeError("prepare_request_count_mismatch")
    projected = []
    for row in requests:
        if not isinstance(row, dict) or row.get("admitted") is not True:
            raise FinalizeError("prepare_request_not_admitted")
        projected.append({key: row[key] for key in (
            "task_id", "lens", "input_bytes", "input_sha256", "output_bytes_cap", "output_tokens_cap"
        )})
    if (sum(row["input_bytes"] for row in projected) != case["request_total"]
            or max(row["input_bytes"] for row in projected) != case["request_max"]):
        raise FinalizeError("prepare_request_identity_mismatch")
    source = capacity.get("source_audit_preflight")
    if (not isinstance(source, dict) or source.get("active_input_limit_bytes") != case["audit_cap"]
            or source.get("status") != "ADMITTED" or source.get("request_count") != case["calls"]
            or source.get("request_bytes_max", case["audit_cap"] + 1) > case["audit_cap"]):
        raise FinalizeError("source_audit_preflight_not_admitted")
    source_rows = source.get("requests")
    if not isinstance(source_rows, list) or len(source_rows) != case["calls"]:
        raise FinalizeError("source_audit_request_set_invalid")
    source_by_id = {}
    for row in source_rows:
        if (not isinstance(row, dict) or row.get("admitted") is not True
                or not isinstance(row.get("task_id"), str)
                or isinstance(row.get("input_bytes"), bool)
                or not isinstance(row.get("input_bytes"), int)
                or not 1 <= row["input_bytes"] <= case["audit_cap"]
                or not isinstance(row.get("input_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", row["input_sha256"])
                or row["task_id"] in source_by_id):
            raise FinalizeError("source_audit_request_invalid")
        source_by_id[row["task_id"]] = row
    if set(source_by_id) != {row["task_id"] for row in projected}:
        raise FinalizeError("source_audit_request_set_invalid")
    identity_sha = snapshot.get("provider_identity_sha256")
    if not isinstance(identity_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", identity_sha):
        raise FinalizeError("provider_identity_pin_missing")
    contract_case = {
        "case_id": case_id,
        "repository": "magnus919/SlopSearX",
        "base_sha": expected_snapshot["base_sha"], "head_sha": expected_snapshot["head_sha"],
        "snapshot_id": case["snapshot_id"], "snapshot_sha256": case["snapshot_sha256"],
        "evidence_index_sha256": case["evidence_index_sha256"],
        "profile_version": case["profile_version"], "profile_file_sha256": case["profile_sha256"],
        "historical_checks_sha256": case["historical_checks_sha256"],
        "check_evidence_sha256": case["check_evidence_sha256"],
        "scope_obligations": case["scope_obligations"],
    }
    budget = {"writer_exact_call_count": case["calls"], **PREPARE_BUDGET,
              "audit_max_input_bytes_per_call": case["audit_cap"]}
    return {
        "schema": "model-only-shadow-live-writer-plan.v2",
        "status": "PREPARE_ONLY_PINNED_PLAN_NO_PROVIDER_DISPATCH",
        "case": contract_case,
        "runtime": {
            "plan_generated_from_revision": source_revision,
            "module_count": module_count, "module_tree_sha256": module_tree,
            "limits_sha256": _sha(LIMITS_PATH.read_bytes()),
            "provider_identity_sha256": identity_sha,
            "writer_provider_config_sha256": _sha(PROVIDER_PATH.read_bytes()),
        },
        "provider_identity": PROVIDER_IDENTITY,
        "budget": budget,
        "writer_requests": projected,
        "prepare_contract": {
            "profile_path": f"docs/real-case-trial-v1/profiles/{case_id}.json",
            "historical_checks_path": f"docs/real-case-trial-v1/checks/{case_id}.json",
            "limits_path": "experiments/model-only-shadow-live-writer-limits-v1.json",
            "provider_config_path": "experiments/model-only-shadow-live-writer-provider-v1.json",
            "mode": "AUTO", "effect_policy": "READ_ONLY", "prepare_only": True,
            "json_output": True, "capture_case_id": case_id, "provider_calls_before_preflight": 0,
        },
    }


def _identity_copy(case_id: str, plan: dict[str, Any], plan_sha: str) -> tuple[bytes, bytes]:
    row = CASES[case_id]
    corpus = json.loads((ROOT / row["old_corpus"]).read_text(encoding="utf-8"))
    corpus_id = f"model-only-shadow-{case_id.replace('-', '').lower()}-v4"
    corpus["corpus_id"] = corpus_id
    corpus["dataset_version"] = "2026-09-29.1"
    source_manifest = corpus["cases"][0]["identity"]["source_manifest"]
    source_manifest.update({"manifest_id": Path(row["plan"]).stem, "sha256": plan_sha})
    corpus_raw = (json.dumps(corpus, indent=2, ensure_ascii=False) + "\n").encode()
    old_manifest = json.loads((ROOT / row["old_manifest"]).read_text(encoding="utf-8"))
    manifest = dict(old_manifest)
    manifest.update({
        "corpus_id": corpus_id, "dataset_version": corpus["dataset_version"],
        "plan_path": row["plan"], "plan_sha256": plan_sha,
        "corpus_path": row["corpus"], "corpus_sha256": _sha(_canonical(corpus)),
    })
    manifest_raw = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode()
    return corpus_raw, manifest_raw


def _replace_once(raw: str, old: str, new: str, error: str) -> str:
    if raw.count(old) != 1:
        raise FinalizeError(error)
    return raw.replace(old, new, 1)


def finalize(prepared_paths: dict[str, Path], *, revision: str) -> dict[str, Any]:
    module_count, module_tree = _source_identity(revision)
    if module_count != 35:
        raise FinalizeError("runtime_module_count_unexpected")
    plan_results: dict[str, tuple[dict[str, Any], bytes, str, dict[str, Any], bytes]] = {}
    for case_id in ("PR-457", "PR-464"):
        prepared, prepared_raw = _read(prepared_paths[case_id])
        plan = _plan(case_id, prepared, revision, module_count, module_tree)
        raw = (json.dumps(plan, indent=2, ensure_ascii=False) + "\n").encode()
        plan_results[case_id] = (plan, raw, _sha(raw), prepared, prepared_raw)

    policy = POLICY_PATH.read_text(encoding="utf-8")
    verifier = VERIFIER_PATH.read_text(encoding="utf-8")
    for case_id in ("PR-457", "PR-464"):
        sha = plan_results[case_id][2]
        marker = f'"{case_id}": {{\n        "plan_relative_path": "{CASES[case_id]["plan"].replace("/", "/")}"'
        # Update the first placeholder after this case's active plan path.
        start = policy.find(marker)
        if start < 0:
            raise FinalizeError("case_policy_route_missing")
        end = policy.find('"plan_sha256": "PENDING_FINAL_V4_PLAN_SHA256"', start)
        if end < 0:
            raise FinalizeError("case_policy_pin_placeholder_missing")
        policy = policy[:end] + f'"plan_sha256": "{sha}"' + policy[end + len('"plan_sha256": "PENDING_FINAL_V4_PLAN_SHA256"'):]
    verifier = _replace_once(verifier, "EXPECTED_MODULE_COUNT = 35", f"EXPECTED_MODULE_COUNT = {module_count}", "module_count_constant_invalid")
    verifier, tree_count = re.subn(
        r'^EXPECTED_MODULE_TREE_SHA256 = "[0-9a-f]{64}"$',
        f'EXPECTED_MODULE_TREE_SHA256 = "{module_tree}"', verifier, count=1, flags=re.MULTILINE,
    )
    if tree_count != 1:
        raise FinalizeError("module_tree_constant_invalid")
    old_revision = re.search(r'if runtime.get\("plan_generated_from_revision"\) != "[0-9a-f]{40}":', verifier)
    if old_revision is None:
        raise FinalizeError("runtime_revision_constant_invalid")
    verifier = verifier[:old_revision.start()] + f'if runtime.get("plan_generated_from_revision") != "{revision}":' + verifier[old_revision.end():]

    outputs: dict[str, bytes] = {
        POLICY_PATH: policy.encode(), VERIFIER_PATH: verifier.encode(),
    }
    for case_id, row in CASES.items():
        plan, plan_raw, plan_sha, _prepared, _prepared_raw = plan_results[case_id]
        corpus_raw, manifest_raw = _identity_copy(case_id, plan, plan_sha)
        outputs[ROOT / row["plan"]] = plan_raw
        outputs[ROOT / row["corpus"]] = corpus_raw
        outputs[ROOT / row["manifest"]] = manifest_raw
        evidence = {
            "schema": "model-only-shadow-live-plan-v4-finalization.v1",
            "status": "FROZEN_PROVIDER_FREE_PREPARATION",
            "case_id": case_id, "source_revision": revision,
            "module_count": module_count, "module_tree_sha256": module_tree,
            "plan_path": row["plan"], "plan_sha256": plan_sha,
            "prepared_output_sha256": _sha(plan_results[case_id][4]),
            "provider_calls": 0, "target_code_execution": False,
        }
        evidence_path = ROOT / f"experiments/model-only-shadow-live-pr{case_id[3:]}-plan-v4-evidence.json"
        outputs[evidence_path] = (json.dumps(evidence, indent=2) + "\n").encode()
    for path, raw in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return {"schema": "model-only-shadow-live-plan-v4-finalization.v1", "status": "FROZEN",
            "source_revision": revision, "module_count": module_count, "module_tree_sha256": module_tree,
            "plans": {case: {"path": CASES[case]["plan"], "sha256": plan_results[case][2]}
                      for case in ("PR-457", "PR-464")}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr457-prepared", type=Path, required=True)
    parser.add_argument("--pr464-prepared", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    try:
        result = finalize({"PR-457": args.pr457_prepared, "PR-464": args.pr464_prepared},
                          revision=args.source_revision)
    except (FinalizeError, OSError, KeyError, TypeError, ValueError) as exc:
        code = str(exc) if isinstance(exc, FinalizeError) else "finalization_failed"
        print(json.dumps({"schema": "model-only-shadow-live-plan-v4-finalization.v1",
                          "status": "REJECTED", "error": code}, separators=(",", ":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
