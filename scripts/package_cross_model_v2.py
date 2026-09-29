#!/usr/bin/env python3
"""Build an offline, byte-verified v2 comparison from private trial artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from model_only_shadow_evaluation_identity import (  # noqa: E402
    IdentityError,
    corpus_path_for,
    plan_path_for,
    validate_identity,
)

from pr_review_harness.cross_model_package import (  # noqa: E402
    _json,
    build_cross_model_package,
)
from pr_review_harness.evaluation import EvaluationError  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True, help="fixed, validated evaluation corpus")
    parser.add_argument("--identity-manifest", type=Path, help="frozen packet identity manifest for model_teacher corpora")
    parser.add_argument("--capture-root", type=Path, required=True, help="private writer capture directory")
    parser.add_argument("--case-packet", type=Path, required=True, help="one case packet inside capture-root/case-packets")
    parser.add_argument("--shadow-root", type=Path, required=True, help="one private shadow-audit output directory")
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory for sanitized v2 input and report")
    parser.add_argument("--json", action="store_true", required=True, help="emit only sanitized status JSON")
    args = parser.parse_args(argv)
    try:
        corpus, _ = _json(args.corpus, 16 * 1024 * 1024)
        if not isinstance(corpus, dict):
            raise EvaluationError("package_json_shape_invalid")
        identity_manifest = None
        identity_plan = None
        identity_plan_sha256 = None
        manifest_path = args.identity_manifest
        plan_relative = plan_path_for(corpus.get("corpus_id"))
        if manifest_path is None and plan_relative is not None:
            manifest_path = args.corpus.parent / "manifest.json"
        if manifest_path is not None:
            identity_manifest, _ = _json(manifest_path, 1_000_000)
        if plan_relative is not None:
            expected_corpus_path = corpus_path_for(corpus.get("corpus_id"))
            if (not isinstance(expected_corpus_path, str)
                    or args.corpus.resolve() != (ROOT / expected_corpus_path).resolve()):
                raise EvaluationError("evaluation_identity_corpus_path_mismatch")
            plan_path = ROOT / plan_relative
            if not plan_path.is_file():
                raise EvaluationError("evaluation_identity_plan_unavailable")
            identity_plan, plan_raw = _json(plan_path, 1_000_000)
            identity_plan_sha256 = hashlib.sha256(plan_raw).hexdigest()
            packet, _ = _json(args.case_packet, 4_000_000)
            validate_identity(corpus, identity_manifest, identity_plan, plan_raw, packet)
            # Keep the module-tree-pinned in-package identity gate unchanged.
            # PR-457 is validated here before entering the generic packager.
            if corpus.get("corpus_id") not in {
                "model-only-shadow-pr464-v1", "model-only-shadow-pr464-v2",
            }:
                identity_manifest = None
                identity_plan = None
                identity_plan_sha256 = None
        result = build_cross_model_package(
            corpus_value=corpus,
            case_packet_path=args.case_packet,
            capture_root=args.capture_root,
            shadow_root=args.shadow_root,
            output_dir=args.output_dir,
            identity_manifest_value=identity_manifest,
            identity_plan_value=identity_plan,
            identity_plan_sha256=identity_plan_sha256,
        )
    except EvaluationError as exc:
        print(json.dumps({"ok": False, "error_code": exc.code}, separators=(",", ":")))
        return 2
    except IdentityError as exc:
        print(json.dumps({"ok": False, "error_code": str(exc)}, separators=(",", ":")))
        return 2
    except (OSError, TypeError, ValueError):
        print('{"ok":false,"error_code":"package_input_invalid"}')
        return 2
    report = result["report"]
    print(json.dumps({
        "ok": True,
        "comparison_id": report["comparison_id"],
        "case_count": len(report["cases"]),
        "verified_artifact_count": report["artifact_verification"]["status_counts"]["VERIFIED"],
        "verified_structured_relation_count": report["assertion_verification"]["verified_structured_relation_count"],
        "claims": report["claims"],
        "comparison_path": str(args.output_dir / "comparison-v2.json"),
        "report_path": str(args.output_dir / "comparison-report.json"),
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
