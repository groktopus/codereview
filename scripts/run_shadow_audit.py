#!/usr/bin/env python3
"""Run the bounded model-only shadow audit against one sealed case packet."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness.claim_transport import ClaimTransport  # noqa: E402
from pr_review_harness.providers import OpenAIProvider, ProviderError  # noqa: E402
from pr_review_harness.shadow_audit import MAX_CASE_BYTES, run_shadow_audit  # noqa: E402


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _read_json(path: Path, limit: int) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("input_unavailable")
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev
                    or opened.st_ino != before.st_ino or opened.st_size > limit):
                raise ValueError("input_unavailable")
            chunks = bytearray()
            while len(chunks) <= limit:
                chunk = os.read(fd, min(64 * 1024, limit + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            raw = bytes(chunks)
        finally:
            os.close(fd)
    except OSError:
        raise ValueError("input_unavailable") from None
    if len(raw) > limit:
        raise ValueError("input_exceeds_limit")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid_constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ValueError("input_invalid_json") from None
    if not isinstance(value, dict):
        raise ValueError("input_invalid_shape")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", type=Path, required=True, help="frozen model-only-shadow case packet JSON")
    parser.add_argument("--source-provider-config", type=Path, required=True)
    parser.add_argument("--claim-provider-config", type=Path, required=True)
    parser.add_argument("--jev-config", type=Path, required=True, help="trusted TypeSafe decision.json")
    parser.add_argument("--output-dir", type=Path, required=True, help="new private artifact directory")
    parser.add_argument("--live", action="store_true", help="authorize up to three bounded provider calls")
    parser.add_argument("--json", action="store_true", help="emit only the sanitized manifest")
    args = parser.parse_args(argv)
    if not args.live:
        parser.error("provider dispatch requires --live after reviewing case data and egress policy")
    try:
        packet = _read_json(args.case, MAX_CASE_BYTES)
        source_config = _read_json(args.source_provider_config, 16_000)
        claim_config = _read_json(args.claim_provider_config, 16_000)
        jev_config = _read_json(args.jev_config, 16_000)
        source_provider = OpenAIProvider(source_config)
        claim_provider = OpenAIProvider(claim_config)
        jev_transport = ClaimTransport.from_decision_config(jev_config)
        result = run_shadow_audit(
            packet,
            source_provider=source_provider,
            jev_transport=jev_transport,
            claim_provider=claim_provider,
            limits={
                "max_input_bytes_per_task": 64_000,
                "max_output_bytes_per_task": 64_000,
                "deadline_seconds": 12,
            },
            output_dir=args.output_dir,
        )
    except (OSError, ValueError, ProviderError) as exc:
        code = getattr(exc, "code", None)
        if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code):
            code = "shadow_audit_failed"
        print(json.dumps({"ok": False, "error_code": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    manifest = result["manifest"]
    if args.json:
        print(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
    else:
        print(f"{manifest['terminal_state']}: {manifest['case_id']}")
        print(f"manifest: {args.output_dir / 'shadow-audit-manifest.json'}")
    return 0 if manifest["terminal_state"] in {"completed", "claim_audit_abstained", "missing_writer_candidate"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
