#!/usr/bin/env python3
"""Build the fixed pilot writer config from validated, trusted environment values."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

EXPECTED_PLAN_SHA256 = "218da5b8011e0d9e391721a6e96114e9aa80f738c49eef2deb0f3c41f47d8db2"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ConfigBuildError(ValueError):
    """The trusted pilot configuration cannot be materialized safely."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ConfigBuildError("plan_json_invalid")
        value[key] = item
    return value


def build(plan_path: Path, output_dir: Path, environ: dict[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    runner_temp_value = env.get("RUNNER_TEMP")
    base_url = env.get("LLM_BASE_URL")
    model = env.get("LLM_MODEL")
    api_key = env.get("LLM_API_KEY")
    if not runner_temp_value or not base_url or not model or not api_key:
        raise ConfigBuildError("writer_secret_configuration_missing")
    runner_temp = Path(runner_temp_value).resolve(strict=True)
    out = output_dir.absolute()
    if out.parent != runner_temp or out.exists() or out.is_symlink():
        raise ConfigBuildError("private_config_path_invalid")
    try:
        plan_bytes = plan_path.read_bytes()
        plan = json.loads(
            plan_bytes.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ConfigBuildError("plan_json_invalid")),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ConfigBuildError):
        raise ConfigBuildError("trusted_plan_unavailable") from None
    if hashlib.sha256(plan_bytes).hexdigest() != EXPECTED_PLAN_SHA256:
        raise ConfigBuildError("trusted_plan_hash_mismatch")
    identity = plan.get("provider_identity") if isinstance(plan, dict) else None
    runtime = plan.get("runtime") if isinstance(plan, dict) else None
    if (
        not isinstance(identity, dict) or identity.get("status") != "PLANNED_NOT_OBSERVED_SECRET_VALUES_OPAQUE"
        or identity.get("writer_credential_env") != "LLM_API_KEY"
        or base_url != identity.get("writer_base_url") or model != identity.get("writer_model")
        or not isinstance(runtime, dict) or not SHA256.fullmatch(str(runtime.get("writer_provider_config_sha256")))
    ):
        raise ConfigBuildError("writer_provider_identity_mismatch")
    config = {
        "kind": "openai_compatible", "provider_id": identity["writer_provider_id"],
        "base_url": base_url, "model": model, "api_key_env": "LLM_API_KEY",
        "timeout_seconds": 90, "max_request_bytes": 128000, "max_response_bytes": 32768,
        "max_output_tokens": 1800, "max_output_items": 100,
    }
    config_bytes = (json.dumps(config, indent=2, allow_nan=False) + "\n").encode("utf-8")
    digest = hashlib.sha256(config_bytes).hexdigest()
    if digest != runtime["writer_provider_config_sha256"]:
        raise ConfigBuildError("writer_provider_config_pin_mismatch")
    try:
        out.mkdir(mode=0o700)
        os.chmod(out, 0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(out / "provider.json", flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ConfigBuildError("private_config_output_invalid")
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(config_bytes)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
    except (OSError, ConfigBuildError):
        raise ConfigBuildError("private_config_write_failed") from None
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        digest = build(args.plan, args.output_dir)
    except (ConfigBuildError, OSError) as exc:
        code = str(exc) if isinstance(exc, ConfigBuildError) else "private_config_write_failed"
        print(json.dumps({"ok": False, "error_code": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, "config_sha256": digest}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
