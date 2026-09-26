#!/usr/bin/env python3
"""Create short-lived provider configs using environment-only credentials."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit


class ConfigError(ValueError):
    """A safe configuration error code that never includes supplied values."""


ENV_NAMES = (
    "LLM_BASE_URL",
    "LLM_MODEL",
    "LLM_API_KEY",
    "JEV_BASE_URL",
    "JEV_MODEL",
    "JEV_API_KEY",
)
MAX_ENDPOINT_BYTES = 2048
MAX_MODEL_BYTES = 256
MAX_CREDENTIAL_BYTES = 8192


def _bounded_text(env: dict[str, str], name: str, limit: int) -> str:
    value = env.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{name.lower()}_required")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise ConfigError(f"{name.lower()}_invalid") from None
    if len(encoded) > limit or value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ConfigError(f"{name.lower()}_invalid")
    return value


def _validate_endpoint(value: str, name: str, *, disallow_suffix: str | None = None) -> str:
    if len(value.encode("utf-8")) > MAX_ENDPOINT_BYTES:
        raise ConfigError(f"{name.lower()}_invalid")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        # Accessing .port validates malformed port syntax.
        _ = parsed.port
    except ValueError:
        raise ConfigError(f"{name.lower()}_invalid") from None
    if disallow_suffix and parsed.path.rstrip("/").endswith(disallow_suffix):
        raise ConfigError(f"{name.lower()}_must_be_api_root")
    if (
        parsed.scheme not in {"https", "http"}
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigError(f"{name.lower()}_invalid")
    if parsed.scheme == "http":
        host = hostname.casefold()
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = host == "localhost"
        if not local:
            raise ConfigError(f"{name.lower()}_remote_http_forbidden")
    return value.rstrip("/")


def configurations_from_environment(env: dict[str, str]) -> tuple[dict[str, object], dict[str, object]]:
    """Validate six runtime variables and produce configs with references only."""
    llm_base = _validate_endpoint(
        _bounded_text(env, "LLM_BASE_URL", MAX_ENDPOINT_BYTES),
        "LLM_BASE_URL",
        disallow_suffix="/chat/completions",
    )
    llm_model = _bounded_text(env, "LLM_MODEL", MAX_MODEL_BYTES)
    _bounded_text(env, "LLM_API_KEY", MAX_CREDENTIAL_BYTES)

    jev_base = _validate_endpoint(
        _bounded_text(env, "JEV_BASE_URL", MAX_ENDPOINT_BYTES),
        "JEV_BASE_URL",
        disallow_suffix="/systemone",
    )
    jev_model = _bounded_text(env, "JEV_MODEL", MAX_MODEL_BYTES)
    _bounded_text(env, "JEV_API_KEY", MAX_CREDENTIAL_BYTES)

    provider_config: dict[str, object] = {
        "kind": "openai_compatible",
        "provider_id": "operator_openai_compatible",
        "base_url": llm_base,
        "model": llm_model,
        "api_key_env": "LLM_API_KEY",
    }
    decision_config: dict[str, object] = {
        "kind": "typesafe",
        "endpoint": f"{jev_base}/systemone",
        "model": jev_model,
        "api_key_env": "JEV_API_KEY",
    }

    # Reuse the production adapter constructors for the remaining schema checks.
    from pr_review_harness.providers import make_decision_provider, make_provider

    try:
        make_provider(provider_config)
        make_decision_provider(decision_config)
    except Exception as exc:
        code = getattr(exc, "code", None)
        if isinstance(code, str) and re.fullmatch(r"[a-z0-9_]{1,100}", code):
            raise ConfigError(code) from None
        raise ConfigError("provider_config_invalid") from None
    return provider_config, decision_config


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def write_config_files(
    output_dir: Path, provider_config: dict[str, object], decision_config: dict[str, object]
) -> dict[str, str]:
    """Create private, exclusive JSON files and return their paths only."""
    output_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(output_dir, 0o700)
    provider_path = output_dir / "provider.json"
    decision_path = output_dir / "decision.json"
    provider_bytes = (json.dumps(provider_config, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    decision_bytes = (json.dumps(decision_config, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    _write_private(provider_path, provider_bytes)
    _write_private(decision_path, decision_bytes)
    return {"provider_config": str(provider_path), "decision_config": str(decision_path)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Write provider configs from six environment variables without storing credential values.",
        epilog=(
            'Example: provider_config_from_env.py --output-dir "$RUNNER_TEMP/pr-review-provider-config" --json. '
            "LLM_BASE_URL and JEV_BASE_URL are API roots without the final route; the adapters append "
            "/chat/completions and /systemone respectively. "
            "Remote HTTP is rejected; loopback HTTP is available for local adapters."
        ),
    )
    parser.add_argument(
        "--output-dir", type=Path, required=True, help="new private directory for ephemeral config files"
    )
    parser.add_argument("--json", action="store_true", help="emit only JSON containing the two config paths")
    args = parser.parse_args(argv)
    try:
        provider_config, decision_config = configurations_from_environment(dict(os.environ))
        paths = write_config_files(args.output_dir, provider_config, decision_config)
    except ConfigError as exc:
        print(f"provider_config_from_env: {exc}", file=sys.stderr)
        return 2
    except OSError:
        print("provider_config_from_env: config_write_failed", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(paths, sort_keys=True, separators=(",", ":")))
    else:
        print(f"Provider config: {paths['provider_config']}")
        print(f"Decision config: {paths['decision_config']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
