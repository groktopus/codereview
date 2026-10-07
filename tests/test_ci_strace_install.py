from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts/install_ci_strace.sh"


def _fake_command(path: Path, name: str, body: str) -> None:
    executable = path / name
    executable.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body, encoding="utf-8")
    executable.chmod(0o755)


def _fixture(tmp_path: Path, *, fail_first_update: bool = False, always_fail: bool = False,
             install_strace: bool = True, existing_strace: bool = False) -> tuple[Path, dict[str, str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "commands.log"
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_BIN": str(bin_dir),
        "FAKE_LOG": str(log),
        "FAKE_FAIL_FIRST_UPDATE": "1" if fail_first_update else "0",
        "FAKE_ALWAYS_FAIL": "1" if always_fail else "0",
        "FAKE_INSTALL_STRACE": "1" if install_strace else "0",
    }
    _fake_command(
        bin_dir,
        "timeout",
        'printf "timeout %s\\n" "$*" >> "$FAKE_LOG"\n'
        '[[ "$1" == "--kill-after=5s" ]] && shift\n'
        '[[ "$1" == "60s" ]] && shift\n'
        'exec "$@"\n',
    )
    _fake_command(
        bin_dir,
        "sudo",
        'printf "sudo %s\\n" "$*" >> "$FAKE_LOG"\nexec "$@"\n',
    )
    _fake_command(
        bin_dir,
        "apt-get",
        'printf "apt-get %s\\n" "$*" >> "$FAKE_LOG"\n'
        'action="${!#}"\n'
        'if [[ "$FAKE_ALWAYS_FAIL" == "1" ]]; then exit 41; fi\n'
        'if [[ "$action" == "update" ]]; then\n'
        '  count=0; [[ -f "$FAKE_LOG.update-count" ]] && count="$(cat "$FAKE_LOG.update-count")"\n'
        '  count=$((count + 1)); printf "%s" "$count" > "$FAKE_LOG.update-count"\n'
        '  if [[ "$FAKE_FAIL_FIRST_UPDATE" == "1" && "$count" == "1" ]]; then exit 42; fi\n'
        'elif [[ "$action" == "strace" && "$FAKE_INSTALL_STRACE" == "1" ]]; then\n'
        '  printf "#!/bin/sh\\nexit 0\\n" > "$FAKE_BIN/strace"; chmod +x "$FAKE_BIN/strace"\n'
        'fi\n',
    )
    if existing_strace:
        _fake_command(bin_dir, "strace", "exit 0\n")
    return bin_dir, env, log


def _run(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(INSTALLER)], env=env, capture_output=True, text=True, timeout=10, check=False
    )


def test_installer_uses_existing_strace_without_apt_or_sudo(tmp_path: Path):
    _, env, log = _fixture(tmp_path, existing_strace=True)

    completed = _run(env)

    assert completed.returncode == 0
    assert "Using existing strace:" in completed.stdout
    assert not log.exists()


def test_installer_retries_once_with_bounded_apt_options_and_requires_strace(tmp_path: Path):
    _, env, log = _fixture(tmp_path, fail_first_update=True)

    completed = _run(env)

    assert completed.returncode == 0
    assert "attempt 1 failed" in completed.stderr
    assert "Installed strace:" in completed.stdout
    lines = log.read_text(encoding="utf-8").splitlines()
    assert sum(line.startswith("timeout ") for line in lines) == 2
    apt_lines = [line for line in lines if line.startswith("apt-get ")]
    assert len(apt_lines) == 3
    assert sum(line.endswith(" update") for line in apt_lines) == 2
    assert sum(" install --yes --no-install-recommends strace" in line for line in apt_lines) == 1
    assert all("Acquire::http::Timeout=15" in line for line in apt_lines)
    assert all("Acquire::https::Timeout=15" in line for line in apt_lines)
    assert all("Acquire::Retries=0" in line for line in apt_lines)
    assert all("--kill-after=5s 60s" in line for line in lines if line.startswith("timeout "))


def test_installer_fails_after_two_attempts_when_apt_cannot_complete(tmp_path: Path):
    _, env, log = _fixture(tmp_path, always_fail=True)

    completed = _run(env)

    assert completed.returncode != 0
    assert "after two bounded attempts" in completed.stderr
    lines = log.read_text(encoding="utf-8").splitlines()
    assert sum(line.startswith("timeout ") for line in lines) == 2
    assert sum(line.startswith("apt-get ") and line.endswith(" update") for line in lines) == 2


def test_installer_does_not_succeed_when_apt_returns_without_strace(tmp_path: Path):
    _, env, log = _fixture(tmp_path, install_strace=False)

    completed = _run(env)

    assert completed.returncode != 0
    assert "apt completed but strace is not available" in completed.stderr
    assert "after two bounded attempts" in completed.stderr
    lines = log.read_text(encoding="utf-8").splitlines()
    assert sum(line.startswith("timeout ") for line in lines) == 2
    apt_lines = [line for line in lines if line.startswith("apt-get ")]
    assert sum(" install --yes --no-install-recommends strace" in line for line in apt_lines) == 2
