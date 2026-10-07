#!/usr/bin/env bash
set -euo pipefail

if command -v strace >/dev/null 2>&1; then
  printf 'Using existing strace: %s\n' "$(command -v strace)"
  exit 0
fi

for command_name in timeout sudo apt-get; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Required observer installer command is unavailable: %s\n' "$command_name" >&2
    exit 127
  fi
done

for attempt in 1 2; do
  if timeout --kill-after=5s 60s bash -c '
    set -euo pipefail
    sudo apt-get \
      -o Acquire::http::Timeout=15 \
      -o Acquire::https::Timeout=15 \
      -o Acquire::Retries=0 \
      update
    sudo apt-get \
      -o Acquire::http::Timeout=15 \
      -o Acquire::https::Timeout=15 \
      -o Acquire::Retries=0 \
      install --yes --no-install-recommends strace
  '; then
    if command -v strace >/dev/null 2>&1; then
      printf 'Installed strace: %s\n' "$(command -v strace)"
      exit 0
    fi
    printf 'apt completed but strace is not available on PATH\n' >&2
  else
    status=$?
    printf 'strace installation attempt %s failed (status %s)\n' "$attempt" "$status" >&2
  fi
  if [[ "$attempt" -eq 1 ]]; then
    sleep 1
  fi
done

printf 'Unable to install the required Linux syscall observer after two bounded attempts\n' >&2
exit 1
