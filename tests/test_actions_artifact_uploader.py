import json
import math
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ACTION = Path(__file__).parents[1] / "scripts/actions-artifact-uploader"
NODE = shutil.which("node")

_STAGE_PRELOAD = r"""
const fs = require('node:fs');
const childProcess = require('node:child_process');
const {syncBuiltinESMExports} = require('node:module');
const allowed = new Set([
  'preload_loaded', 'spawn_called', 'spawn_threw', 'child_spawn', 'child_error',
  'child_exit', 'child_close', 'stdout_data', 'stdout_end', 'stdout_close',
  'timer_scheduled', 'timer_fired', 'timer_cleared', 'before_exit', 'process_exit',
  'uncaught_exception', 'unknown_stage',
]);
const started = process.hrtime.bigint();
const MAX_RECORDS = 32;
const MAX_BYTES = 4096;
let fd = -1;
let recordCount = 0;
let outputBytes = 0;
try {
  const file = process.env.CANARY_DIAGNOSTIC_FILE;
  if (typeof file === 'string' && file.length <= 4096) {
    fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o077) !== 0) {
      fs.closeSync(fd);
      fd = -1;
    }
  }
} catch {
  fd = -1;
}
function finiteCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? Math.min(value, 2147483647) : null;
}
function record(name, {bytes, delayMs} = {}) {
  if (fd < 0 || recordCount >= MAX_RECORDS) return;
  const stage = allowed.has(name) ? name : 'unknown_stage';
  const elapsed = Number(process.hrtime.bigint() - started) / 1000000;
  const row = {stage, elapsed_ms: Math.min(1e9, Math.max(0, Math.round(elapsed * 100) / 100))};
  const safeBytes = finiteCount(bytes);
  const safeDelay = finiteCount(delayMs);
  if (safeBytes !== null) row.byte_count = safeBytes;
  if (safeDelay !== null) row.delay_ms = safeDelay;
  const line = JSON.stringify(row) + '\n';
  const size = Buffer.byteLength(line);
  if (outputBytes + size > MAX_BYTES) return;
  try {
    fs.writeSync(fd, line);
    outputBytes += size;
    recordCount += 1;
  } catch {
    try { fs.closeSync(fd); } catch {}
    fd = -1;
  }
}
const originalSpawn = childProcess.spawn;
childProcess.spawn = function (...args) {
  record('spawn_called');
  let child;
  try {
    child = originalSpawn.apply(this, args);
  } catch (error) {
    record('spawn_threw');
    throw error;
  }
  const originalChildEmit = child.emit;
  const childStages = {spawn: 'child_spawn', error: 'child_error', exit: 'child_exit', close: 'child_close'};
  child.emit = function (event, ...eventArgs) {
    if (childStages[event]) record(childStages[event]);
    return originalChildEmit.call(this, event, ...eventArgs);
  };
  if (child.stdout) {
    const originalStdoutEmit = child.stdout.emit;
    child.stdout.emit = function (event, ...eventArgs) {
      if (event === 'data' && Buffer.isBuffer(eventArgs[0])) record('stdout_data', {bytes: eventArgs[0].byteLength});
      else if (event === 'end') record('stdout_end');
      else if (event === 'close') record('stdout_close');
      return originalStdoutEmit.call(this, event, ...eventArgs);
    };
  }
  return child;
};
syncBuiltinESMExports();

const originalSetTimeout = globalThis.setTimeout;
const originalClearTimeout = globalThis.clearTimeout;
const timers = new Map();
globalThis.setTimeout = function (callback, delay, ...args) {
  if (typeof callback !== 'function') return originalSetTimeout.call(this, callback, delay, ...args);
  const delayMs = finiteCount(Number(delay)) ?? 0;
  let timer;
  const wrapped = function (...callbackArgs) {
    if (timers.has(timer)) {
      timers.delete(timer);
      record('timer_fired', {delayMs});
    }
    return callback.apply(this, callbackArgs);
  };
  timer = originalSetTimeout.call(this, wrapped, delay, ...args);
  timers.set(timer, delayMs);
  record('timer_scheduled', {delayMs});
  return timer;
};
globalThis.clearTimeout = function (timer) {
  if (timers.has(timer)) {
    const delayMs = timers.get(timer);
    timers.delete(timer);
    record('timer_cleared', {delayMs});
  }
  return originalClearTimeout.call(this, timer);
};
process.on('uncaughtExceptionMonitor', () => record('uncaught_exception'));
process.on('beforeExit', () => record('before_exit'));
process.on('exit', () => {
  record('process_exit');
  if (fd >= 0) {
    try { fs.closeSync(fd); } catch {}
    fd = -1;
  }
});
record('preload_loaded');
if (process.env.CANARY_STAGE_TEST_MODE === 'cap') {
  for (let i = 0; i < 100; i += 1) record('stdout_data', {bytes: i});
} else if (process.env.CANARY_STAGE_TEST_MODE === 'unknown') {
  record('not-a-safe-stage-name', {bytes: 7, private_data: process.env.CANARY_STAGE_TEST_SENTINEL});
  record('x'.repeat(100000), {bytes: Number.MAX_SAFE_INTEGER + 1, payload: process.env.CANARY_STAGE_TEST_SENTINEL});
}
"""


def _stage_preload(tmp_path):
    preload = tmp_path / "canary-stage-preload.cjs"
    preload.write_text(_STAGE_PRELOAD, encoding="utf-8")
    preload.chmod(0o600)
    return preload


def _stage_file(tmp_path):
    stage_file = tmp_path / "canary-stage-records.jsonl"
    fd = os.open(stage_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    return stage_file


def _read_stage_records(stage_file, forbidden=()):
    with stage_file.open("rb") as stream:
        raw = stream.read(4097)
    assert len(raw) <= 4096
    assert all(value.encode() not in raw for value in forbidden)
    lines = raw.splitlines()
    assert len(lines) <= 32
    records = [json.loads(line) for line in lines]
    allowed = {
        "preload_loaded", "spawn_called", "spawn_threw", "child_spawn", "child_error",
        "child_exit", "child_close", "stdout_data", "stdout_end", "stdout_close",
        "timer_scheduled", "timer_fired", "timer_cleared", "before_exit", "process_exit",
        "uncaught_exception", "unknown_stage",
    }
    for record in records:
        assert {"stage", "elapsed_ms"} <= set(record)
        assert set(record) <= {"stage", "elapsed_ms", "byte_count", "delay_ms"}
        assert record["stage"] in allowed
        elapsed = record["elapsed_ms"]
        assert isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool)
        assert math.isfinite(elapsed) and 0 <= elapsed <= 1e9
        assert all(
            isinstance(record[key], int)
            and not isinstance(record[key], bool)
            and 0 <= record[key] <= 2147483647
            for key in ("byte_count", "delay_ms")
            if key in record
        )
    return records


def _run_canary_with_fake_python(tmp_path, child_source, *, deadline_ms=500, path=None):
    if NODE is None:
        pytest.skip("Node.js is not available")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    child_script = tmp_path / "fake-runtime.mjs"
    child_script.write_text(child_source)
    fake_python = bin_dir / "python"
    fake_python.write_text(f"#!/bin/sh\nexec {shlex.quote(NODE)} {shlex.quote(str(child_script))}\n")
    fake_python.chmod(0o700)
    env = {
        "PATH": path if path is not None else str(bin_dir),
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
        "GITHUB_WORKSPACE": str(Path(__file__).parents[1]),
        "ACTIONS_RUNTIME_TOKEN": "runtime-test-token",
        "ACTIONS_RESULTS_URL": "https://results.actions.githubusercontent.com/",
    }
    runner = (
        "import {runCanary} from "
        + json.dumps((ACTION / "canary.mjs").as_uri())
        + f"; const result = await runCanary({{deadlineMs: {deadline_ms}}}); "
        + "process.stdout.write(result.stdout); process.exitCode = result.exitCode;"
    )
    started = time.monotonic()
    completed = subprocess.run(
        [NODE, "--input-type=module", "-e", runner],
        cwd=Path(__file__).parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return completed, time.monotonic() - started


def test_node_action_passes_runtime_credentials_only_to_bounded_python_child(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not available")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python = bin_dir / "python"
    python.write_text(
        "#!/bin/sh\n"
        'test -n "$ACTIONS_RUNTIME_TOKEN" || exit 11\n'
        'test -n "$ACTIONS_RESULTS_URL" || exit 12\n'
        'test -n "$GITHUB_TOKEN" || exit 13\n'
        'test -z "$NOUS_API_KEY" || exit 14\n'
        'test -z "$TYPESAFE_API_KEY" || exit 15\n'
        'test -z "$GITHUB_ACTOR" || exit 16\n'
        'test -z "$CANARY_TEST_SENTINEL" || exit 17\n'
        'test -z "$NODE_OPTIONS" || exit 18\n'
        'test -z "$CANARY_DIAGNOSTIC_FILE" || exit 19\n'
        'printf \'%s\\n\' \'{"state":"UNKNOWN","reason":"canary_fake_test","safe_to_publish":false}\'\n'
    )
    python.chmod(0o700)
    env = {
        "PATH": str(bin_dir),
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
        "GITHUB_WORKSPACE": str(Path(__file__).parents[1]),
        "GITHUB_TOKEN": "read-token",
        "ACTIONS_RUNTIME_TOKEN": "runtime-token",
        "ACTIONS_RESULTS_URL": "https://results.actions.githubusercontent.com/",
        "NOUS_API_KEY": "must-not-enter-python-child",
        "TYPESAFE_API_KEY": "must-not-enter-python-child",
        "GITHUB_ACTOR": "must-not-authorize-writer",
        "CANARY_TEST_SENTINEL": "private-canary-test-sentinel",
    }
    preload = _stage_preload(tmp_path)
    stage_file = _stage_file(tmp_path)
    env["CANARY_DIAGNOSTIC_FILE"] = str(stage_file)
    env["NODE_OPTIONS"] = f"--require {shlex.quote(str(preload))}"
    try:
        completed = subprocess.run(
            [node, str(ACTION / "canary.mjs")],
            cwd=Path(__file__).parents[1],
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        records = _read_stage_records(
            stage_file,
            ("read-token", "runtime-token", "must-not-enter-python-child", "must-not-authorize-writer", env["CANARY_TEST_SENTINEL"]),
        )
        raise AssertionError(f"outer_five_second_timeout; sanitized_stage_records={records!r}") from None
    records = _read_stage_records(
        stage_file,
        ("read-token", "runtime-token", "must-not-enter-python-child", "must-not-authorize-writer", env["CANARY_TEST_SENTINEL"]),
    )
    assert records and records[0]["stage"] == "preload_loaded"
    stages = {record["stage"] for record in records}
    assert {
        "spawn_called", "child_spawn", "stdout_data", "stdout_end", "child_exit",
        "child_close", "timer_scheduled", "timer_cleared", "process_exit",
    } <= stages
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        "state": "UNKNOWN",
        "reason": "canary_fake_test",
        "safe_to_publish": False,
    }
    assert "runtime-token" not in completed.stdout + completed.stderr


@pytest.mark.skipif(NODE is None, reason="Node.js is not available")
@pytest.mark.parametrize("mode", ["cap", "unknown"])
def test_stage_preload_bounds_and_sanitizes_diagnostics(tmp_path, mode):
    preload = _stage_preload(tmp_path)
    stage_file = _stage_file(tmp_path)
    forbidden = "private-stage-probe-sentinel"
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "CANARY_DIAGNOSTIC_FILE": str(stage_file),
        "CANARY_STAGE_TEST_MODE": mode,
        "CANARY_STAGE_TEST_SENTINEL": forbidden,
        "NODE_OPTIONS": f"--require {shlex.quote(str(preload))}",
    }
    subprocess.run([NODE, "-e", ""], env=env, timeout=2, check=True, capture_output=True)
    records = _read_stage_records(stage_file, (forbidden, "not-a-safe-stage-name"))
    assert records and records[0]["stage"] == "preload_loaded"
    if mode == "cap":
        assert len(records) == 32
        assert all(record["stage"] == "stdout_data" for record in records[1:])
    else:
        assert len(records) >= 4
        assert records[1]["stage"] == "unknown_stage"
        assert records[2]["stage"] == "unknown_stage"
        assert set(records[2]) == {"stage", "elapsed_ms"}
        assert b"x" * 64 not in stage_file.read_bytes()


@pytest.mark.parametrize(
    "record",
    [
        {"stage": "child_spawn", "elapsed_ms": 1, "raw_payload": "must-not-be-accepted"},
        {"stage": "child_spawn"},
        {"stage": "child_spawn", "elapsed_ms": float("nan")},
        {"stage": "child_spawn", "elapsed_ms": 1, "byte_count": 2147483648},
    ],
)
def test_stage_reader_rejects_malformed_records(tmp_path, record):
    stage_file = _stage_file(tmp_path)
    stage_file.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(AssertionError):
        _read_stage_records(stage_file)


def test_node_action_fails_closed_without_official_runtime_context(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not available")
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "GITHUB_WORKSPACE": str(Path(__file__).parents[1]),
    }
    completed = subprocess.run(
        [node, str(ACTION / "canary.mjs")],
        cwd=Path(__file__).parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        "state": "UNKNOWN",
        "reason": "actions_runtime_unavailable",
        "safe_to_publish": False,
    }


@pytest.mark.skipif(os.name == "nt", reason="process-group ownership is POSIX-specific")
def test_canary_timeout_kills_owned_process_group_and_returns_unknown(tmp_path):
    marker = tmp_path / "same-group-survived"
    child = (
        "import {spawn} from 'node:child_process';\n"
        f"const marker = {json.dumps(str(marker))};\n"
        "const code = `setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'alive'), 1400); setTimeout(() => {}, 5000)`;\n"
        "spawn(process.execPath, ['-e', code], {stdio: ['ignore', 'inherit', 'ignore']});\n"
        "setInterval(() => {}, 1000);\n"
    )
    completed, elapsed = _run_canary_with_fake_python(tmp_path, child)

    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "state": "UNKNOWN",
        "reason": "canary_deadline_exhausted",
        "safe_to_publish": False,
    }
    assert elapsed < 1.5
    time.sleep(1.5)
    assert not marker.exists()


@pytest.mark.skipif(os.name == "nt", reason="detached descendant behavior is POSIX-specific")
def test_canary_timeout_closes_owned_pipe_when_descendant_escaped_group(tmp_path):
    marker = tmp_path / "escaped-descendant-finished"
    child = (
        "import {spawn} from 'node:child_process';\n"
        f"const marker = {json.dumps(str(marker))};\n"
        "const code = `setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'finished'), 1400)`;\n"
        "spawn(process.execPath, ['-e', code], {detached: true, stdio: ['ignore', 'inherit', 'ignore']});\n"
        "setInterval(() => {}, 1000);\n"
    )
    completed, elapsed = _run_canary_with_fake_python(tmp_path, child)

    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "state": "UNKNOWN",
        "reason": "canary_deadline_exhausted",
        "safe_to_publish": False,
    }
    assert elapsed < 1.5
    deadline = time.monotonic() + 3
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.025)
    assert marker.read_text() == "finished"


def test_canary_oversized_output_is_bounded_and_fails_closed(tmp_path):
    child = "process.stdout.write('x'.repeat(70 * 1024)); setInterval(() => {}, 1000);\n"
    completed, elapsed = _run_canary_with_fake_python(tmp_path, child, deadline_ms=5_000)

    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "state": "UNKNOWN",
        "reason": "canary_runtime_failed_or_oversized",
        "safe_to_publish": False,
    }
    assert elapsed < 1.5


def test_canary_spawn_failure_does_not_leave_deadline_timer_running(tmp_path):
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()
    completed, elapsed = _run_canary_with_fake_python(
        tmp_path,
        "process.stdout.write('unused\\n');\n",
        deadline_ms=5_000,
        path=str(empty_path),
    )

    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "state": "UNKNOWN",
        "reason": "canary_runtime_failed",
        "safe_to_publish": False,
    }
    assert elapsed < 1.5


def test_canary_internal_deadline_hook_cannot_exceed_production_bound():
    if NODE is None:
        pytest.skip("Node.js is not available")
    runner = (
        "import {runCanary} from "
        + json.dumps((ACTION / "canary.mjs").as_uri())
        + "; let spawned = false; "
        + "const result = await runCanary({deadlineMs: 150001, "
        + "spawnProcess: () => { spawned = true; throw new Error('must not run'); }}); "
        + "process.stdout.write(JSON.stringify({result, spawned}));"
    )
    completed = subprocess.run(
        [NODE, "--input-type=module", "-e", runner],
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        "result": {
            "stdout": '{"state":"UNKNOWN","reason":"canary_runtime_failed","safe_to_publish":false}\n',
            "exitCode": 1,
        },
        "spawned": False,
    }
