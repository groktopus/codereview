"""Run a fixed, bounded historical pilot through the public CLI (environment keys only)."""

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

HEADS = [
    "c1de456402961cf7d90703a4d8acca1a005392dc",
    "c355830512fa5bffc167926a6a167bace93d96c6",
    "3c8bc043fd96168a25246e56587f691996c5ac2d",
    "9dc787e96df24fec2b1fbff901f2f5f52b185c93",
    "63e3ecd2f09d79c34e3594a3be74f017a1c5a12c",
    "606d695515a400e9a50b18d5cfb9ef0e177e7fc5",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--output", default="artifacts/pilot")
    parser.add_argument("--decision-config")
    parser.add_argument("--head", action="append", help="Override fixed sample; maximum six SHA revisions")
    args = parser.parse_args()
    heads = args.head or HEADS
    if not 1 <= len(heads) <= 6:
        parser.error("sample must have one to six revisions")
    root = Path(__file__).resolve().parents[1]
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    stamp = str(time.time_ns())
    rows = []
    source_hashes = {}
    for folder in ("src", "profiles", "examples"):
        for path in sorted((root / folder).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                source_hashes[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = {
        "manifest_version": 1,
        "sample_kind": "purposive_recent_first_parent",
        "quality_labels": "none",
        "source_hashes": source_hashes,
        "runs": rows,
    }
    manifest_path = output / ("manifest-" + stamp + ".json")
    for index, revision in enumerate(heads):

        def git(*parts):
            return subprocess.check_output(["git", "-C", args.repo, *parts], text=True, timeout=30).strip()

        head = git("rev-parse", "--verify", "--end-of-options", revision + "^{commit}")
        base = git("rev-parse", head + "^1")
        run_id = "pilot-" + head[:12] + "-" + stamp + "-" + str(index)
        command = [
            sys.executable,
            "-m",
            "pr_review_harness",
            "review",
            "--repo",
            args.repo,
            "--base",
            base,
            "--head",
            head,
            "--profile",
            str(root / "profiles/slopsearx.json"),
            "--provider-config",
            str(root / "examples/provider.nous.json"),
            "--output",
            str(output),
            "--run-id",
            run_id,
            "--json",
        ]
        if args.decision_config:
            command += ["--decision-config", args.decision_config]
        started = time.monotonic()
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=360, cwd=root)
            (output / (run_id + ".stdout.json")).write_text(proc.stdout)
            (output / (run_id + ".stderr.txt")).write_text(proc.stderr)
            result = json.loads(proc.stdout) if proc.returncode == 0 else {}
            row = {
                "run_id": run_id,
                "base": base,
                "head": head,
                "subject": git("show", "-s", "--format=%s", head),
                "exit_code": proc.returncode,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "disposition": result.get("disposition"),
                "coverage_state": result.get("coverage_state"),
                "finding_count": len(result.get("findings", [])),
                "budget": result.get("budget"),
                "artifact": run_id + ".json",
            }
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            row = {"run_id": run_id, "base": base, "head": head, "status": "RUNNER_FAILURE"}
        rows.append(row)
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        print(json.dumps(row), flush=True)
    return 0 if all(row.get("exit_code") == 0 for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
