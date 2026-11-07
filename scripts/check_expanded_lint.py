#!/usr/bin/env python3
"""Ratchet expanded Ruff debt without fixing code or hiding new diagnostics.

Exit 0: exact baseline match; 1: new/grown/stale debt; 2: invalid tool,
configuration, source or baseline. Candidate generation is explicit and requires
review; it never overwrites an existing accepted baseline.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import subprocess
import sys
import tokenize
from collections import Counter
from pathlib import Path

SCHEMA = "pr-review-expanded-lint-baseline.v1"
REPORT_SCHEMA = "pr-review-expanded-lint-report.v1"
RUFF_VERSION = "0.17.3"
RULES = ("B", "SIM", "UP", "C4", "RUF", "ASYNC")
CORE_RULES = ("E4", "E7", "E9", "F", "I")
PIN_MANIFEST = "tests/fixtures/frozen-runtime-7d550b6/pins.json"
ROOTS = ("src", "scripts", "experiments", "tests")
EXCLUSIONS = (
    "tests/fixtures/frozen-runtime-7d550b6/**",
    "tests/fixtures/*-base.py",
    "examples/evaluation/adversarial-pairs-v1/fixtures/**",
)
BASELINE = "scripts/expanded-lint-baseline.v1.json"
POLICY = {
    "ruff_version": RUFF_VERSION,
    "rules": list(RULES),
    "roots": list(ROOTS),
    "exclusions": list(EXCLUSIONS),
    "target_version": "py311",
    "fingerprint": "canonical-statement-ast+comment-token+message.v1",
    "ignore_noqa": True,
    "core_rules_for_noqa_context": list(CORE_RULES),
    "immutable_pin_manifest": PIN_MANIFEST,
}
KEY_FIELDS = ("path", "code", "scope", "fingerprint")


def maintained_files(root: Path) -> list[Path]:
    """Do not inherit gitignore, Ruff ignores, or local virtual environments."""
    manifest = json.loads((root / PIN_MANIFEST).read_text(encoding="utf-8"))
    pins = {path: manifest["pins"][name] for name, path in manifest["pin_files"].items()}
    for relative, digest in pins.items():
        path = root / relative
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"immutable fixture pin mismatch: {relative}")
    files = []
    for name in ROOTS:
        directory = root / name
        if not directory.is_dir():
            raise ValueError(f"missing maintained directory: {name}")
        for path in directory.rglob("*"):
            relative = path.relative_to(root)
            if path.is_symlink():
                raise ValueError(f"symlink in maintained tree: {relative}")
            if path.suffix not in {".py", ".pyi"} or not path.is_file():
                continue
            if any(
                relative.is_relative_to(pattern.removesuffix("/**"))
                if pattern.endswith("/**")
                else relative.match(pattern)
                for pattern in EXCLUSIONS
            ):
                if relative.as_posix() not in pins:
                    raise ValueError(f"unregistered immutable fixture: {relative}")
                continue
            files.append(path)
    return sorted(files)


def canonical_ast(node: object) -> object:
    """Normalize AST differences across Python 3.11-3.14 (including empty fields)."""
    if isinstance(node, ast.AST):
        fields = {}
        for name, value in ast.iter_fields(node):
            if value is None or value == []:
                continue
            fields[name] = canonical_ast(value)
        return {"node": type(node).__name__, "fields": fields}
    if isinstance(node, list):
        return [canonical_ast(item) for item in node]
    if isinstance(node, (str, int, float, bool)) or node is None:
        return node
    return {"literal": repr(node)}


def source_anchor(tree: ast.AST, row: int, column: int) -> tuple[str, str]:
    """Bind to qualified scope and AST content, never volatile line numbers."""
    scopes = []
    statements = []

    def visit(node: ast.AST, scope: tuple[str, ...]) -> None:
        if hasattr(node, "lineno"):
            start = (node.lineno, node.col_offset)
            end = (node.end_lineno, node.end_col_offset)
            if not start <= (row, column) < end:
                return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope = (*scope, node.name)
            scopes.append(scope)
        if isinstance(node, ast.stmt):
            statements.append(node)
        for child in ast.iter_child_nodes(node):
            visit(child, scope)

    visit(tree, ())
    scope = ".".join(max(scopes, key=len)) if scopes else "<module>"
    anchor = statements[-1] if statements else tree
    return scope, json.dumps(canonical_ast(anchor), sort_keys=True, ensure_ascii=True)


def collect(root: Path) -> tuple[Counter, int]:
    version = subprocess.run([sys.executable, "-m", "ruff", "--version"], capture_output=True, text=True, check=False)
    if version.returncode or version.stdout.strip() != f"ruff {RUFF_VERSION}":
        raise ValueError(f"requires ruff {RUFF_VERSION} in this Python environment; got {version.stdout.strip()!r}")
    files = maintained_files(root)
    records: Counter = Counter()
    # Bounded per-file calls avoid OS command-line limits and isolate path mapping.
    for path in files:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "ruff",
                "check",
                "--isolated",
                "--no-cache",
                "--no-fix",
                "--ignore-noqa",
                "--target-version",
                "py311",
                "--select",
                ",".join((*CORE_RULES, *RULES)),
                "--output-format",
                "json",
                str(path),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode not in (0, 1):
            raise ValueError(f"Ruff failed for {path.relative_to(root)}: {result.stderr.strip()}")
        diagnostics = json.loads(result.stdout)
        if not isinstance(diagnostics, list) or (result.returncode == 1 and not diagnostics):
            raise ValueError("invalid Ruff diagnostic output")
        for diagnostic in diagnostics:
            code = diagnostic["code"]
            if isinstance(code, str) and code.startswith(CORE_RULES):
                continue  # Existing hard lint gate owns core diagnostics, not this baseline.
            if not isinstance(code, str) or not code.startswith(RULES):
                raise ValueError(f"unexpected Ruff diagnostic: {code!r}")
            location = diagnostic["location"]
            # Ruff uses Unicode character columns; AST uses UTF-8 byte offsets.
            row = location["row"]
            column = len(source.splitlines()[row - 1][: location["column"] - 1].encode("utf-8"))
            scope, anchor = source_anchor(tree, row, column)
            for token in tokenize.generate_tokens(io.StringIO(source).readline):
                if code in {"RUF003", "RUF100"} and token.type == tokenize.COMMENT and token.start[0] == row:
                    anchor = "comment:" + token.string
                    break
            fingerprint = hashlib.sha256((anchor + "\n" + diagnostic["message"]).encode()).hexdigest()
            records[(path.relative_to(root).as_posix(), code, scope, fingerprint)] += 1
    return records, len(files)


def entries(records: Counter) -> list[dict]:
    return [dict(zip(KEY_FIELDS, key, strict=True), count=count) for key, count in sorted(records.items())]


def load_baseline(path: Path) -> Counter:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA or data.get("policy") != POLICY:
        raise ValueError("baseline schema/tool/policy mismatch; generate and review a migration candidate")
    if not isinstance(data.get("review_reason"), str) or len(data["review_reason"].strip()) < 10:
        raise ValueError("baseline requires a review reason")
    if not isinstance(data.get("entries"), list):
        raise ValueError("baseline entries must be a list")
    records: Counter = Counter()
    for entry in data["entries"]:
        if not isinstance(entry, dict) or set(entry) != {*KEY_FIELDS, "count"}:
            raise ValueError("invalid baseline entry fields")
        key = tuple(entry[field] for field in KEY_FIELDS)
        if not all(isinstance(value, str) and value for value in key):
            raise ValueError("invalid baseline identity")
        path_value = Path(entry["path"])
        if path_value.is_absolute() or ".." in path_value.parts or path_value.parts[0] not in ROOTS:
            raise ValueError("baseline path is not maintained repository-relative code")
        if not entry["code"].startswith(RULES):
            raise ValueError("baseline code outside expanded rules")
        fingerprint = entry["fingerprint"]
        if len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint):
            raise ValueError("invalid fingerprint")
        if type(entry["count"]) is not int or entry["count"] <= 0 or key in records:
            raise ValueError("invalid count or duplicate baseline identity")
        records[key] = entry["count"]
    return records


def compare(current: Counter, baseline: Counter) -> list[dict]:
    findings = []
    for key in sorted(current.keys() | baseline.keys()):
        actual, accepted = current[key], baseline[key]
        if actual == accepted:
            continue
        code = "NEW_FINDING" if not accepted else "BASELINE_GROWTH" if actual > accepted else "BASELINE_STALE"
        findings.append(dict(zip(KEY_FIELDS, key, strict=True), kind=code, actual=actual, accepted=accepted))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--baseline", type=Path, default=Path(BASELINE))
    parser.add_argument("--write-candidate", type=Path, help="write a separate baseline candidate for review")
    parser.add_argument("--reason", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    baseline_path = root / args.baseline
    try:
        if args.write_candidate is not None:
            candidate = root / args.write_candidate
            if candidate.resolve() == baseline_path.resolve() or candidate.exists():
                raise ValueError("candidate must be a new file separate from the accepted baseline")
            if len(args.reason.strip()) < 10:
                raise ValueError("candidate generation requires --reason (at least 10 characters)")
        current, file_count = collect(root)
        if args.write_candidate is not None:
            payload = {"schema": SCHEMA, "policy": POLICY, "review_reason": args.reason, "entries": entries(current)}
            candidate.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            print(f"Review candidate {args.write_candidate}: {sum(current.values())} findings in {file_count} files")
            return 0
        findings = compare(current, load_baseline(baseline_path))
    except (OSError, ValueError, SyntaxError, KeyError, TypeError) as error:
        print(f"expanded lint guard error: {error}", file=sys.stderr)
        return 2
    report = {
        "schema": REPORT_SCHEMA,
        "status": "FAIL" if findings else "PASS",
        "ruff_version": RUFF_VERSION,
        "scanned_files": file_count,
        "remaining_debt": sum(current.values()),
        "identities": len(current),
        "by_rule": dict(
            sorted(
                Counter(
                    {
                        code: sum(n for key, n in current.items() if key[1] == code)
                        for code in {key[1] for key in current}
                    }
                ).items()
            )
        ),
        "findings": findings,
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for finding in findings:
            print(
                f"{finding['kind']}: {finding['path']} {finding['code']} {finding['scope']} "
                f"{finding['accepted']} -> {finding['actual']}"
            )
        print(f"expanded lint {report['status']}: {sum(current.values())} remaining findings; {len(findings)} changes")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
