#!/usr/bin/env python3
"""Strict implementation typing, with finite, reviewed historical debt.

Exit 0: exact debt match; 1: new/grown/stale debt; 2: invalid environment,
configuration, checker output or baseline. No runtime code is imported/executed.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import subprocess
import sys
import tokenize
from collections import Counter
from pathlib import Path
from typing import NamedTuple, cast

SCHEMA = "pr-review-typing-baseline.v1"
BASELINE = "scripts/typing-baseline.v1.json"
CONFIG = "scripts/typing-ratchet.ini"
OWN_FILES = ("scripts/check_typing.py", "tests/test_typing_guard.py")
VERSIONS = {
    "mypy": "1.15.0",
    "mypy-extensions": "1.1.0",
    "typing-extensions": "4.16.0",
    "PyJWT": "2.15.1",
    "cryptography": "50.0.2",
    "pytest": "9.2.0",
}
FIELDS = ("path", "code", "qualname", "fingerprint")
Key = tuple[str, str, str, str]
Records = Counter[Key]
FATAL_CODES = {"import-not-found", "import-untyped", "syntax"}


class Diagnostic(NamedTuple):
    path: str
    line: int
    column: int
    code: str
    message: str


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def environment() -> dict[str, object]:
    if sys.version_info[:2] not in {(3, 11), (3, 12), (3, 13)}:
        raise ValueError("mypy 1.15.0 gate requires a Python 3.11-3.13 host (not 3.14)")
    actual = {name: importlib.metadata.version(name) for name in VERSIONS}
    if actual != VERSIONS:
        raise ValueError(f"typing tool/type-provider version mismatch: expected {VERSIONS}, got {actual}")
    return {"python": platform.python_version(), "platform": sys.platform, "distributions": actual}


def policy(root: Path) -> dict[str, object]:
    return {
        "versions": VERSIONS,
        "config_sha256": digest((root / CONFIG).read_text(encoding="utf-8")),
        "target_python": "3.11",
        "target_platform": "linux",
        "host_python": ["3.11", "3.12", "3.13"],
        "roots": ["src/**/*.py"],
        "zero_debt_files": list(OWN_FILES),
        "fingerprint": "smallest-statement-ast+message+qualified-scope.v1",
        "suppression_policy": "inventory type-ignore comments; reject mypy directives",
    }


def implementation_files(root: Path) -> list[str]:
    directory = root / "src"
    files = []
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("missing or symlinked src implementation directory")
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlink in source tree: {path.relative_to(root)}")
        if path.suffix != ".py" or not path.is_file():
            continue
        if path.with_suffix(".pyi").exists():
            raise ValueError(f"stub shadows implementation: {path.relative_to(root)}")
        files.append(path.relative_to(root).as_posix())
    if not files:
        raise ValueError("no source implementations discovered")
    for relative in OWN_FILES:
        if not (root / relative).is_file() or (root / relative).is_symlink():
            raise ValueError(f"missing/non-regular zero-debt checker file: {relative}")
    return files


def canonical(node: ast.AST) -> str:
    # Ignore empty optional AST fields added by newer host Python releases.
    def value(item: object) -> object:
        if isinstance(item, ast.AST):
            return [type(item).__name__, {k: value(v) for k, v in ast.iter_fields(item) if v is not None and v != []}]
        if isinstance(item, list):
            return [value(child) for child in item]
        return item if isinstance(item, (str, int, float, bool)) or item is None else repr(item)

    return json.dumps(value(node), sort_keys=True, ensure_ascii=True)


def anchor(tree: ast.AST, row: int, column: int) -> tuple[str, str]:
    scopes: list[tuple[str, ...]] = []
    statements: list[ast.stmt] = []

    def visit(node: ast.AST, scope: tuple[str, ...]) -> None:
        if isinstance(node, (ast.stmt, ast.expr, ast.arg, ast.keyword)):
            end_row, end_column = node.end_lineno or node.lineno, node.end_col_offset or node.col_offset
            if not (node.lineno, node.col_offset) <= (row, column) <= (end_row, end_column):
                return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope = (*scope, node.name)
            scopes.append(scope)
        if isinstance(node, ast.stmt):
            statements.append(node)
        for child in ast.iter_child_nodes(node):
            visit(child, scope)

    visit(tree, ())
    selected: tuple[str, ...] = max(scopes, key=len) if scopes else ()
    scope = ".".join(selected) if selected else "<module>"
    return scope, canonical(statements[-1] if statements else tree)


def suppression_records(path: str, source: str, tree: ast.AST) -> Records:
    records: Records = Counter()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module in {"typing", "typing_extensions"}
            and any(item.name in {"no_type_check", "*"} for item in node.names)
        ) or (isinstance(node, ast.Attribute) and node.attr == "no_type_check"):
            raise ValueError(f"no_type_check suppression or typing wildcard import is forbidden: {path}")
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type != tokenize.COMMENT:
            continue
        comment = "".join(token.string.lower().split())
        if "mypy:" in comment:
            raise ValueError(f"inline mypy directives are not allowed: {path}:{token.start[0]}")
        if "type:ignore" in comment:
            source_line = source.splitlines()[token.start[0] - 1]
            column = len(source_line) - len(source_line.lstrip())
            scope, statement = anchor(tree, token.start[0], column)
            records[(path, "type-ignore", scope, digest(statement + "\n" + token.string))] += 1
    return records


def parse_output(output: str, paths: set[str]) -> list[Diagnostic]:
    result = []
    for line in output.splitlines():
        raw = json.loads(line)
        if not isinstance(raw, dict) or raw.get("severity") not in {"error", "note"}:
            raise ValueError("invalid mypy JSON diagnostic")
        if raw["severity"] == "note":
            continue
        path, row, column, code, message = (raw.get(key) for key in ("file", "line", "column", "code", "message"))
        if not isinstance(path, str) or path not in paths:
            raise ValueError(f"mypy diagnostic outside explicit coverage: {path!r}")
        if type(row) is not int or type(column) is not int or not isinstance(code, str) or not isinstance(message, str):
            raise ValueError("invalid mypy diagnostic fields")
        if code in FATAL_CODES:
            raise ValueError(f"unbaselineable checker/import failure: {path}:{row}: {code}: {message}")
        result.append(Diagnostic(path, row, column, code, message))
    return result


def collect(root: Path) -> tuple[Records, list[str], dict[str, object]]:
    identity = environment()
    files = implementation_files(root)
    paths = [*files, *OWN_FILES]
    trees: dict[str, ast.AST] = {}
    sources: dict[str, str] = {}
    records: Records = Counter()
    for path in paths:
        sources[path] = (root / path).read_text(encoding="utf-8")
        trees[path] = ast.parse(sources[path], filename=path)
        records.update(suppression_records(path, sources[path], trees[path]))
    env = {key: value for key, value in os.environ.items() if key not in {"MYPYPATH", "MYPY_CACHE_DIR", "PYTHONPATH"}}
    result = subprocess.run(
        [sys.executable, "-I", "-m", "mypy", "--config-file", CONFIG, "--output", "json", "--no-incremental", *paths],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if result.returncode not in {0, 1} or result.stderr.strip():
        raise ValueError(f"mypy failed ({result.returncode}): {result.stderr.strip() or result.stdout.strip()}")
    diagnostics = parse_output(result.stdout, set(paths))
    if bool(diagnostics) != bool(result.returncode):
        raise ValueError("mypy exit status contradicts diagnostic output")
    for diagnostic in diagnostics:
        # Mypy 1.15 JSON columns and Python AST offsets are both UTF-8 bytes.
        scope, statement = anchor(trees[diagnostic.path], diagnostic.line, diagnostic.column)
        records[(diagnostic.path, diagnostic.code, scope, digest(statement + "\n" + diagnostic.message))] += 1
    if any(key[0] in OWN_FILES for key in records):
        raise ValueError("checker and its regression tests must have zero typing/suppression debt")
    return records, files, identity


def entries(records: Records) -> list[dict[str, object]]:
    return [dict(zip(FIELDS, key, strict=True), count=count) for key, count in sorted(records.items())]


def load_baseline(path: Path, expected_policy: dict[str, object]) -> tuple[Records, list[str]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema") != SCHEMA or raw.get("policy") != expected_policy:
        raise ValueError("baseline schema/tool/config policy mismatch")
    if not isinstance(raw.get("review_reason"), str) or len(raw["review_reason"].strip()) < 10:
        raise ValueError("baseline requires an explicit review reason")
    files = raw.get("implementation_files")
    if not isinstance(files, list) or not files or any(not isinstance(item, str) for item in files):
        raise ValueError("baseline requires implementation coverage inventory")
    if len(files) != len(set(files)) or not isinstance(raw.get("entries"), list):
        raise ValueError("duplicate coverage or invalid baseline entries")
    records: Records = Counter()
    for entry in raw["entries"]:
        if not isinstance(entry, dict) or set(entry) != {*FIELDS, "count"}:
            raise ValueError("invalid baseline entry")
        key = tuple(entry[field] for field in FIELDS)
        if not all(isinstance(item, str) and item for item in key):
            raise ValueError("invalid baseline identity")
        path_value = Path(entry["path"])
        if path_value.is_absolute() or ".." in path_value.parts or entry["path"] not in files:
            raise ValueError("baseline debt must belong to inventoried implementations")
        if entry["code"] in FATAL_CODES or len(entry["fingerprint"]) != 64:
            raise ValueError("unbaselineable code or invalid fingerprint")
        typed_key = cast(Key, key)
        if type(entry["count"]) is not int or entry["count"] <= 0 or typed_key in records:
            raise ValueError("invalid baseline count/duplicate identity")
        records[typed_key] = entry["count"]
    return records, files


def compare(current: Records, baseline: Records) -> list[dict[str, object]]:
    findings = []
    for key in sorted(current.keys() | baseline.keys()):
        actual, accepted = current[key], baseline[key]
        if actual != accepted:
            kind = "NEW_ERROR" if not accepted else "DEBT_GROWTH" if actual > accepted else "STALE_DEBT"
            findings.append(dict(zip(FIELDS, key, strict=True), kind=kind, actual=actual, accepted=accepted))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--baseline", default=BASELINE)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--write-candidate", type=Path)
    parser.add_argument("--reason", default="")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        current, files, identity = collect(root)
        expected_policy = policy(root)
        if args.write_candidate:
            candidate = root / args.write_candidate
            if candidate.resolve() == (root / args.baseline).resolve() or candidate.exists():
                raise ValueError("candidate must be a new path, not the accepted baseline")
            if len(args.reason.strip()) < 10:
                raise ValueError("candidate requires an explicit review reason of at least 10 characters")
            data = {
                "schema": SCHEMA,
                "policy": expected_policy,
                "generated_environment": identity,
                "review_reason": args.reason,
                "implementation_files": files,
                "entries": entries(current),
            }
            with candidate.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
            print(f"Candidate only: {len(files)} implementations, {sum(current.values())} debt records")
            return 0
        baseline, covered = load_baseline(root / args.baseline, expected_policy)
        findings = compare(current, baseline)
        findings.extend({"kind": "MISSING_IMPLEMENTATION", "path": path} for path in sorted(set(covered) - set(files)))
        report = {
            "status": "FAIL" if findings else "PASS",
            "environment": identity,
            "policy": expected_policy,
            "implementation_files": files,
            "new_implementations": sorted(set(files) - set(covered)),
            "zero_debt_files": list(OWN_FILES),
            "remaining_debt": sum(current.values()),
            "identities": len(current),
            "by_code": dict(
                sorted(
                    Counter(
                        {code: sum(n for k, n in current.items() if k[1] == code) for code in {k[1] for k in current}}
                    ).items()
                )
            ),
            "findings": findings,
        }
        print(
            json.dumps(report, indent=2, sort_keys=True)
            if args.json
            else f"{report['status']}: {len(files)} implementations; {sum(current.values())} debt records; {len(findings)} violations"
        )
        return 1 if findings else 0
    except (
        OSError,
        ValueError,
        SyntaxError,
        tokenize.TokenError,
        importlib.metadata.PackageNotFoundError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"typing ratchet error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
