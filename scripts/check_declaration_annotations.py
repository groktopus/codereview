#!/usr/bin/env python3
"""Ratchet missing annotations on maintained declarations and source stubs.

This checks declaration annotations only. The strict implementation mypy gate
continues to own full type analysis for ``src``.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.check_expanded_lint import EXCLUSIONS, PIN_MANIFEST, ROOTS, maintained_files  # noqa: E402

SCHEMA = "pr-review-declaration-annotations-baseline.v1"
DECLARATION_ROOTS = ("scripts", "experiments", "tests")
SOURCE_STUB_ROOT = "src"
SOURCE_STUB_GLOB = "src/**/*.pyi"
OWN_FILES = ("scripts/check_declaration_annotations.py", "tests/test_declaration_annotation_guard.py")
KEY_FIELDS = ("path", "qualname", "signature_sha256")
HEX256 = frozenset("0123456789abcdef")

Key = tuple[str, str, str]


class DeclarationError(ValueError):
    """A source declaration or baseline cannot be analyzed safely."""


@dataclass(frozen=True)
class Declaration:
    path: str
    qualname: str
    signature_sha256: str
    missing: tuple[str, ...]

    @property
    def key(self) -> Key:
        return self.path, self.qualname, self.signature_sha256


class BindingCollector(ast.NodeVisitor):
    """Collect names bound in one execution scope without entering nested scopes."""

    def __init__(self) -> None:
        self.names: list[tuple[str, str]] = []
        self._comprehension_targets: set[int] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store) and id(node) not in self._comprehension_targets:
            self.names.append((node.id, "other"))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.append((node.name, "other"))

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.append((node.name, "other"))

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.append((node.name, "other"))

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.split(".", 1)[0]
            self.names.append((bound, "other"))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name
            self.names.append((bound, "other"))

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.names.append((node.name, "other"))
        if node.type is not None:
            self.generic_visit(node.type)
        for statement in node.body:
            self.visit(statement)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node)

    def _visit_comprehension(self, node: ast.AST) -> None:
        targets = {
            id(target)
            for child in ast.walk(node)
            if isinstance(child, ast.comprehension)
            for target in ast.walk(child.target)
            if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store)
        }
        previous = self._comprehension_targets
        self._comprehension_targets = previous | targets
        self.generic_visit(node)
        self._comprehension_targets = previous


def _scope_bindings(statements: list[ast.stmt]) -> dict[str, str]:
    collected: list[tuple[str, str]] = []
    for statement in statements:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                origin = "builtins_module" if alias.name == "builtins" else "other"
                collected.append((bound, origin))
        elif isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                bound = alias.asname or alias.name
                origin = "other"
                if statement.level == 0 and statement.module == "builtins" and alias.name == "staticmethod":
                    origin = "builtin_staticmethod"
                collected.append((bound, origin))
        else:
            visitor = BindingCollector()
            visitor.visit(statement)
            collected.extend(visitor.names)
    grouped: dict[str, list[str]] = {}
    for name, origin in collected:
        grouped.setdefault(name, []).append(origin)
    return {name: values[0] if len(values) == 1 else "ambiguous" for name, values in grouped.items()}


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else None
    return None


def _is_static_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    class_node: ast.ClassDef,
    module: ast.Module,
) -> bool:
    module_prefix = [statement for statement in module.body if statement.lineno < class_node.lineno]
    module_bindings = _scope_bindings(module_prefix)
    class_prefix = [statement for statement in class_node.body if statement.lineno < node.lineno]
    class_bindings = _scope_bindings(class_prefix)

    def resolve(name: str) -> str | None:
        if name in class_bindings:
            return class_bindings[name]
        if name in module_bindings:
            return module_bindings[name]
        return None

    for decorator in node.decorator_list:
        dotted = _dotted_name(decorator)
        if dotted == "staticmethod" and resolve("staticmethod") in {None, "builtin_staticmethod"}:
            return True
        if dotted and "." not in dotted and resolve(dotted) == "builtin_staticmethod":
            return True
        if dotted and dotted.endswith(".staticmethod"):
            module_alias = dotted.removesuffix(".staticmethod")
            if resolve(module_alias) == "builtins_module":
                return True
    return False


def _arguments(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[str, ast.arg]]:
    values: list[tuple[str, ast.arg]] = []
    values.extend(("positional_only", item) for item in node.args.posonlyargs)
    values.extend(("positional_or_keyword", item) for item in node.args.args)
    if node.args.vararg:
        values.append(("vararg", node.args.vararg))
    values.extend(("keyword_only", item) for item in node.args.kwonlyargs)
    if node.args.kwarg:
        values.append(("kwarg", node.args.kwarg))
    return values


def _function_type_comment(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    receiver_index: int | None,
) -> tuple[set[int], bool] | None:
    if node.type_comment is None:
        return None
    if any(argument.annotation is not None for _, argument in _arguments(node)) or node.returns is not None:
        raise DeclarationError(f"function type comment conflicts with inline annotations at line {node.lineno}")
    try:
        parsed = ast.parse(node.type_comment, mode="func_type")
    except (SyntaxError, ValueError) as exc:
        raise DeclarationError(
            f"invalid function type comment at line {node.lineno}: {exc.msg if isinstance(exc, SyntaxError) else exc}"
        ) from None
    if not isinstance(parsed, ast.FunctionType) or (
        isinstance(parsed.returns, ast.Constant) and parsed.returns.value is Ellipsis
    ):
        raise DeclarationError(f"invalid function type comment shape at line {node.lineno}")
    arguments = _arguments(node)
    arity = len(parsed.argtypes)
    has_ellipsis = any(isinstance(value, ast.Constant) and value.value is Ellipsis for value in parsed.argtypes)
    only_ellipsis = (
        len(parsed.argtypes) == 1
        and isinstance(parsed.argtypes[0], ast.Constant)
        and parsed.argtypes[0].value is Ellipsis
    )
    if has_ellipsis and not only_ellipsis:
        raise DeclarationError(
            f"ellipsis cannot be mixed with explicit function type-comment arguments at line {node.lineno}"
        )
    omitted_receiver = receiver_index == 0 and arity == len(arguments) - 1
    if arity != len(arguments) and not omitted_receiver:
        if only_ellipsis:
            return set(range(len(arguments))) - ({receiver_index} if receiver_index is not None else set()), True
        raise DeclarationError(f"function type comment arity mismatch at line {node.lineno}")
    indexes = [index for index in range(len(arguments)) if not (omitted_receiver and index == receiver_index)]
    missing = {
        indexes[position]
        for position, value in enumerate(parsed.argtypes)
        if isinstance(value, ast.Constant) and value.value is Ellipsis
    }
    if receiver_index is not None:
        missing.discard(receiver_index)
    return missing, False


def _qualname(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    parts: list[str] = [node.name] if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) else []
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            parts.append(current.name)
    return ".".join(reversed(parts))


def _signature_digest(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    arguments: list[tuple[str, ast.arg]],
    missing: list[str],
    *,
    receiver_index: int | None,
    static_method: bool,
    implicit_init_return: bool,
    comment_uses_ellipsis: bool,
) -> str:
    shape = {
        "name": node.name,
        "async": isinstance(node, ast.AsyncFunctionDef),
        "parameters": [
            {"kind": kind, "name": argument.arg, "inline_annotation": argument.annotation is not None}
            for kind, argument in arguments
        ],
        "return_annotation": node.returns is not None,
        "receiver_index": receiver_index,
        "static_method": static_method,
        "implicit_init_return": implicit_init_return,
        "function_type_comment_ellipsis": comment_uses_ellipsis,
        "missing": missing,
    }
    data = json.dumps(shape, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def declarations_for_source(path: str, source: str) -> list[Declaration]:
    try:
        tree = ast.parse(source, filename=path, type_comments=True)
    except (SyntaxError, ValueError) as exc:
        raise DeclarationError(f"cannot parse {path}: {exc}") from None
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    declarations: list[Declaration] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        parent = parents.get(node)
        class_node = parent if isinstance(parent, ast.ClassDef) else None
        static_method = bool(class_node and _is_static_decorator(node, class_node, tree))
        positional = [*node.args.posonlyargs, *node.args.args]
        receiver_index = 0 if class_node and positional and not static_method else None
        arguments = _arguments(node)
        implicit_init_return = bool(
            class_node and node.name == "__init__" and any(argument.annotation is not None for _, argument in arguments)
        )
        comment_result = _function_type_comment(node, receiver_index=receiver_index)
        missing: list[str] = []
        if comment_result is not None:
            comment_missing, comment_uses_ellipsis = comment_result
            for index in sorted(comment_missing):
                kind, argument = arguments[index]
                missing.append(f"{kind}:{argument.arg}")
            missing_return = False
        else:
            comment_uses_ellipsis = False
            for index, (kind, argument) in enumerate(arguments):
                if argument.annotation is None and index != receiver_index:
                    missing.append(f"{kind}:{argument.arg}")
            missing_return = node.returns is None and not implicit_init_return
        if missing_return:
            missing.append("return")
        if not missing:
            continue
        declarations.append(
            Declaration(
                path=path,
                qualname=_qualname(node, parents),
                signature_sha256=_signature_digest(
                    node,
                    arguments,
                    missing,
                    receiver_index=receiver_index,
                    static_method=static_method,
                    implicit_init_return=implicit_init_return,
                    comment_uses_ellipsis=comment_uses_ellipsis,
                ),
                missing=tuple(missing),
            )
        )
    return declarations


def maintained_declarations(root: Path) -> tuple[Counter[Key], dict[Key, tuple[str, ...]], int]:
    counts: Counter[Key] = Counter()
    missing_by_key: dict[Key, tuple[str, ...]] = {}
    files = [
        path
        for path in maintained_files(root)
        if path.relative_to(root).parts[0] in DECLARATION_ROOTS
        or (path.relative_to(root).parts[0] == SOURCE_STUB_ROOT and path.suffix == ".pyi")
    ]
    for path in files:
        relative = path.relative_to(root).as_posix()
        for declaration in declarations_for_source(relative, path.read_text(encoding="utf-8")):
            counts[declaration.key] += 1
            prior = missing_by_key.setdefault(declaration.key, declaration.missing)
            if prior != declaration.missing:
                raise DeclarationError(f"signature fingerprint collision: {relative}::{declaration.qualname}")
    if any(key[0] in OWN_FILES for key in counts):
        raise DeclarationError("checker and its regression tests must have zero unannotated declarations")
    return counts, missing_by_key, len(files)


def policy() -> dict[str, object]:
    return {
        "roots": [*DECLARATION_ROOTS, SOURCE_STUB_GLOB],
        "maintained_roots": list(ROOTS),
        "immutable_exclusions": list(EXCLUSIONS),
        "pin_manifest": PIN_MANIFEST,
        "identity": "path+qualified-name+canonical-signature-shape.v1",
        "declaration_scope": "FunctionDef+AsyncFunctionDef; lambdas are not declarations with annotatable signatures",
        "source_stub_scope": "maintained src/**/*.pyi only; src/**/*.py implementations remain owned by strict implementation typing",
        "receiver": "first-positional-parameter-of-direct-nonstatic-class-method",
        "implicit_init_return": "mypy-implicit-None-for-class-__init__-with-any-annotated-parameter",
        "function_type_comments": "parse-func_type; exact-arity-or-bound-receiver-omission; ellipsis-does-not-annotate-explicit-parameters",
        "explicit_any": "allowed",
        "suppressions": "none; only reviewed historical baseline entries grandfather declarations",
    }


def entries(counts: Counter[Key], missing_by_key: dict[Key, tuple[str, ...]]) -> list[dict[str, object]]:
    return [
        {
            "path": key[0],
            "qualname": key[1],
            "signature_sha256": key[2],
            "missing": list(missing_by_key[key]),
            "count": count,
        }
        for key, count in sorted(counts.items())
    ]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _invalid_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


def load_baseline(path: Path) -> tuple[Counter[Key], dict[Key, tuple[str, ...]]]:
    try:
        raw = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object, parse_constant=_invalid_constant
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise DeclarationError(f"baseline is unavailable or invalid: {exc}") from None
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema", "policy", "review_reason", "entries"}
        or raw.get("schema") != SCHEMA
        or raw.get("policy") != policy()
    ):
        raise DeclarationError("baseline schema or policy mismatch")
    if not isinstance(raw.get("review_reason"), str) or len(raw["review_reason"].strip()) < 10:
        raise DeclarationError("baseline requires an explicit review reason")
    raw_entries = raw.get("entries")
    if not isinstance(raw_entries, list):
        raise DeclarationError("baseline entries must be a list")
    counts: Counter[Key] = Counter()
    missing_by_key: dict[Key, tuple[str, ...]] = {}
    for entry in raw_entries:
        if not isinstance(entry, dict) or set(entry) != {*KEY_FIELDS, "missing", "count"}:
            raise DeclarationError("baseline entry fields are invalid")
        entry_path, qualname, signature_hash = (entry.get(field) for field in KEY_FIELDS)
        missing = entry.get("missing")
        count = entry.get("count")
        if not isinstance(entry_path, str) or not isinstance(qualname, str) or not qualname:
            raise DeclarationError("baseline declaration identity is invalid")
        relative = Path(entry_path)
        if (
            not relative.parts
            or relative.is_absolute()
            or ".." in relative.parts
            or not (
                relative.parts[0] in DECLARATION_ROOTS
                or (relative.parts[0] == SOURCE_STUB_ROOT and relative.suffix == ".pyi")
            )
        ):
            raise DeclarationError("baseline path is outside maintained declaration roots")
        if relative.suffix not in {".py", ".pyi"}:
            raise DeclarationError("baseline path is not a Python declaration file")
        if not isinstance(signature_hash, str) or len(signature_hash) != 64 or not set(signature_hash) <= HEX256:
            raise DeclarationError("baseline signature fingerprint is invalid")
        if (
            not isinstance(missing, list)
            or not missing
            or not all(isinstance(item, str) and item for item in missing)
            or len(set(missing)) != len(missing)
        ):
            raise DeclarationError("baseline missing-field inventory is invalid")
        if type(count) is not int or count <= 0:
            raise DeclarationError("baseline count must be a positive integer")
        key: Key = (entry_path, qualname, signature_hash)
        if key in counts:
            raise DeclarationError("duplicate baseline declaration identity")
        counts[key] = count
        missing_by_key[key] = tuple(missing)
    return counts, missing_by_key


def compare(current: Counter[Key], baseline: Counter[Key]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for key in sorted(current.keys() | baseline.keys()):
        actual, accepted = current[key], baseline[key]
        if actual == accepted:
            continue
        kind = (
            "NEW_UNANNOTATED_DECLARATION"
            if accepted == 0
            else "DEBT_GROWTH"
            if actual > accepted
            else "STALE_ALLOWANCE"
        )
        findings.append(
            {
                "path": key[0],
                "qualname": key[1],
                "signature_sha256": key[2],
                "kind": kind,
                "actual": actual,
                "accepted": accepted,
            }
        )
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--baseline", default="scripts/declaration-annotations-baseline.v1.json")
    parser.add_argument("--write-candidate", type=Path)
    parser.add_argument("--reason", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    baseline_path = root / args.baseline
    candidate_path = root / args.write_candidate if args.write_candidate is not None else None
    try:
        current, missing_by_key, file_count = maintained_declarations(root)
        if candidate_path is not None:
            if candidate_path.resolve() == baseline_path.resolve() or candidate_path.exists():
                raise DeclarationError("candidate must be a new path, not the accepted baseline")
            if len(args.reason.strip()) < 10:
                raise DeclarationError("candidate requires a review reason of at least 10 characters")
            document = {
                "schema": SCHEMA,
                "policy": policy(),
                "review_reason": args.reason,
                "entries": entries(current, missing_by_key),
            }
            candidate_path.parent.mkdir(parents=True, exist_ok=True)
            with candidate_path.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
            print(f"Candidate only: {file_count} maintained files; {sum(current.values())} unannotated declarations")
            return 0
        baseline, baseline_missing = load_baseline(baseline_path)
        if any(missing_by_key[key] != baseline_missing[key] for key in current.keys() & baseline.keys()):
            raise DeclarationError("baseline missing-field inventory does not match its signature identity")
        findings = compare(current, baseline)
        report = {
            "status": "FAIL" if findings else "PASS",
            "maintained_file_count": file_count,
            "unannotated_declarations": sum(current.values()),
            "historical_allowance_count": sum(baseline.values()),
            "identities": len(current),
            "findings": findings,
        }
        print(
            json.dumps(report, indent=2, sort_keys=True)
            if args.json
            else f"{report['status']}: {file_count} files; {sum(current.values())} unannotated declarations; {len(findings)} findings"
        )
        return 1 if findings else 0
    except (OSError, UnicodeError, DeclarationError, SyntaxError, ValueError, RecursionError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
