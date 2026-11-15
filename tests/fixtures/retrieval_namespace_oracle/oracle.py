"""Independent CPython 3.11 compiler-table oracle; source is never executed.

The compiler owns local/free/global decisions. A parent index over public
symtable children finds the nearest capturable compiler local. AST traversal
only routes exact load occurrences into compiler tables; it collects no binders
and performs no lexical name resolution. No production module participates.
"""

from __future__ import annotations

import ast
import hashlib
import symtable
import sys
from typing import Any

FLAGS = ("local", "free", "global", "nonlocal", "declared_global", "parameter", "imported", "annotated", "assigned")
COMP_NAMES = {ast.ListComp: "listcomp", ast.SetComp: "setcomp", ast.DictComp: "dictcomp", ast.GeneratorExp: "genexpr"}
MAX_BYTES, MAX_NODES, MAX_DEPTH, MAX_TABLES = 8192, 1024, 8, 64


def _parse(source: str) -> ast.Module:
    if len(source.encode()) > MAX_BYTES:
        raise ValueError("source byte cap exceeded")
    tree = ast.parse(source)
    if sum(1 for _ in ast.walk(tree)) > MAX_NODES:
        raise ValueError("AST node cap exceeded")
    return tree


def _signature(node: ast.AST) -> tuple[str, str, int]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return "function", node.name, node.lineno
    if isinstance(node, ast.ClassDef):
        return "class", node.name, node.lineno
    if isinstance(node, ast.Lambda):
        return "function", "lambda", node.lineno
    return "function", COMP_NAMES[type(node)], node.lineno


class CompilerIndex:
    def __init__(self, source: str) -> None:
        self.tree = _parse(source)
        self.tables = {}
        self.parents = {}
        self.children = {}
        self.node_tables = {}
        self.source_ids = {}
        self.ast_parents = {
            id(child): parent for parent in ast.walk(self.tree) for child in ast.iter_child_nodes(parent)
        }
        self.occurrences = {}
        self.contexts = {}
        root = symtable.symtable(source, "<oracle-case>", "exec")
        self._index(root, "module", None, 0)
        self.postponed = any(
            isinstance(node, ast.ImportFrom)
            and node.module == "__future__"
            and any(alias.name == "annotations" for alias in node.names)
            for node in self.tree.body
        )
        self._walk(self.tree, "module")

    def _index(self, table: symtable.SymbolTable, key: str, parent: str | None, depth: int) -> None:
        if depth > MAX_DEPTH or len(self.tables) >= MAX_TABLES:
            raise ValueError("compiler-table resource cap exceeded")
        self.tables[key] = table
        self.parents[key] = parent
        self.children[key] = []
        for ordinal, child in enumerate(table.get_children()):
            # Ordinal identifies a concrete compiler object, never matches source.
            child_key = f"{key}/{ordinal}"
            self.children[key].append(child_key)
            self._index(child, child_key, key, depth + 1)

    def select(self, parent: str, signature: tuple[str, str, int]) -> str:
        kind, name, line = signature
        matches = [
            key
            for key in self.children[parent]
            if (self.tables[key].get_type(), self.tables[key].get_name(), self.tables[key].get_lineno())
            == (kind, name, line)
        ]
        if len(matches) != 1:
            raise ValueError(f"ambiguous_scope_mapping: {signature}: {len(matches)} matches")
        return matches[0]

    def _scope(self, node: ast.AST, parent: str | None) -> str | None:
        key = None if parent is None else self.select(parent, _signature(node))
        self.node_tables[id(node)] = key
        return key

    def _walk_args(self, args: ast.arguments, parent: str | None, annotations: bool) -> None:
        for default in (*args.defaults, *args.kw_defaults):
            if default is not None:
                self._walk(default, parent)
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg):
            if arg is not None and arg.annotation is not None:
                self._walk(arg.annotation, parent if annotations else None)

    def _walk(self, node: ast.AST, current: str | None) -> None:
        self.contexts[id(node)] = current
        if isinstance(node, ast.Name):
            self.occurrences[(node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)] = current
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                self._walk(decorator, current)
            self._walk_args(node.args, current, not self.postponed)
            if node.returns is not None:
                self._walk(node.returns, current if not self.postponed else None)
            child = self._scope(node, current)
            for statement in node.body:
                self._walk(statement, child)
            return
        if isinstance(node, ast.ClassDef):
            for expression in (*node.decorator_list, *node.bases, *node.keywords):
                self._walk(expression, current)
            child = self._scope(node, current)
            for statement in node.body:
                self._walk(statement, child)
            return
        if isinstance(node, ast.Lambda):
            self._walk_args(node.args, current, False)
            self._walk(node.body, self._scope(node, current))
            return
        if type(node) in COMP_NAMES:
            self._walk(node.generators[0].iter, current)
            child = self._scope(node, current)
            for i, generator in enumerate(node.generators):
                self._walk(generator.target, child)
                if i:
                    self._walk(generator.iter, child)
                for condition in generator.ifs:
                    self._walk(condition, child)
            for expression in (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,):
                self._walk(expression, child)
            return
        if isinstance(node, ast.AnnAssign):
            self._walk(node.target, current)
            if node.value is not None:
                self._walk(node.value, current)
            active = current is not None and not self.postponed
            self._walk(node.annotation, current if active else None)
            return
        for child in ast.iter_child_nodes(node):
            self._walk(child, current)

    def facts(self) -> list[dict[str, Any]]:
        return [
            {
                "id": key,
                "parent": self.parents[key],
                "kind": table.get_type(),
                "name": table.get_name(),
                "line": table.get_lineno(),
                "symbols": [self.symbol(key, name) for name in sorted(table.get_identifiers())],
            }
            for key, table in self.tables.items()
        ]

    def symbol(self, key: str, name: str) -> dict[str, Any]:
        symbol = self.tables[key].lookup(name)
        return {"name": name, **{flag: bool(getattr(symbol, f"is_{flag}")()) for flag in FLAGS}}

    def owner(self, key: str, name: str) -> tuple[str | None, str]:
        symbol = self.symbol(key, name)
        if symbol["local"]:
            return key, "local"
        if symbol["global"]:
            bound = name in self.tables["module"].get_identifiers() and self.symbol("module", name)["local"]
            return ("module" if bound else None), "global"
        if not symbol["free"]:
            raise ValueError("compiler symbol has no supported namespace classification")
        parent = self.parents[key]
        while parent is not None:
            table = self.tables[parent]
            if table.get_type() == "class":
                if name == "__class__":
                    return parent, "implicit_class_cell"
            elif name in table.get_identifiers():
                candidate = self.symbol(parent, name)
                if candidate["local"] and table.get_type() == "function":
                    return parent, "free"
                if candidate["declared_global"]:
                    raise ValueError("free use crosses compiler global barrier")
            parent = self.parents[parent]
        raise ValueError("free use has no capturable compiler owner")


def _source_enclosing_scope(node: ast.AST, index: CompilerIndex) -> str:
    """Source-only counterpart of compiler header/first-iterable routing."""
    path = {id(node)}
    parent = index.ast_parents.get(id(node))
    while parent is not None:
        if id(parent) in index.source_ids:
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                enters = any(id(statement) in path for statement in parent.body)
            elif isinstance(parent, ast.Lambda):
                enters = id(parent.body) in path
            else:
                enters = id(parent.generators[0].iter) not in path
            if enters:
                return index.source_ids[id(parent)]
        path.add(id(parent))
        parent = index.ast_parents.get(id(parent))
    return "module"


def _scope_map(case: dict[str, Any], index: CompilerIndex) -> dict[str, str | None]:
    scopes = {"module": "module"}
    for spec in case["scopes"]:
        if spec["id"] == "module":
            continue
        nodes = [
            node
            for node in ast.walk(index.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda, *COMP_NAMES))
            and node.lineno == spec["line"]
            and (
                "function"
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                else "class"
                if isinstance(node, ast.ClassDef)
                else "lambda"
                if isinstance(node, ast.Lambda)
                else COMP_NAMES[type(node)]
            )
            == spec["kind"]
        ]
        if len(nodes) != 1:
            raise ValueError("source scope witness does not map uniquely")
        index.source_ids[id(nodes[0])] = spec["id"]
        actual = index.node_tables[id(nodes[0])]
        if actual is not None and index.parents[actual] != scopes[spec["parent"]]:
            raise ValueError("source scope parent witness mismatch")
        if actual is None:
            syntax_parent = _source_enclosing_scope(nodes[0], index)
            if syntax_parent != spec["parent"]:
                raise ValueError("inert source scope parent witness mismatch")
        scopes[spec["id"]] = actual
    mapped = [value for value in scopes.values() if value is not None]
    if len(set(mapped)) != len(mapped) or set(mapped) != set(index.tables):
        raise ValueError(
            f"scope witness coverage is incomplete or ambiguous: {case['label']}: {mapped}: {list(index.tables)}"
        )
    return scopes


def _evaluation_context(node: ast.Name, index: CompilerIndex) -> dict[str, object]:
    """Static phase and annotation inertness are independent axes.

    ``static_immediate`` means no deferred body separates the occurrence from
    module/class evaluation and no permanently inert annotation encloses it.
    It does not assert execution: conditions, calls, exceptions and reachability
    are not evaluated. Eager comprehensions inherit their enclosing phase;
    generator first iterables inherit it while generator bodies defer.
    """
    phase = "immediate"
    annotation = "none"
    path = {id(node)}
    ancestor = index.ast_parents.get(id(node))
    while ancestor is not None:
        if isinstance(ancestor, ast.AnnAssign) and id(ancestor.annotation) in path:
            parent = index.ast_parents.get(id(ancestor))
            while parent is not None and id(parent) not in index.node_tables:
                parent = index.ast_parents.get(id(parent))
            annotation = (
                "postponed"
                if index.postponed
                else "function_local"
                if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
                else "eager"
            )
        if isinstance(ancestor, ast.arg) and ancestor.annotation is not None and id(ancestor.annotation) in path:
            annotation = "postponed" if index.postponed else "eager"
        if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if ancestor.returns is not None and id(ancestor.returns) in path:
                annotation = "postponed" if index.postponed else "eager"
            if phase == "immediate" and any(id(statement) in path for statement in ancestor.body):
                phase = "function_body"
        if phase == "immediate" and isinstance(ancestor, ast.Lambda) and id(ancestor.body) in path:
            phase = "lambda_body"
        if (
            phase == "immediate"
            and isinstance(ancestor, ast.GeneratorExp)
            and id(ancestor.generators[0].iter) not in path
        ):
            phase = "generator_body"
        path.add(id(ancestor))
        ancestor = index.ast_parents.get(id(ancestor))
    applicable = annotation not in ("function_local", "postponed")
    return {
        "evaluation_phase": phase,
        "annotation_context": annotation,
        "namespace_applicable": applicable,
        "static_immediate": applicable and phase == "immediate",
    }


def _classification(index: CompilerIndex, scope: str, facts: dict[str, Any], applicable: bool) -> str:
    if not applicable:
        return "not_applicable"
    kind = index.tables[scope].get_type()
    if kind == "module":
        return "module"
    if facts["declared_global"]:
        return "explicit_global"
    if facts["nonlocal"]:
        return "nonlocal"
    if facts["local"]:
        return "class_local" if kind == "class" else "local"
    if facts["free"]:
        return "free"
    return "class_lookup" if kind == "class" else "implicit_global"


def _role(
    case: dict[str, Any], role: dict[str, Any], index: CompilerIndex, scopes: dict[str, str | None]
) -> dict[str, Any]:
    # Marker identity and exact coordinates bind the witness to one source load.
    calls = [
        node
        for node in ast.walk(index.tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == role["marker"]
    ]
    if len(calls) != 1 or len(calls[0].args) != 1:
        raise ValueError("use witness marker is not unique")
    argument = calls[0].args[0]
    node = argument.func if isinstance(argument, ast.Call) else argument
    if not isinstance(node, ast.Name):
        raise ValueError("use witness argument is not a name or named call")
    position = (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
    if list(position) != role["position"] or node.id != role["name"] or not isinstance(node.ctx, ast.Load):
        raise ValueError("use witness occurrence mismatch")
    context = _evaluation_context(node, index)
    if any(role[key] != value for key, value in context.items()):
        raise ValueError(f"use witness evaluation context mismatch: {case['label']}: {role['marker']}")
    actual_scope = index.occurrences[position]
    expected_scope = scopes[role["scope"]] if role.get("compiler_present", role["namespace_applicable"]) else None
    if actual_scope != expected_scope:
        raise ValueError(
            f"use witness compiler scope mismatch: {case['label']}: {role['marker']}: {actual_scope} != {expected_scope}"
        )
    if actual_scope is None:
        syntax_scope = _source_enclosing_scope(node, index)
        if syntax_scope != role["scope"]:
            raise ValueError("inert use witness source scope mismatch")
        if role["classification"] != "not_applicable":
            raise ValueError("inert classification mismatch")
        if role["owner"] is not None or role["flags"]:
            raise ValueError("inert use witness cannot claim compiler owner/flags")
        return {
            "marker": role["marker"],
            "position": list(position),
            **context,
            "scope": None,
            "owner": None,
            "namespace": "not_applicable",
            "classification": "not_applicable",
        }
    facts = index.symbol(actual_scope, role["name"])
    if any(facts[flag] != value for flag, value in role["flags"].items()):
        raise ValueError(f"use witness compiler flags mismatch: {case['label']}")
    classification = _classification(index, actual_scope, facts, role["namespace_applicable"])
    if classification != role["classification"]:
        raise ValueError(
            f"use witness namespace class mismatch: {case['label']}: {classification} != {role['classification']}"
        )
    actual_owner, namespace = index.owner(actual_scope, role["name"])
    expected_owner = None if role["owner"] is None else scopes[role["owner"]]
    if actual_owner != expected_owner or (role.get("owner_kind") == "implicit_class_cell") != (
        namespace == "implicit_class_cell"
    ):
        raise ValueError(f"owner witness is not the nearest capturable compiler owner: {case['label']}")
    if "owner_flags" in role:
        owner_facts = index.symbol(actual_owner, role["name"])
        if any(owner_facts[flag] != value for flag, value in role["owner_flags"].items()):
            raise ValueError("owner witness compiler flags mismatch")
    return {
        "marker": role["marker"],
        "position": list(position),
        **context,
        "scope": actual_scope,
        "owner": actual_owner,
        "namespace": namespace if role["namespace_applicable"] else "not_applicable",
        "compiler_namespace": namespace,
        "classification": classification,
        "symbol": facts,
    }


def _effects(index: CompilerIndex) -> list[dict[str, Any]]:
    effects = []
    for node in ast.walk(index.tree):
        origin = index.contexts.get(id(node))
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                affected = "module" if isinstance(node, ast.Global) else index.owner(origin, name)[0]
                effects.append(
                    {
                        "kind": "global_directive" if isinstance(node, ast.Global) else "nonlocal_directive",
                        "origin": origin,
                        "affected": affected,
                        "name": name,
                        "position": [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset],
                    }
                )
        elif isinstance(node, ast.NamedExpr) and origin is not None:
            effects.append(
                {
                    "kind": "walrus_write",
                    "origin": origin,
                    "affected": index.owner(origin, node.target.id)[0],
                    "name": node.target.id,
                    "position": [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset],
                }
            )
        elif isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
            effects.append(
                {
                    "kind": "import_star",
                    "origin": origin,
                    "affected": origin,
                    "name": None,
                    "position": [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset],
                }
            )
    return sorted(effects, key=lambda row: (row["position"], row["kind"]))


def _digest(case: dict[str, Any]) -> str:
    source = case["source"]
    if hashlib.sha256(source.encode()).hexdigest() != case["sha256"]:
        raise ValueError("source digest mismatch")
    return source


def analyze(corpus: dict) -> dict:
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 11):
        raise ValueError("oracle requires CPython 3.11")
    if sum(len(corpus[key]) for key in ("positive", "rejected", "ambiguous")) > 1792:
        raise ValueError("case cap exceeded")
    rows = {
        "oracle": "CPython-3.11-public-symtable-v3",
        "coverage": corpus["coverage"],
        "positive": [],
        "rejected": [],
        "ambiguous": [],
        "unreachable_edges": corpus["unreachable_edges"],
    }
    for case in corpus["positive"]:
        index = CompilerIndex(_digest(case))
        scopes = _scope_map(case, index)
        corroboration = [_role(case, role, index, scopes) for role in case["roles"]]
        actual_effects = _effects(index)
        expected_effects = [
            {**effect, "origin": scopes[effect["origin"]], "affected": scopes[effect["affected"]]}
            for effect in case["effects"]
        ]
        if actual_effects != sorted(expected_effects, key=lambda row: (row["position"], row["kind"])):
            raise ValueError(f"source effect witness mismatch: {case['label']}")
        for absent in case.get("annotation", {}).get("absent_tables", []):
            if scopes[absent] is not None:
                raise ValueError("inert annotation unexpectedly has a compiler table")
        for check in case.get("compiler_checks", []):
            key = scopes[check["scope"]]
            present = key is not None and check["name"] in index.tables[key].get_identifiers()
            if present != check["present"]:
                raise ValueError("compiler symbol presence witness mismatch")
            if present and any(
                index.symbol(key, check["name"])[flag] != value for flag, value in check["flags"].items()
            ):
                raise ValueError("compiler symbol flags witness mismatch")
        rows["positive"].append(
            {
                **case,
                "scope_map": scopes,
                "corroboration": corroboration,
                "effect_corroboration": actual_effects,
                "tables": index.facts(),
            }
        )
    for case in corpus["rejected"]:
        source = _digest(case)
        try:
            _parse(source)
            symtable.symtable(source, "<rejected-case>", "exec")
        except (SyntaxError, ValueError) as exc:
            rows["rejected"].append(
                {"label": case["label"], "sha256": case["sha256"], "rejected": True, "error_type": type(exc).__name__}
            )
        else:
            raise ValueError("expected syntax rejection was accepted")
    for case in corpus["ambiguous"]:
        source = _digest(case)
        # Avoid the AST router, which itself must reject the duplicate signature.
        root = symtable.symtable(source, "<ambiguous-case>", "exec")
        signature = case["selector"]
        if signature["parent"] != "module" or case["expected"] != "ambiguous_scope_mapping":
            raise ValueError("ambiguous source witness mismatch")
        matches = [
            table
            for table in root.get_children()
            if (table.get_type(), table.get_name(), table.get_lineno())
            == (signature["kind"], signature["name"], signature["line"])
        ]
        if len(matches) < 2:
            raise ValueError("expected ambiguous selector is unique")
        try:
            CompilerIndex(source)
        except ValueError as exc:
            if "ambiguous_scope_mapping" not in str(exc):
                raise
        else:
            raise ValueError("ambiguous source mapping was accepted")
        rows["ambiguous"].append(
            {
                "label": case["label"],
                "sha256": case["sha256"],
                "expected": case["expected"],
                "matching_tables": len(matches),
                "rejected_mapping": True,
            }
        )
    return rows


if __name__ == "__main__":
    import json

    from generate import cases

    print(json.dumps(analyze(cases()), sort_keys=True, indent=2))
