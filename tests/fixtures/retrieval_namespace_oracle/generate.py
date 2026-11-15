"""Finite source recipes with known placements; never execute the generated source.

This module does not import the oracle or any production resolver. Scope markers
are written by construction; the oracle must independently map them to CPython
compiler tables and correlate the exact marked load with its binding owner.
"""

from __future__ import annotations

import ast
import hashlib
import itertools
from collections import Counter
from collections.abc import Callable
from typing import Any

COMPS = ("listcomp", "setcomp", "dictcomp", "genexpr")
KINDS = ("function", "class", "lambda", *COMPS)
CAPS = {"transition": 256, "depth": 768, "directive_effect": 512, "annotation": 256}
LIMITS = {"cases": 1792, "source_bytes": 8192, "ast_nodes": 1024, "scope_depth": 8, "tables": 64}


def reachable(parent: str, child: str) -> bool:
    return parent in ("module", "function", "class") or child not in ("function", "class")


def _flags(kind: str, owner: str | None, use: str, binding: str = "local") -> dict[str, bool]:
    local = owner == use
    return {
        "local": local,
        "free": owner not in (None, "module", use),
        "global": owner in (None, "module") and (use == "module" or not local),
        "nonlocal": False,
        "declared_global": False,
        "parameter": local and (kind == "lambda" or binding == "parameter"),
        "imported": local and binding == "import",
    }


def _case(label: str, category: str, source: str, specs: list[tuple[str, str, str | None]], roles: list[dict]) -> dict:
    tree = ast.parse(source)
    if len(source.encode()) > LIMITS["source_bytes"] or sum(1 for _ in ast.walk(tree)) > LIMITS["ast_nodes"]:
        raise ValueError("generated source exceeds resource bounds")
    scopes = []
    for ident, kind, parent in specs:
        lines = [
            i for i, line in enumerate(source.splitlines(), 1) if f"# scope:{ident}" == line.strip().split("  ")[-1]
        ]
        if ident == "module":
            line = 0
        else:
            if len(lines) != 1:
                raise ValueError(f"missing source scope marker: {ident}: {lines}")
            line = lines[0]
        scopes.append({"id": ident, "kind": kind, "parent": parent, "line": line})
    for role in roles:
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == role["marker"]
        ]
        if len(calls) != 1 or len(calls[0].args) != 1:
            raise ValueError("role marker must identify exactly one name occurrence")
        argument = calls[0].args[0]
        node = argument.func if isinstance(argument, ast.Call) else argument
        if not isinstance(node, ast.Name):
            raise ValueError("role marker argument must identify a name or named call")
        role["position"] = [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]
        role.setdefault("name", node.id)
        scope_index = {scope["id"]: scope for scope in scopes}
        kind = scope_index[role["scope"]]["kind"]
        phase_scope = role["scope"]
        while phase_scope is not None and scope_index[phase_scope]["kind"] not in ("function", "lambda", "genexpr"):
            phase_scope = scope_index[phase_scope]["parent"]
        role["evaluation_phase"] = (
            "immediate"
            if phase_scope is None
            else {"function": "function_body", "lambda": "lambda_body", "genexpr": "generator_body"}[
                scope_index[phase_scope]["kind"]
            ]
        )
        role.setdefault("annotation_context", "none")
        role["static_immediate"] = role["namespace_applicable"] and role["evaluation_phase"] == "immediate"
        flags = role["flags"]
        role["classification"] = (
            "not_applicable"
            if not role["namespace_applicable"]
            else "module"
            if kind == "module"
            else "explicit_global"
            if flags.get("declared_global")
            else "nonlocal"
            if flags.get("nonlocal")
            else "class_local"
            if kind == "class" and flags.get("local")
            else "class_lookup"
            if kind == "class" and flags.get("global")
            else "local"
            if flags.get("local")
            else "free"
            if flags.get("free")
            else "implicit_global"
        )
    return {
        "label": label,
        "category": category,
        "source": source,
        "sha256": hashlib.sha256(source.encode()).hexdigest(),
        "scopes": scopes,
        "roles": roles,
        "effects": [],
    }


def _recipe(label: str, category: str, path: tuple[str, ...], placements: dict[int, str]) -> dict:
    """Render known nesting/binding placements (index zero denotes module)."""
    specs = [("module", "module", None)] + [
        (f"s{i}", kind, "module" if i == 1 else f"s{i - 1}") for i, kind in enumerate(path, 1)
    ]

    def body(index: int) -> str:
        if index > len(path):
            return "observe_probe(probe)"
        kind = path[index - 1]
        ident = f"s{index}"
        child = body(index + 1)
        binding = placements.get(index)
        if kind in ("function", "class"):
            head = (
                f"def {ident}({'probe' if binding == 'parameter' else ''}):"
                if kind == "function"
                else f"class {ident}:"
            )
            binder = "import package as probe\n" if binding == "import" else "probe = 1\n" if binding else ""
            statement = child if path[index : index + 1] in (("function",), ("class",)) else f"result = {child}"
            return f"{head}  # scope:{ident}\n" + "\n".join(f" {line}" for line in (binder + statement).splitlines())
        if kind == "lambda":
            return f"(lambda {'probe' if binding else ''}: (  # scope:{ident}\n{child}\n))"
        opening, closing = {
            "listcomp": ("[", "]"),
            "setcomp": ("{", "}"),
            "dictcomp": ("{", "}"),
            "genexpr": ("(", ")"),
        }[kind]
        value = f"{child}: 0" if kind == "dictcomp" else child
        return f"{opening}  # scope:{ident}\n{value}\nfor {'probe' if binding else f'item{index}'} in xs\n{closing}"

    rendered = body(1)
    prefix = "import package as probe\n" if placements.get(0) == "import" else "probe = 0\n" if 0 in placements else ""
    source = prefix + (rendered if path[0] in ("function", "class") else "result = " + rendered) + "\n"
    use = f"s{len(path)}"
    own = len(path) if len(path) in placements else None
    owner_index = own
    if owner_index is None:
        owner_index = next(
            (i for i in range(len(path) - 1, 0, -1) if i in placements and path[i - 1] != "class"),
            0 if 0 in placements else None,
        )
    owner = None if owner_index is None else "module" if owner_index == 0 else f"s{owner_index}"
    flags = _flags(path[-1], owner, use, placements.get(len(path), "local"))
    role = {"marker": "observe_probe", "scope": use, "owner": owner, "flags": flags, "namespace_applicable": True}
    if owner is not None:
        owner_kind = "module" if owner_index == 0 else path[owner_index - 1]
        role["owner_flags"] = {
            "local": True,
            "parameter": owner_kind == "lambda" or placements[owner_index] == "parameter",
            "imported": placements[owner_index] == "import",
        }
    result = _case(label, category, source, specs, [role])
    result["compiler_checks"] = [
        {
            "scope": "module" if i == 0 else f"s{i}",
            "name": "probe",
            "present": True,
            "flags": {
                "local": True,
                "parameter": i > 0 and (path[i - 1] == "lambda" or binding == "parameter"),
                "imported": binding == "import",
            },
        }
        for i, binding in placements.items()
    ]
    result["path"] = ["module", *path]
    result["placements"] = {"module" if i == 0 else f"s{i}": binding for i, binding in placements.items()}
    return result


def _effect(case: dict[str, Any], kind: str, origin: str, affected: str, name: str | None = "probe") -> None:
    node_type = {
        "global_directive": ast.Global,
        "nonlocal_directive": ast.Nonlocal,
        "walrus_write": ast.NamedExpr,
        "import_star": ast.ImportFrom,
    }[kind]
    nodes = [node for node in ast.walk(ast.parse(case["source"])) if isinstance(node, node_type)]
    if len(nodes) != 1:
        raise ValueError("effect recipe must have one exact source statement")
    node = nodes[0]
    case["effects"].append(
        {
            "kind": kind,
            "origin": origin,
            "affected": affected,
            "name": name,
            "position": [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset],
        }
    )


def _directive_cases(rows: list[dict[str, Any]], add: Callable[..., None], role: Callable[..., dict[str, Any]]) -> None:
    for directive in ("global", "nonlocal"):
        for scope_kind in ("function", "class"):
            for after in (False, True):
                source = (
                    "probe = 0\ndef outer():  # scope:outer\n probe = 1\n "
                    + ("def inner():" if scope_kind == "function" else "class inner:")
                    + "  # scope:inner\n"
                )
                use = "  result = observe_probe(probe)\n"
                declaration = f"  {directive} probe\n"
                specs = [("outer", "function", "module"), ("inner", scope_kind, "outer")]
                if after:
                    use = "  result = [observe_probe(probe) for item in xs]  # scope:comp\n"
                    specs.append(("comp", "listcomp", "inner"))
                source += use + declaration if after else declaration + use
                flags = (
                    {"global": True, "declared_global": not after}
                    if directive == "global"
                    else {"free": True, "nonlocal": not after}
                )
                owner = "module" if directive == "global" else "outer"
                if after and scope_kind == "class":
                    flags, owner = {"free": True, "nonlocal": False}, "outer"
                add(
                    f"{directive}:{scope_kind}:{'after' if after else 'before'}",
                    source,
                    specs,
                    [role("comp" if after else "inner", owner, **flags)],
                )
                _effect(rows[-1], directive + "_directive", "inner", "module" if directive == "global" else "outer")
    for directive in ("global", "nonlocal", "none"):
        source = "probe = 0\ndef outer():  # scope:outer\n probe = 1\n def inner():  # scope:inner\n"
        if directive != "none":
            source += f"  {directive} probe\n"
        source += "  result = [  # scope:comp\n  observe_probe(probe) for item in xs]\n"
        add(
            f"{directive}:bridge:comp",
            source,
            [("outer", "function", "module"), ("inner", "function", "outer"), ("comp", "listcomp", "inner")],
            [
                role(
                    "comp",
                    "module" if directive == "global" else "outer",
                    **({"global": True} if directive == "global" else {"free": True}),
                )
            ],
        )
        if directive != "none":
            _effect(rows[-1], directive + "_directive", "inner", "module" if directive == "global" else "outer")
    for directive in ("global", "nonlocal", "none"):
        prefix = "probe = 0\ndef outer():  # scope:outer\n probe = 1\n def inner():  # scope:inner\n"
        source = prefix + (f"  {directive} probe\n" if directive != "none" else "")
        source += "  result = [  # scope:comp\n  (probe := item, observe_probe(probe)) for item in xs]\n"
        owner = "module" if directive == "global" else "outer" if directive == "nonlocal" else "inner"
        add(
            f"walrus_escape:{directive}",
            source,
            [("outer", "function", "module"), ("inner", "function", "outer"), ("comp", "listcomp", "inner")],
            [
                role(
                    "comp",
                    owner,
                    **(
                        {"global": True, "declared_global": True}
                        if directive == "global"
                        else {"free": True, "nonlocal": True}
                    ),
                )
            ],
        )
        if directive != "none":
            _effect(rows[-1], directive + "_directive", "inner", "module" if directive == "global" else "outer")
        _effect(rows[-1], "walrus_write", "comp", owner)


def _specials() -> list[dict]:
    rows = []

    def add(
        label: str,
        source: str,
        specs: list[tuple[str, str, str]],
        roles: list[dict[str, Any]],
        category: str = "directive_effect",
    ) -> None:
        rows.append(_case(label, category, source, [("module", "module", None), *specs], roles))

    def role(scope: str, owner: str | None, **flags: bool) -> dict[str, Any]:
        return {"marker": "observe_probe", "scope": scope, "owner": owner, "flags": flags, "namespace_applicable": True}

    # Exact failure shapes from the stopped resolver, with explicit use/owner IDs.
    add(
        "nested_comprehension_iteration_owner_prior_failure",
        "result = [  # scope:outer\n[observe_probe(probe()) for y in ys]  # scope:inner\nfor probe in probes]\n",
        [("outer", "listcomp", "module"), ("inner", "listcomp", "outer")],
        [role("inner", "outer", free=True)],
    )
    rows.append(
        _recipe(
            "function_class_method_comp_prior_failure",
            "depth",
            ("function", "class", "function", "listcomp"),
            {1: "local", 2: "local"},
        )
    )
    rows.append(
        _recipe(
            "repeated_class_bridge",
            "depth",
            ("function", "class", "class", "function", "listcomp"),
            {1: "local", 2: "local", 3: "local"},
        )
    )
    rows.append(
        _recipe("nearer_competing_binder", "depth", ("function", "function", "function"), {1: "local", 2: "local"})
    )
    _directive_cases(rows, add, role)
    add(
        "lambda_walrus_boundary",
        "def outer():  # scope:outer\n probe = 1\n result = [  # scope:comp\n (lambda: (  # scope:lam\n (probe := 2, observe_probe(probe)))) for item in xs]\n",
        [("outer", "function", "module"), ("comp", "listcomp", "outer"), ("lam", "lambda", "comp")],
        [role("lam", "lam", local=True)],
    )
    _effect(rows[-1], "walrus_write", "lam", "lam")
    add(
        "class_cell",
        "class C:  # scope:cls\n def method(self):  # scope:method\n  return observe_probe(__class__)\n",
        [("cls", "class", "module"), ("method", "function", "cls")],
        [{**role("method", "cls", free=True), "name": "__class__", "owner_kind": "implicit_class_cell"}],
    )
    add(
        "class_body_own_read",
        "probe = 0\nclass C:  # scope:cls\n probe = 1\n value = observe_probe(probe)\n",
        [("cls", "class", "module")],
        [role("cls", "cls", local=True)],
    )
    add(
        "class_body_unbound_lookup",
        "class C:  # scope:cls\n value = observe_probe(probe)\n",
        [("cls", "class", "module")],
        [role("cls", None, **{"global": True})],
    )
    add(
        "module_bound",
        "probe = 0\nobserve_probe(probe)\n",
        [],
        [role("module", "module", local=True, **{"global": True})],
    )
    add("module_unbound", "observe_probe(probe)\n", [], [role("module", None, local=False, **{"global": True})])
    add(
        "wildcard_effect",
        "from package import *\nobserve_probe(probe)\n",
        [],
        [role("module", None, **{"global": True})],
    )
    _effect(rows[-1], "import_star", "module", "module", None)
    add(
        "class_comp_first_iterable",
        "probe = 0\nclass C:  # scope:cls\n probe = 1\n result = [  # scope:comp\n inner_probe(probe) for item in outer_probe(probe)]\n",
        [("cls", "class", "module"), ("comp", "listcomp", "cls")],
        [
            {**role("cls", "cls", local=True), "marker": "outer_probe"},
            {**role("comp", "module", **{"global": True}), "marker": "inner_probe"},
        ],
    )
    add(
        "function_default_and_body",
        "probe = 0\ndef outer():  # scope:outer\n probe = 1\n def inner(value=header_probe(probe)):  # scope:inner\n  probe = 2\n  return body_probe(probe)\n",
        [("outer", "function", "module"), ("inner", "function", "outer")],
        [
            {**role("outer", "outer", local=True), "marker": "header_probe"},
            {**role("inner", "inner", local=True), "marker": "body_probe"},
        ],
    )
    # Binder forms are compiler-local even if a read precedes the binder.
    for name, binder in {
        "assignment": "probe = 1",
        "delete": "del probe",
        "annotation": "probe: int",
        "definition": "def probe():\n pass",
        "named_import": "import package as probe",
        "from_import": "from package import value as probe",
    }.items():
        source = (
            "def outer():  # scope:outer\n result = observe_probe(probe)\n"
            + "\n".join(" " + line for line in binder.splitlines())
            + "\n"
        )
        specs = [("outer", "function", "module")]
        if name == "definition":
            source = source.replace("def probe():", "def probe():  # scope:binder")
            specs.append(("binder", "function", "outer"))
        add(
            f"binder:{name}",
            source,
            specs,
            [role("outer", "outer", local=True, imported=name in ("named_import", "from_import"))],
        )
    return rows


def _annotation_expression(
    descendant: str, location: str
) -> tuple[str, list[tuple[str, str, str]], list[tuple[str, str]]]:
    """Recipes declare each marked occurrence's scope; no oracle is consulted."""
    body = "(annotation_probe(probe), annotation_only(inert_only))"
    specs: list[tuple[str, str, str]] = []
    extra: list[tuple[str, str]] = []
    if descendant == "name":
        return body, specs, extra
    if descendant == "lambda":
        return f"(lambda: (  # scope:ann\n{body}))", [("ann", "lambda", location)], extra
    if descendant == "lambda_default":
        return (
            f"(lambda value=default_probe(probe): (  # scope:ann\n{body}))",
            [("ann", "lambda", location)],
            [("default_probe", location)],
        )
    if descendant in COMPS:
        opening, closing = {
            "listcomp": ("[", "]"),
            "setcomp": ("{", "}"),
            "dictcomp": ("{", "}"),
            "genexpr": ("(", ")"),
        }[descendant]
        iterable = "iter_probe(probe)" if descendant == "genexpr" else "xs"
        if descendant == "genexpr":
            extra = [("iter_probe", location)]
        return (
            f"{opening}  # scope:ann\n{body}"
            + (": 0" if descendant == "dictcomp" else "")
            + f" for item in {iterable}{closing}",
            [("ann", descendant, location)],
            extra,
        )
    if descendant == "gen_multi":
        return (
            f"(  # scope:ann\n{body} for item in iter_probe(probe) for other in later_probe(probe) if filter_probe(probe))",
            [("ann", "genexpr", location)],
            [("iter_probe", location), ("later_probe", "ann"), ("filter_probe", "ann")],
        )
    if descendant in ("gen_iter_lambda", "gen_iter_comp", "comp_iter_gen"):
        outer_kind, inner_kind = {
            "gen_iter_lambda": ("genexpr", "lambda"),
            "gen_iter_comp": ("genexpr", "listcomp"),
            "comp_iter_gen": ("listcomp", "genexpr"),
        }[descendant]
        # The inner expression is in the outermost iterable, so its compiler
        # parent and inherited phase are the enclosing location, not ann.
        inner = (
            "(lambda: (  # scope:iter_scope\niter_probe(probe)))"
            if inner_kind == "lambda"
            else ("[" if inner_kind == "listcomp" else "(")
            + "  # scope:iter_scope\niter_probe(probe) for other in xs"
            + ("]" if inner_kind == "listcomp" else ")")
        )
        opening, closing = ("[", "]") if outer_kind == "listcomp" else ("(", ")")
        expression = f"{opening}  # scope:ann\n{body} for item in {inner}{closing}"
        return (
            expression,
            [("ann", outer_kind, location), ("iter_scope", inner_kind, location)],
            [("iter_probe", "iter_scope")],
        )
    outer_kind, inner_kind = {
        "lambda_comp": ("lambda", "listcomp"),
        "comp_lambda": ("listcomp", "lambda"),
        "lambda_gen": ("lambda", "genexpr"),
        "gen_lambda": ("genexpr", "lambda"),
        "comp_gen": ("listcomp", "genexpr"),
        "gen_comp": ("genexpr", "listcomp"),
        "gen_gen": ("genexpr", "genexpr"),
    }[descendant]
    inner = (
        f"(lambda: (  # scope:ann_child\n{body}))"
        if inner_kind == "lambda"
        else ("[" if inner_kind == "listcomp" else "(")
        + f"  # scope:ann_child\n{body} for other in "
        + ("inner_iter_probe(probe)" if inner_kind == "genexpr" else "xs")
        + ("]" if inner_kind == "listcomp" else ")")
    )
    if inner_kind == "genexpr":
        extra.append(("inner_iter_probe", "ann"))
    expression = (
        f"(lambda: (  # scope:ann\n{inner}))"
        if outer_kind == "lambda"
        else ("[" if outer_kind == "listcomp" else "(")
        + f"  # scope:ann\n{inner} for item in "
        + ("iter_probe(probe)" if outer_kind == "genexpr" else "xs")
        + ("]" if outer_kind == "listcomp" else ")")
    )
    if outer_kind == "genexpr":
        extra.append(("iter_probe", location))
    return expression, [("ann", outer_kind, location), ("ann_child", inner_kind, "ann")], extra


ANNOTATION_DESCENDANTS = (
    "name",
    "lambda",
    *COMPS,
    "lambda_comp",
    "comp_lambda",
    "lambda_default",
    "gen_multi",
    "gen_iter_lambda",
    "gen_iter_comp",
    "comp_iter_gen",
    "lambda_gen",
    "gen_lambda",
    "comp_gen",
    "gen_comp",
    "gen_gen",
)


def _annotations() -> list[dict]:
    rows = []
    for location in ("module", "class", "function"):
        for postponed in (False, True):
            for descendant in ANNOTATION_DESCENDANTS:
                expression, nested, extra = _annotation_expression(descendant, location)
                prefix = "from __future__ import annotations\n" if postponed else ""
                specs = [("module", "module", None)]
                source = prefix + "probe = 0\n"
                indent = ""
                if location != "module":
                    source += ("class C:" if location == "class" else "def f():") + f"  # scope:{location}\n"
                    indent = " "
                    specs.append((location, location, "module"))
                source += "\n".join(indent + line for line in ("x: " + expression).splitlines()) + "\n"
                source += indent + "active_probe(probe)\n"
                applicable = not postponed and location != "function"
                context = "postponed" if postponed else "function_local" if location == "function" else "eager"
                body_scope = (
                    "ann_child" if any(spec[0] == "ann_child" for spec in nested) else "ann" if nested else location
                )
                annotation_role = {
                    "marker": "annotation_probe",
                    "scope": body_scope,
                    "owner": "module" if not postponed else None,
                    "flags": {"global": True} if not postponed else {},
                    "namespace_applicable": applicable,
                    "compiler_present": not postponed,
                    "annotation_context": context,
                }
                roles = [annotation_role, {**annotation_role, "marker": "annotation_only", "owner": None}]
                roles.extend({**annotation_role, "marker": marker, "scope": scope} for marker, scope in extra)
                roles.append(
                    {
                        "marker": "active_probe",
                        "scope": location,
                        "owner": "module",
                        "flags": {"global": True},
                        "namespace_applicable": True,
                    }
                )
                case = _case(
                    f"annotation:{location}:{'postponed' if postponed else 'eager'}:{descendant}",
                    "annotation",
                    source,
                    specs + nested,
                    roles,
                )
                case["annotation"] = {
                    "location": location,
                    "postponed": postponed,
                    "descendant": descendant,
                    "namespace_applicable": applicable,
                    "absent_tables": [spec[0] for spec in nested] if postponed else [],
                }
                case["compiler_checks"] = [
                    {"scope": location, "name": "x", "present": True, "flags": {"annotated": True, "local": True}},
                    {
                        "scope": body_scope,
                        "name": "inert_only",
                        "present": not postponed,
                        "flags": {"global": True} if not postponed else {},
                    },
                ]
                rows.append(case)
    return rows


def _header_boundaries() -> list[dict]:
    rows = []
    for location in ("module", "class", "function"):
        for postponed in (False, True):
            source = ("from __future__ import annotations\n" if postponed else "") + "probe = 0\n"
            specs = [("module", "module", None)]
            indent = ""
            if location != "module":
                source += ("class C:" if location == "class" else "def outer():") + f"  # scope:{location}\n"
                indent = " "
                specs.append((location, location, "module"))
            lines = [
                "@decorator_probe(probe)",
                "def header(value: argument_probe(probe) = default_probe(probe)) -> return_probe(probe):  # scope:header",
                " pass",
                "@class_decorator_probe(probe)",
                "class Child(base_probe(probe), metaclass=meta_probe(probe)):  # scope:child",
                " pass",
                "x: variable_probe(probe) = value_probe(probe)",
            ]
            source += "\n".join(indent + line for line in lines) + "\n"
            specs.extend([("header", "function", location), ("child", "class", location)])
            roles = [
                {
                    "marker": marker,
                    "scope": location,
                    "owner": "module",
                    "flags": {"global": True},
                    "namespace_applicable": True,
                }
                for marker in (
                    "decorator_probe",
                    "default_probe",
                    "class_decorator_probe",
                    "base_probe",
                    "meta_probe",
                    "value_probe",
                )
            ]
            for marker in ("argument_probe", "return_probe", "variable_probe"):
                context = (
                    "postponed"
                    if postponed
                    else "function_local"
                    if marker == "variable_probe" and location == "function"
                    else "eager"
                )
                roles.append(
                    {
                        "marker": marker,
                        "scope": location,
                        "owner": None if postponed else "module",
                        "flags": {} if postponed else {"global": True},
                        "namespace_applicable": context == "eager",
                        "compiler_present": not postponed,
                        "annotation_context": context,
                    }
                )
            case = _case(
                f"annotation_headers:{location}:{'postponed' if postponed else 'eager'}",
                "annotation",
                source,
                specs,
                roles,
            )
            case["header_boundary"] = {"location": location, "postponed": postponed}
            case["compiler_checks"] = [
                {"scope": location, "name": "x", "present": True, "flags": {"local": True, "annotated": True}}
            ]
            rows.append(case)
    return rows


def cases() -> dict:
    positives = []
    for parent in ("module", *KINDS):
        for child in KINDS:
            if not reachable(parent, child):
                continue
            path = (child,) if parent == "module" else (parent, child)
            for state in ("parent", "absent", "own", "root", "nearer"):
                parent_index = len(path) - 1
                placement = (
                    {}
                    if state == "absent"
                    else {len(path) if state == "own" else parent_index if state == "parent" else 0: "local"}
                )
                if state == "nearer":
                    placement = {parent_index: "local", len(path): "local"}
                positives.append(_recipe(f"{parent}->{child}:{state}", "transition", path, placement))
    for path in itertools.product(KINDS, repeat=3):
        if all(reachable(a, b) for a, b in itertools.pairwise(path)):
            for state, placements in (
                ("outer", {0: "local", 1: "local"}),
                ("nearer", {0: "local", 1: "local", 2: "local"}),
            ):
                positives.append(_recipe("depth:" + ">".join(path) + ":" + state, "depth", path, placements))
    for owner_kind in ("module", "function", "class", "lambda", *COMPS):
        for binding in ("parameter", "import"):
            if binding == "parameter" and owner_kind not in ("function", "lambda"):
                continue
            if binding == "import" and owner_kind not in ("module", "function", "class"):
                continue
            for child in KINDS:
                if not reachable(owner_kind, child):
                    continue
                path = (child,) if owner_kind == "module" else (owner_kind, child)
                label = f"binding:{owner_kind}:{binding}" + ("" if child == "listcomp" else f"->{child}")
                positives.append(_recipe(label, "transition", path, {len(path) - 1: binding}))
    positives.extend(_specials())
    positives.extend(_annotations())
    positives.extend(_header_boundaries())
    rejected_sources = {
        "nonlocal_without_owner": "def f():\n nonlocal probe\n",
        "class_comp_walrus": "class C:\n value=[(probe := x) for x in xs]\n",
        "iteration_walrus_conflict": "[(x := 1) for x in xs for x in ys]\n",
        "nonlocal_global_conflict": "def f():\n global probe\n nonlocal probe\n",
        "parameter_global_conflict": "def f(probe):\n global probe\n",
        "walrus_in_iterable": "[x for x in (probe := xs)]\n",
    }
    rejected = [
        {"label": label, "source": source, "sha256": hashlib.sha256(source.encode()).hexdigest()}
        for label, source in rejected_sources.items()
    ]
    ambiguous_source = "value = (lambda: probe, lambda: probe)\n"
    ambiguous = [
        {
            "label": "same_line_identical_lambda_signatures",
            "source": ambiguous_source,
            "sha256": hashlib.sha256(ambiguous_source.encode()).hexdigest(),
            "selector": {"parent": "module", "kind": "function", "name": "lambda", "line": 1},
            "expected": "ambiguous_scope_mapping",
        }
    ]
    # Deduplicate exact source bytes while retaining all coverage recipe labels.
    unique = {}
    for row in positives:
        if row["sha256"] in unique:
            unique[row["sha256"]]["aliases"].append(row["label"])
        else:
            row["aliases"] = []
            unique[row["sha256"]] = row
    positives = list(unique.values())
    counts = Counter(row["category"] for row in positives)
    if (
        any(counts[key] > cap for key, cap in CAPS.items())
        or len(positives) + len(rejected) + len(ambiguous) > LIMITS["cases"]
    ):
        raise ValueError("generated case cap exceeded")
    unreachable = [
        {"parent": parent, "child": child, "reason": "statement scope cannot be a direct expression-scope child"}
        for parent in KINDS
        for child in ("function", "class")
        if not reachable(parent, child)
    ]
    return {
        "positive": positives,
        "rejected": rejected,
        "ambiguous": ambiguous,
        "unreachable_edges": unreachable,
        "coverage": {
            "counts": dict(sorted(counts.items())),
            "component_caps": CAPS,
            "limits": LIMITS,
            "depth_policy": "all valid three-kind paths; outer and nearer placement variants; named deeper class bridges",
            "omissions": [
                "not exhaustive arbitrary-depth programs",
                "async syntax and all Python binder constructs beyond named recipe forms are outside this finite oracle",
                "runtime class LOAD_NAME fallback and callable association are not inferred",
            ],
        },
    }


if __name__ == "__main__":
    import json

    print(json.dumps(cases(), sort_keys=True, indent=2))
