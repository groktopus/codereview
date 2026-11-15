"""Source-recipe coverage, compiler corroboration and rejecting witness mutations.

Generated programs are only passed to ast.parse/public symtable. The fixture
modules are test tools, not generated source or production resolver imports.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import itertools
import json
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "retrieval_namespace_oracle"
CPYTHON_311 = pytest.mark.skipif(
    sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 11),
    reason="compiler-table oracle is pinned to public CPython 3.11 semantics",
)


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, FIXTURES / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def manifest() -> dict[str, Any]:
    return json.loads((FIXTURES / "manifest.json").read_text())


def by_label(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {label: row for row in rows for label in (row["label"], *row.get("aliases", []))}


def one_case(label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    corpus = load("generate").cases()
    row = copy.deepcopy(by_label(corpus["positive"])[label])
    return {**corpus, "positive": [row], "rejected": [], "ambiguous": []}, row


def test_manifest_is_reproducible_and_resource_bounded() -> None:
    generator = load("generate")
    corpus = generator.cases()
    expected = manifest()
    assert corpus == generator.cases()
    assert corpus["coverage"] == expected["coverage"]
    assert len(corpus["positive"]) + len(corpus["rejected"]) + len(corpus["ambiguous"]) <= 1792
    assert len({case["sha256"] for case in corpus["positive"]}) == len(corpus["positive"])
    counts = Counter(case["category"] for case in corpus["positive"])
    assert dict(counts) == corpus["coverage"]["counts"]
    assert all(0 < counts[category] <= cap for category, cap in generator.CAPS.items())
    for family in ("positive", "rejected", "ambiguous"):
        assert [row["sha256"] for row in corpus[family]] == [row["sha256"] for row in expected[family]]
        for row in corpus[family]:
            assert hashlib.sha256(row["source"].encode()).hexdigest() == row["sha256"]
            assert len(row["source"].encode()) <= generator.LIMITS["source_bytes"]
    for row in corpus["positive"]:
        assert len(list(ast.walk(ast.parse(row["source"])))) <= generator.LIMITS["ast_nodes"]
        assert expected["positive"][corpus["positive"].index(row)]["source"] == row["source"]
    assert corpus["unreachable_edges"] == expected["unreachable_edges"]


def test_every_realizable_transition_and_depth_three_path_has_witnesses() -> None:
    generator = load("generate")
    rows = by_label(manifest()["positive"])
    for parent, child in itertools.product(("module", *generator.KINDS), generator.KINDS):
        if generator.reachable(parent, child):
            assert all(f"{parent}->{child}:{state}" in rows for state in ("parent", "absent", "own", "root", "nearer"))
    for path in itertools.product(generator.KINDS, repeat=3):
        if all(generator.reachable(a, b) for a, b in itertools.pairwise(path)):
            assert all("depth:" + ">".join(path) + ":" + state in rows for state in ("outer", "nearer"))
    assert {(edge["parent"], edge["child"]) for edge in manifest()["unreachable_edges"]} == {
        (parent, child) for parent in ("lambda", *generator.COMPS) for child in ("function", "class")
    }
    assert {row["classification"] for case in manifest()["positive"] for row in case["corroboration"]} == {
        "module",
        "local",
        "free",
        "implicit_global",
        "explicit_global",
        "nonlocal",
        "class_local",
        "class_lookup",
        "not_applicable",
    }


@CPYTHON_311
def test_expected_rows_recompute_with_independent_public_compiler_oracle() -> None:
    assert load("oracle").analyze(load("generate").cases()) == manifest()


def test_known_failures_and_parameters_imports_have_correlated_compiler_owners() -> None:
    rows = by_label(manifest()["positive"])
    for label, owner in (
        ("nested_comprehension_iteration_owner_prior_failure", "outer"),
        ("function_class_method_comp_prior_failure", "s1"),
        ("repeated_class_bridge", "s1"),
        ("nearer_competing_binder", "s2"),
    ):
        case = rows[label]
        result = case["corroboration"][0]
        assert result["symbol"]["free"]
        assert result["owner"] == case["scope_map"][owner]
        assert result["scope"] != result["owner"]
    nested = rows["nested_comprehension_iteration_owner_prior_failure"]
    assert "probe()" in nested["source"]
    assert nested["scope_map"]["inner"].startswith(nested["scope_map"]["outer"] + "/")
    for label in (
        "binding:function:parameter",
        "binding:lambda:parameter",
        "binding:module:import",
        "binding:function:import",
        "binding:class:import",
    ):
        case = rows[label]
        check = next(check for check in case["compiler_checks"] if check["name"] == "probe")
        table = next(table for table in case["tables"] if table["id"] == case["scope_map"][check["scope"]])
        symbol = next(symbol for symbol in table["symbols"] if symbol["name"] == "probe")
        assert symbol["parameter" if label.endswith("parameter") else "imported"]
        if ":class:" not in label:
            assert case["corroboration"][0]["owner"] == table["id"]
    cell = rows["class_cell"]
    assert cell["corroboration"][0]["owner"] == cell["scope_map"]["cls"]
    assert cell["corroboration"][0]["compiler_namespace"] == "implicit_class_cell"
    class_iterable = rows["class_comp_first_iterable"]
    assert [row["classification"] for row in class_iterable["corroboration"]] == ["class_local", "implicit_global"]
    assert [row["owner"] for row in class_iterable["corroboration"]] == [class_iterable["scope_map"]["cls"], "module"]


def test_annotation_inertness_compiler_presence_and_occurrence_phase_are_separate() -> None:
    rows = [row for row in manifest()["positive"] if "annotation" in row]
    assert len(rows) == 6 * len(load("generate").ANNOTATION_DESCENDANTS)
    for row in rows:
        annotation = row["annotation"]
        applicable = not annotation["postponed"] and annotation["location"] != "function"
        annotation_roles = [role for role in row["corroboration"] if role["marker"] != "active_probe"]
        assert all(role["namespace_applicable"] == applicable for role in annotation_roles)
        ordinary = next(role for role in row["corroboration"] if role["marker"] == "active_probe")
        assert ordinary["namespace_applicable"] and ordinary["symbol"]["global"]
        for expected, actual in zip(row["roles"], row["corroboration"], strict=True):
            for key in ("evaluation_phase", "annotation_context", "namespace_applicable", "static_immediate"):
                assert actual[key] == expected[key]
        if annotation["postponed"]:
            assert all(role["scope"] is None and "symbol" not in role for role in annotation_roles)
        else:
            # Local annotations retain compiler facts even when permanently inert.
            assert all(role["symbol"]["global"] and role["scope"] is not None for role in annotation_roles)
        if not applicable:
            assert all(
                role["classification"] == "not_applicable" and not role["static_immediate"] for role in annotation_roles
            )
        checks = {check["name"]: check for check in row["compiler_checks"]}
        assert checks["x"]["flags"] == {"local": True, "annotated": True}
        assert checks["inert_only"]["present"] == (not annotation["postponed"])


def test_explicit_phase_boundaries_do_not_treat_deferred_as_permanently_inert() -> None:
    rows = by_label(manifest()["positive"])
    expected = {
        # Recipe-independent literal phase expectations for the reviewed failures.
        ("lambda", "annotation_probe"): ("lambda_body", False),
        ("genexpr", "annotation_probe"): ("generator_body", False),
        ("genexpr", "iter_probe"): ("immediate", True),
        ("comp_lambda", "annotation_probe"): ("lambda_body", False),
        ("lambda_comp", "annotation_probe"): ("lambda_body", False),
        ("lambda_default", "default_probe"): ("immediate", True),
        ("lambda_default", "annotation_probe"): ("lambda_body", False),
        ("gen_multi", "iter_probe"): ("immediate", True),
        ("gen_multi", "later_probe"): ("generator_body", False),
        ("gen_multi", "filter_probe"): ("generator_body", False),
        ("gen_iter_lambda", "iter_probe"): ("lambda_body", False),
        ("gen_iter_comp", "iter_probe"): ("immediate", True),
        ("comp_iter_gen", "iter_probe"): ("generator_body", False),
        ("comp_iter_gen", "annotation_probe"): ("immediate", True),
        ("lambda_gen", "inner_iter_probe"): ("lambda_body", False),
        ("lambda_gen", "annotation_probe"): ("generator_body", False),
        ("gen_comp", "annotation_probe"): ("generator_body", False),
        ("gen_gen", "inner_iter_probe"): ("generator_body", False),
        ("gen_gen", "iter_probe"): ("immediate", True),
        ("gen_lambda", "annotation_probe"): ("lambda_body", False),
    }
    for location in ("module", "class", "function"):
        for mode in ("eager", "postponed"):
            context = "postponed" if mode == "postponed" else "function_local" if location == "function" else "eager"
            applicable = context == "eager"
            for (descendant, marker), (phase, immediate) in expected.items():
                case = rows[f"annotation:{location}:{mode}:{descendant}"]
                role = next(role for role in case["corroboration"] if role["marker"] == marker)
                expected_phase = "function_body" if phase == "immediate" and location == "function" else phase
                assert role["evaluation_phase"] == expected_phase
                assert role["static_immediate"] == (applicable and immediate and location != "function")
                assert role["annotation_context"] == context
                assert role["namespace_applicable"] == applicable
                if mode == "eager":
                    assert role["symbol"]["global"]
                else:
                    assert "symbol" not in role


def test_defaults_decorators_headers_and_annotation_values_keep_their_own_context() -> None:
    rows = [row for row in manifest()["positive"] if "header_boundary" in row]
    assert len(rows) == 6
    for case in rows:
        boundary = case["header_boundary"]
        expected_phase = "function_body" if boundary["location"] == "function" else "immediate"
        for role in case["corroboration"]:
            assert role["evaluation_phase"] == expected_phase
            if role["marker"] in ("argument_probe", "return_probe", "variable_probe"):
                context = (
                    "postponed"
                    if boundary["postponed"]
                    else "function_local"
                    if role["marker"] == "variable_probe" and boundary["location"] == "function"
                    else "eager"
                )
                assert role["annotation_context"] == context
                assert role["namespace_applicable"] == (context == "eager")
            else:
                assert role["annotation_context"] == "none" and role["namespace_applicable"]
                assert role["symbol"]["global"]
            assert role["static_immediate"] == (role["namespace_applicable"] and expected_phase == "immediate")


@CPYTHON_311
@pytest.mark.parametrize(
    "mutation",
    [
        "farther_owner",
        "use_table",
        "use_position",
        "parameter_flag",
        "import_flag",
        "annotation_presence",
        "annotation_applicability",
        "effect_owner",
        "digest",
    ],
)
def test_bad_source_bound_witnesses_are_rejected_not_merely_snapshot_changed(mutation: str) -> None:
    labels = {
        "farther_owner": "nearer_competing_binder",
        "use_table": "class_comp_first_iterable",
        "use_position": "class_comp_first_iterable",
        "parameter_flag": "binding:function:parameter",
        "import_flag": "binding:function:import",
        "annotation_presence": "annotation:function:eager:lambda",
        "annotation_applicability": "annotation:function:eager:lambda",
        "effect_owner": "walrus_escape:none",
        "digest": "nearer_competing_binder",
    }
    corpus, case = one_case(labels[mutation])
    if mutation == "farther_owner":
        case["roles"][0]["owner"] = "s1"  # An existing local, but s2 shadows it.
    elif mutation == "use_table":
        # Existing class local facts cannot witness the comprehension's load.
        case["roles"][1].update(scope="cls", flags={"local": True})
    elif mutation == "use_position":
        case["roles"][1]["position"] = case["roles"][0]["position"]
    elif mutation in ("parameter_flag", "import_flag"):
        case["roles"][0]["owner_flags"]["parameter" if mutation == "parameter_flag" else "imported"] = False
    elif mutation == "annotation_presence":
        case["compiler_checks"][1]["present"] = False
    elif mutation == "annotation_applicability":
        case["roles"][0]["namespace_applicable"] = True
    elif mutation == "effect_owner":
        case["effects"][0]["affected"] = "outer"
    else:
        case["source"] += "\n"
    with pytest.raises(ValueError):
        load("oracle").analyze(corpus)


@CPYTHON_311
@pytest.mark.parametrize(
    "descendant,marker,key,bad_value",
    [
        ("lambda", "annotation_probe", "evaluation_phase", "immediate"),
        ("genexpr", "annotation_probe", "evaluation_phase", "immediate"),
        ("genexpr", "iter_probe", "evaluation_phase", "generator_body"),
        ("genexpr", "iter_probe", "static_immediate", False),
        ("lambda_comp", "annotation_probe", "evaluation_phase", "immediate"),
        ("gen_comp", "annotation_probe", "evaluation_phase", "immediate"),
        ("lambda_gen", "inner_iter_probe", "evaluation_phase", "immediate"),
        ("gen_iter_comp", "iter_probe", "evaluation_phase", "generator_body"),
        ("lambda_default", "default_probe", "evaluation_phase", "lambda_body"),
        ("lambda", "annotation_probe", "namespace_applicable", False),
        ("lambda", "annotation_probe", "static_immediate", True),
        ("genexpr", "annotation_probe", "annotation_context", "none"),
    ],
)
def test_phase_and_annotation_context_witness_mutations_are_rejected(
    descendant: str, marker: str, key: str, bad_value: Any
) -> None:
    corpus, case = one_case(f"annotation:module:eager:{descendant}")
    role = next(role for role in case["roles"] if role["marker"] == marker)
    role[key] = bad_value
    with pytest.raises(ValueError, match="evaluation context mismatch"):
        load("oracle").analyze(corpus)


@CPYTHON_311
def test_wrong_outer_comp_owner_is_rejected_even_when_both_tables_have_probe() -> None:
    corpus, case = one_case("depth:function>listcomp>listcomp:nearer")
    case["roles"][0]["owner"] = "s1"
    with pytest.raises(ValueError, match="nearest capturable compiler owner"):
        load("oracle").analyze(corpus)


@CPYTHON_311
def test_ambiguity_and_resource_limits_fail_closed() -> None:
    oracle = load("oracle")
    with pytest.raises(ValueError, match="ambiguous_scope_mapping"):
        oracle.CompilerIndex("value = (lambda: probe, lambda: probe)\n")
    with pytest.raises(ValueError, match="byte cap"):
        oracle.CompilerIndex("#" + "x" * 8192)
    with pytest.raises(ValueError, match="AST node cap"):
        oracle.CompilerIndex("x\n" * 400)
    source = "probe\n"
    for i in range(9):
        source = f"def f{i}():\n" + "\n".join(" " + line for line in source.splitlines()) + "\n"
    with pytest.raises(ValueError, match="resource cap"):
        oracle.CompilerIndex(source)


def test_source_effects_rejections_and_mapping_ambiguity_are_explicit() -> None:
    expected = manifest()
    assert {effect["kind"] for row in expected["positive"] for effect in row["effect_corroboration"]} == {
        "global_directive",
        "nonlocal_directive",
        "walrus_write",
        "import_star",
    }
    assert len(expected["rejected"]) == 6
    assert all(row["rejected"] for row in expected["rejected"])
    assert len(expected["ambiguous"]) == 1
    assert expected["ambiguous"][0]["matching_tables"] == 2
    assert expected["ambiguous"][0]["rejected_mapping"]
