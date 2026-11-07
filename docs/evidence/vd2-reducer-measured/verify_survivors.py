"""Independent differential triage; no application production files modified."""

from __future__ import annotations

import ast
import copy
import hashlib
import itertools
import json
from pathlib import Path

source = Path("src/pr_review_harness/engine.py").read_text()
module = ast.parse(source)
original = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "_reduce")


def function(variant):
    node = copy.deepcopy(original)
    changes = 0
    for call in ast.walk(node):
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "completeness"
            and call.func.attr == "get"
            and len(call.args) == 2
            and isinstance(call.args[0], ast.Constant)
            and call.args[0].value == "waived"
        ):
            if variant == 33:
                call.args[1] = ast.Constant(None)
                changes += 1
            elif variant == 35:
                call.args.pop()
                changes += 1
    assert changes == (0 if variant == 0 else 1)
    env = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), "<triage>", "exec"), env)
    return env["_reduce"]


functions = {variant: function(variant) for variant in (0, 33, 35)}
summaries = [None, {}, {"waived": 0}, {"waived": None}, {"waived": False}, {"waived": 1}, {"waived": 2}]
findings = [
    [],
    [{"status": "ACCEPTED", "blocking_class": "BLOCKING"}],
    [{"status": "NEEDS_EVIDENCE", "blocking_class": "UNRESOLVED"}],
]
cases = 0
for summary, found, coverage, freshness, policy, allow in itertools.product(
    summaries,
    findings,
    ["COMPLETE", "COMPLETE_WITH_WAIVERS", "PARTIAL"],
    ["CURRENT", "STALE", "UNKNOWN"],
    [False, True],
    [False, True],
):
    value = {"findings": found, "coverage_state": coverage, "freshness": freshness, "completeness_summary": summary}
    before = copy.deepcopy(value)
    results = {variant: fn(value, allow, policy) for variant, fn in functions.items()}
    assert len(set(results.values())) == 1, (value, results)
    assert value == before
    cases += 1
record = {
    "method": "AST extracts exact immutable production function; transforms only exact survivor diff; differential comparison supplements semantic argument, not mutation score",
    "scope": "ordinary JSON-derived dict/list/scalar inputs; not arbitrary dict subclasses with custom get",
    "cases": cases,
    "variants": [33, 35],
    "differences": 0,
    "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
    "semantic_argument": "Both mutants change only missing-key default from 0 to None. Both defaults are false in boolean disjunction and final bool(); present waived values and other operands remain identical. No disposition or input mutation difference for ordinary dict contracts.",
    "disposition": "likely-equivalent within stated reducer input contract; still counted as survivors, not excluded",
}
Path("survivor-triage.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record, indent=2))
