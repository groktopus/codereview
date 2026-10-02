#!/usr/bin/env python3
"""Run the frozen PR466 functional review through the production CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "docs/historical-functional-review-pr466-v1"
MANIFEST = CASE_DIR / "manifest.json"
CHECKS = CASE_DIR / "historical-checks.json"
LIMITS = CASE_DIR / "limits.json"
PROFILE = ROOT / "profiles/slopsearx.json"
REPOSITORY = "magnus919/SlopSearX"
BASE = "63e3ecd2f09d79c34e3594a3be74f017a1c5a12c"
HEAD = "7bce9dd246f141eb961c52ae96061203a98f083b"
PROFILE_SHA256 = "cc9c4631882662c27be5fb8534e65abbd352489afefa78e9dd3d3160fe0b1c65"
CHECKS_SHA256 = "c7d3a28b0e12583dceb0021b04814573706f202a188e4cbed2d1ebde821d5963"
LIMITS_SHA256 = "5b92e2381ba6c15e8afc2b77d7437d3cbb53a8ff6275e1b18617218753b364d6"
V2_CASE_DIR = ROOT / "docs/historical-functional-review-pr466-v2"
V2_MANIFEST = V2_CASE_DIR / "manifest.json"
V2_CHECKS = V2_CASE_DIR / "historical-checks.json"
V2_LIMITS = V2_CASE_DIR / "limits.json"
V2_PROFILE = ROOT / "profiles/slopsearx-v10-bounded-head-context-trial.json"
V2_PROFILE_VERSION = "slopsearx-production-v10-bounded-head-context-trial"
V2_PROFILE_SHA256 = "c2fefca40483bed31207f88fc1ae21f8c058098a207aca9ca987a54ff7abb34b"
V2_CHECKS_SHA256 = CHECKS_SHA256
V2_LIMITS_SHA256 = "964a11a8de3bfd47520ea62e358c954dceb1ac7da7f0648ef4db11d6f885870e"
V2_MANIFEST_SCHEMA = "historical-functional-review-pr466.v2"
V3_CASE_DIR = ROOT / "docs/historical-functional-review-pr466-v3"
V3_MANIFEST = V3_CASE_DIR / "manifest.json"
V3_CHECKS = V3_CASE_DIR / "historical-checks.json"
V3_LIMITS = V3_CASE_DIR / "limits.json"
V3_PROFILE = ROOT / "profiles/slopsearx-v11-related-implementation-context-candidate.json"
V3_PROFILE_VERSION = "slopsearx-production-v11-related-implementation-context-candidate"
V3_PROFILE_SHA256 = "5afcbf3cf5af235a97b59487303c28cb5c5f0942dc51cccc1ff84178617853d3"
V3_CHECKS_SHA256 = CHECKS_SHA256
V3_LIMITS_SHA256 = V2_LIMITS_SHA256
V3_MANIFEST_SCHEMA = "historical-functional-review-pr466.v3"
V4_CASE_DIR = ROOT / "docs/historical-functional-review-pr466-v4"
V4_MANIFEST = V4_CASE_DIR / "manifest.json"
V4_CHECKS = V4_CASE_DIR / "historical-checks.json"
V4_LIMITS = V4_CASE_DIR / "limits.json"
V4_PROFILE = ROOT / "profiles/slopsearx-v12-dependency-context-candidate.json"
V4_PROFILE_VERSION = "slopsearx-production-v12-head-dependency-context-candidate"
V4_PROFILE_SHA256 = "e2b1d9bbdafd6d054462b9abac48ce88fdc71400abcb7655902fcf3677c4d446"
V4_CHECKS_SHA256 = CHECKS_SHA256
V4_LIMITS_SHA256 = V2_LIMITS_SHA256
V4_MANIFEST_SCHEMA = "historical-functional-review-pr466.v4"
V5_CASE_DIR = ROOT / "docs/historical-functional-review-pr466-v5"
V5_MANIFEST = V5_CASE_DIR / "manifest.json"
V5_CHECKS = V5_CASE_DIR / "historical-checks.json"
V5_LIMITS = V5_CASE_DIR / "limits.json"
V5_PROFILE = ROOT / "profiles/slopsearx-v13-static-assessment-candidate.json"
V5_PROFILE_VERSION = "slopsearx-production-v13-static-assessment-candidate"
V5_PROFILE_SHA256 = "f1a566359a7a5a9af317159dcc962e8b0223e90513516cc25a4f785200ee3156"
V5_CHECKS_SHA256 = CHECKS_SHA256
V5_LIMITS_SHA256 = V2_LIMITS_SHA256
V5_MANIFEST_SCHEMA = "historical-functional-review-pr466.v5"
V6_CASE_DIR = ROOT / "docs/historical-functional-review-pr466-v6"
V6_MANIFEST = V6_CASE_DIR / "manifest.json"
V6_CHECKS = V6_CASE_DIR / "historical-checks.json"
V6_LIMITS = V6_CASE_DIR / "limits.json"
V6_PROFILE = ROOT / "profiles/slopsearx-v14-jev-reconciliation-candidate.json"
V6_PROFILE_VERSION = "slopsearx-production-v14-jev-reconciliation-candidate"
V6_PROFILE_SHA256 = "5e83bc43c615f717df0d3d29722de08dd5990c84c8e69d1705c94f3918d49692"
V6_CHECKS_SHA256 = CHECKS_SHA256
V6_LIMITS_SHA256 = V2_LIMITS_SHA256
V6_MANIFEST_SCHEMA = "historical-functional-review-pr466.v6"
V6_PREPARE_OBSERVATION = json.loads(
    '{"base_sha":"63e3ecd2f09d79c34e3594a3be74f017a1c5a12c","capacity":{"candidate_adjudication_candidate'
    '_upper_bound_before_call_cap":700,"candidate_and_summary_request_sizes":"UNKNOWN_UNTIL_PRIMARY_RESUL'
    'TS","candidate_count_for_semantic_adjudication":"UNKNOWN_UNTIL_PRIMARY_RESULTS","configured_claim_as'
    'sessment_call_slots":1,"configured_followup_task_slots":0,"configured_max_context_bytes":600000,"con'
    'figured_max_input_bytes_per_task":80000,"configured_max_provider_calls":10,"configured_optional_stag'
    'e_slots_excluding_candidate_adjudication":2,"configured_summary_advisory_call_slots":1,"effective_ma'
    'x_input_bytes_per_task":80000,"effective_snapshot_context_bytes":600000,"exact_primary_call_demand":'
    '7,"exact_primary_serialized_input_bytes":442578,"fits_call_cap":null,"max_candidate_items_per_primar'
    'y_response":100,"max_semantic_adjudication_calls_if_no_other_stage_uses_remaining_slots":3,"overall_'
    'capacity":"UNKNOWN_RUNTIME_DEMAND_WITHIN_CAPPED_LEDGER","primary_serialized_input_bytes_fit_context_'
    'cap":true,"remaining_global_call_slots_after_primary":3,"runtime_call_demand":"UNKNOWN_UNTIL_PRIMARY'
    '_RESULTS_AND_OPTIONAL_STAGE_ADMISSION","semantic_adjudication_calls_per_structurally_valid_candidate'
    '":1,"semantic_adjudication_supported_by_primary_provider":true,"status":"DYNAMIC_STAGE_DEMAND_UNKNOW'
    'N"},"case_id":"pr466-v6","configuration_identity_sha256":"065a8b4a2ea1be645d67c228b2c0fae89fffd2d44c'
    'd8d28de2bfbafe736c71e3","head_sha":"7bce9dd246f141eb961c52ae96061203a98f083b","historical_checks_sha'
    '256":"c7d3a28b0e12583dceb0021b04814573706f202a188e4cbed2d1ebde821d5963","limits_sha256":"964a11a8de3'
    'bfd47520ea62e358c954dceb1ac7da7f0648ef4db11d6f885870e","primary_requests":[{"input_bytes":77471,"inp'
    'ut_sha256":"df34d903482bae43aabea4be61eb8887fede6b130b9df0b192832d8f134aec4e","lens":"correctness","'
    'task_id":"task-b67231b415e0fae4:chunk-1"},{"input_bytes":54176,"input_sha256":"4ecdee413db0c298ec260'
    '5a2aaa294f976fc05297c7d8c2810e49fc434f36df9","lens":"tests","task_id":"task-c7bd62fae5d455e7:chunk-1'
    '"},{"input_bytes":51256,"input_sha256":"a905a406b5f73faf6f362a0aad2150ae53e9c3a65548cffc4696f88152a2'
    '0047","lens":"maintainability","task_id":"task-851071533f96bbe8:chunk-1"},{"input_bytes":73711,"inpu'
    't_sha256":"37cef28365bd53d79588e37f1524e461a7998f04eece6853c0e4cf8028823eed","lens":"correctness","t'
    'ask_id":"task-4ef4d2c78bf7eb5c:chunk-1"},{"input_bytes":74170,"input_sha256":"9ef86a3e75cebfa9a8c4c4'
    '3c5b6771ee077a122d2f18a921c2ecc00923e8a430","lens":"tests","task_id":"task-1417f5e58bbfecc9:chunk-1"'
    '},{"input_bytes":37526,"input_sha256":"de2c8d3117f95351d9083d8b6fd31d99f45fd4080f7e2047a9c30c2035644'
    '248","lens":"maintainability","task_id":"task-02fca8f4164306d8:chunk-1"},{"input_bytes":74268,"input'
    '_sha256":"09c051852d78364da38e2ab5f428ecf9acdefb2dc017bc37239c1b7912c9227f","lens":"security","task_'
    'id":"task-ba31ed7705450763:chunk-1"}],"profile_sha256":"5e83bc43c615f717df0d3d29722de08dd5990c84c8e6'
    '9d1705c94f3918d49692","provider_calls":0,"scope":{"admitted_obligation_ids":["check:portal-browser-e'
    'vidence","check:portal-impact-evidence","unit:unit-085bee8621ac5b68ceb3:lens:correctness","unit:unit'
    '-085bee8621ac5b68ceb3:lens:maintainability","unit:unit-085bee8621ac5b68ceb3:lens:security","unit:uni'
    't-085bee8621ac5b68ceb3:lens:tests","unit:unit-20fc055da4ded703dfc0:lens:correctness","unit:unit-20fc'
    '055da4ded703dfc0:lens:maintainability","unit:unit-20fc055da4ded703dfc0:lens:tests","unit:unit-a1b56f'
    '57f84276c8a5b6:lens:correctness","unit:unit-a1b56f57f84276c8a5b6:lens:maintainability","unit:unit-a1'
    'b56f57f84276c8a5b6:lens:tests","unit:unit-f1dcabcdb97f34fae272:lens:correctness","unit:unit-f1dcabcd'
    'b97f34fae272:lens:maintainability","unit:unit-f1dcabcdb97f34fae272:lens:tests"],"admitted_primary_ta'
    'sks":7,"coverage_obligations":[{"lens":"correctness","obligation_id":"unit:unit-f1dcabcdb97f34fae272'
    ':lens:correctness","obligation_kind":"CHANGED_UNIT_LENS","required":true,"scope_unit_ids":["unit-f1d'
    'cabcdb97f34fae272"]},{"lens":"tests","obligation_id":"unit:unit-f1dcabcdb97f34fae272:lens:tests","ob'
    'ligation_kind":"CHANGED_UNIT_LENS","required":true,"scope_unit_ids":["unit-f1dcabcdb97f34fae272"]},{'
    '"lens":"maintainability","obligation_id":"unit:unit-f1dcabcdb97f34fae272:lens:maintainability","obli'
    'gation_kind":"CHANGED_UNIT_LENS","required":true,"scope_unit_ids":["unit-f1dcabcdb97f34fae272"]},{"l'
    'ens":"correctness","obligation_id":"unit:unit-085bee8621ac5b68ceb3:lens:correctness","obligation_kin'
    'd":"CHANGED_UNIT_LENS","required":true,"scope_unit_ids":["unit-085bee8621ac5b68ceb3"]},{"lens":"test'
    's","obligation_id":"unit:unit-085bee8621ac5b68ceb3:lens:tests","obligation_kind":"CHANGED_UNIT_LENS"'
    ',"required":true,"scope_unit_ids":["unit-085bee8621ac5b68ceb3"]},{"lens":"maintainability","obligati'
    'on_id":"unit:unit-085bee8621ac5b68ceb3:lens:maintainability","obligation_kind":"CHANGED_UNIT_LENS","'
    'required":true,"scope_unit_ids":["unit-085bee8621ac5b68ceb3"]},{"lens":"security","obligation_id":"u'
    'nit:unit-085bee8621ac5b68ceb3:lens:security","obligation_kind":"CHANGED_UNIT_LENS","required":true,"'
    'scope_unit_ids":["unit-085bee8621ac5b68ceb3"]},{"lens":"correctness","obligation_id":"unit:unit-20fc'
    '055da4ded703dfc0:lens:correctness","obligation_kind":"CHANGED_UNIT_LENS","required":true,"scope_unit'
    '_ids":["unit-20fc055da4ded703dfc0"]},{"lens":"tests","obligation_id":"unit:unit-20fc055da4ded703dfc0'
    ':lens:tests","obligation_kind":"CHANGED_UNIT_LENS","required":true,"scope_unit_ids":["unit-20fc055da'
    '4ded703dfc0"]},{"lens":"maintainability","obligation_id":"unit:unit-20fc055da4ded703dfc0:lens:mainta'
    'inability","obligation_kind":"CHANGED_UNIT_LENS","required":true,"scope_unit_ids":["unit-20fc055da4d'
    'ed703dfc0"]},{"lens":"correctness","obligation_id":"unit:unit-a1b56f57f84276c8a5b6:lens:correctness"'
    ',"obligation_kind":"CHANGED_UNIT_LENS","required":true,"scope_unit_ids":["unit-a1b56f57f84276c8a5b6"'
    ']},{"lens":"tests","obligation_id":"unit:unit-a1b56f57f84276c8a5b6:lens:tests","obligation_kind":"CH'
    'ANGED_UNIT_LENS","required":true,"scope_unit_ids":["unit-a1b56f57f84276c8a5b6"]},{"lens":"maintainab'
    'ility","obligation_id":"unit:unit-a1b56f57f84276c8a5b6:lens:maintainability","obligation_kind":"CHAN'
    'GED_UNIT_LENS","required":true,"scope_unit_ids":["unit-a1b56f57f84276c8a5b6"]},{"check_binding_id":"'
    'external:portal-contract","obligation_id":"check:portal-impact-evidence","obligation_kind":"PROJECT_'
    'CHECK","reason":"Dependency manifests are packaging inputs; base AGENTS requires portal-impact revie'
    'w and portal-contract CI evidence for packaging changes. Bind evidence to the target repository and '
    'exact head from the configured GitHub check app; missing or mismatched evidence is UNKNOWN, and a fa'
    'iling check remains FAIL.","required":true,"scope_unit_ids":["unit-085bee8621ac5b68ceb3"]},{"check_b'
    'inding_id":"external:portal-browser","obligation_id":"check:portal-browser-evidence","obligation_kin'
    'd":"PROJECT_CHECK","reason":"Base AGENTS requires portal impact and relevant browser-journey check e'
    'vidence. This static pilot does not execute target code; evidence absent stays explicit.","required"'
    ':true,"scope_unit_ids":["unit-085bee8621ac5b68ceb3"]}],"inventory_units":4,"optional_context_gaps":['
    '{"path":"pyproject.toml","reason":"not_bound_by_context_selection","required":false,"retrievable":tr'
    'ue,"source_kind":"profile_context"},{"path":"Dockerfile","reason":"not_bound_by_context_selection","'
    'required":false,"retrievable":false,"source_kind":"profile_context"},{"path":".github/workflows/ci.y'
    'ml","reason":"not_bound_by_context_selection","required":false,"retrievable":true,"source_kind":"pro'
    'file_context"},{"path":"tests/test_mcp_gateway.py","reason":"not_bound_by_context_selection","requir'
    'ed":false,"retrievable":true,"source_kind":"profile_context"},{"path":"tests/test_mcp_harness.py","r'
    'eason":"not_bound_by_context_selection","required":false,"retrievable":true,"source_kind":"profile_c'
    'ontext"},{"path":"slopsearx/filters.py","reason":"not_bound_by_context_selection","required":false,"'
    'retrievable":true,"source_kind":"profile_context"},{"path":"slopsearx/config.py","reason":"not_bound'
    '_by_context_selection","required":false,"retrievable":true,"source_kind":"profile_context"}],"planne'
    'd_obligations":15,"planned_task_scopes":[{"evidence_ids":["ev-de145a5003dea0ca81a30cf5","ev-b8fc43e5'
    'c8eee1441a28372a","ev-8b9cefc9a8663c79a1d2c968","ev-d8ff93e4df2e04baf5afcb1d","ev-af66ab2a87301d715b'
    'bc8aa5","ev-9ccb507a2f619cc41e06a1fb","ev-065699951f269f92d32505bc","ev-81d4df109595015f954a73a3","e'
    'v-a811ebcdbf76a391c96b65ee","ev-7da3e672442ae193c3853e74","ev-4539962fb622ee18c60fd1ab","ev-863b4617'
    '3281c84e2fa795e6","ev-0fd051e134106f56f6aaeca3","ev-d7c8b3114e49045ec5fb4a10","ev-cc876aaec84d4ccd13'
    '926cd0"],"lens":"correctness","obligation_ids":["unit:unit-f1dcabcdb97f34fae272:lens:correctness","u'
    'nit:unit-20fc055da4ded703dfc0:lens:correctness","unit:unit-a1b56f57f84276c8a5b6:lens:correctness"],"'
    'required_context_ids":["ev-8b9cefc9a8663c79a1d2c968","ev-d8ff93e4df2e04baf5afcb1d","ev-af66ab2a87301'
    'd715bbc8aa5","ev-9ccb507a2f619cc41e06a1fb","ev-065699951f269f92d32505bc","ev-81d4df109595015f954a73a'
    '3","ev-a811ebcdbf76a391c96b65ee"],"task_id":"task-b67231b415e0fae4","task_kind":"SPECIALIST_FINDINGS'
    '","unit_ids":["unit-f1dcabcdb97f34fae272","unit-20fc055da4ded703dfc0","unit-a1b56f57f84276c8a5b6"]},'
    '{"evidence_ids":["ev-de145a5003dea0ca81a30cf5","ev-b8fc43e5c8eee1441a28372a","ev-8b9cefc9a8663c79a1d'
    '2c968","ev-d8ff93e4df2e04baf5afcb1d","ev-a811ebcdbf76a391c96b65ee","ev-7da3e672442ae193c3853e74","ev'
    '-4539962fb622ee18c60fd1ab","ev-863b46173281c84e2fa795e6","ev-0fd051e134106f56f6aaeca3","ev-d7c8b3114'
    'e49045ec5fb4a10","ev-cc876aaec84d4ccd13926cd0"],"lens":"tests","obligation_ids":["unit:unit-f1dcabcd'
    'b97f34fae272:lens:tests","unit:unit-20fc055da4ded703dfc0:lens:tests","unit:unit-a1b56f57f84276c8a5b6'
    ':lens:tests"],"required_context_ids":["ev-8b9cefc9a8663c79a1d2c968","ev-d8ff93e4df2e04baf5afcb1d","e'
    'v-a811ebcdbf76a391c96b65ee"],"task_id":"task-c7bd62fae5d455e7","task_kind":"SPECIALIST_FINDINGS","un'
    'it_ids":["unit-f1dcabcdb97f34fae272","unit-20fc055da4ded703dfc0","unit-a1b56f57f84276c8a5b6"]},{"evi'
    'dence_ids":["ev-de145a5003dea0ca81a30cf5","ev-b8fc43e5c8eee1441a28372a","ev-8b9cefc9a8663c79a1d2c968'
    '","ev-d8ff93e4df2e04baf5afcb1d","ev-7da3e672442ae193c3853e74","ev-4539962fb622ee18c60fd1ab","ev-863b'
    '46173281c84e2fa795e6","ev-0fd051e134106f56f6aaeca3","ev-d7c8b3114e49045ec5fb4a10","ev-cc876aaec84d4c'
    'cd13926cd0"],"lens":"maintainability","obligation_ids":["unit:unit-f1dcabcdb97f34fae272:lens:maintai'
    'nability","unit:unit-20fc055da4ded703dfc0:lens:maintainability","unit:unit-a1b56f57f84276c8a5b6:lens'
    ':maintainability"],"required_context_ids":["ev-8b9cefc9a8663c79a1d2c968","ev-d8ff93e4df2e04baf5afcb1'
    'd"],"task_id":"task-851071533f96bbe8","task_kind":"SPECIALIST_FINDINGS","unit_ids":["unit-f1dcabcdb9'
    '7f34fae272","unit-20fc055da4ded703dfc0","unit-a1b56f57f84276c8a5b6"]},{"evidence_ids":["ev-065699951'
    'f269f92d32505bc","ev-7ef2b76f2637f9692cfd4a1d","ev-81d4df109595015f954a73a3","ev-8b9cefc9a8663c79a1d'
    '2c968","ev-d8ff93e4df2e04baf5afcb1d","ev-af66ab2a87301d715bbc8aa5","ev-9ccb507a2f619cc41e06a1fb","ev'
    '-0fd051e134106f56f6aaeca3","ev-cc876aaec84d4ccd13926cd0","ev-7da3e672442ae193c3853e74","ev-863b46173'
    '281c84e2fa795e6","ev-de145a5003dea0ca81a30cf5","ev-b8fc43e5c8eee1441a28372a","ev-a811ebcdbf76a391c96'
    'b65ee"],"lens":"correctness","obligation_ids":["unit:unit-085bee8621ac5b68ceb3:lens:correctness"],"r'
    'equired_context_ids":["ev-8b9cefc9a8663c79a1d2c968","ev-d8ff93e4df2e04baf5afcb1d","ev-af66ab2a87301d'
    '715bbc8aa5","ev-9ccb507a2f619cc41e06a1fb","ev-0fd051e134106f56f6aaeca3","ev-cc876aaec84d4ccd13926cd0'
    '","ev-7da3e672442ae193c3853e74","ev-863b46173281c84e2fa795e6","ev-de145a5003dea0ca81a30cf5","ev-b8fc'
    '43e5c8eee1441a28372a","ev-a811ebcdbf76a391c96b65ee"],"task_id":"task-4ef4d2c78bf7eb5c","task_kind":"'
    'SPECIALIST_FINDINGS","unit_ids":["unit-085bee8621ac5b68ceb3"]},{"evidence_ids":["ev-065699951f269f92'
    'd32505bc","ev-7ef2b76f2637f9692cfd4a1d","ev-81d4df109595015f954a73a3","ev-8b9cefc9a8663c79a1d2c968",'
    '"ev-d8ff93e4df2e04baf5afcb1d","ev-af66ab2a87301d715bbc8aa5","ev-9ccb507a2f619cc41e06a1fb","ev-0fd051'
    'e134106f56f6aaeca3","ev-cc876aaec84d4ccd13926cd0","ev-7da3e672442ae193c3853e74","ev-863b46173281c84e'
    '2fa795e6","ev-de145a5003dea0ca81a30cf5","ev-b8fc43e5c8eee1441a28372a","ev-a811ebcdbf76a391c96b65ee"]'
    ',"lens":"tests","obligation_ids":["unit:unit-085bee8621ac5b68ceb3:lens:tests"],"required_context_ids'
    '":["ev-8b9cefc9a8663c79a1d2c968","ev-d8ff93e4df2e04baf5afcb1d","ev-af66ab2a87301d715bbc8aa5","ev-9cc'
    'b507a2f619cc41e06a1fb","ev-0fd051e134106f56f6aaeca3","ev-cc876aaec84d4ccd13926cd0","ev-7da3e672442ae'
    '193c3853e74","ev-863b46173281c84e2fa795e6","ev-de145a5003dea0ca81a30cf5","ev-b8fc43e5c8eee1441a28372'
    'a","ev-a811ebcdbf76a391c96b65ee"],"task_id":"task-1417f5e58bbfecc9","task_kind":"SPECIALIST_FINDINGS'
    '","unit_ids":["unit-085bee8621ac5b68ceb3"]},{"evidence_ids":["ev-065699951f269f92d32505bc","ev-7ef2b'
    '76f2637f9692cfd4a1d","ev-81d4df109595015f954a73a3","ev-8b9cefc9a8663c79a1d2c968","ev-d8ff93e4df2e04b'
    'af5afcb1d"],"lens":"maintainability","obligation_ids":["unit:unit-085bee8621ac5b68ceb3:lens:maintain'
    'ability"],"required_context_ids":["ev-8b9cefc9a8663c79a1d2c968","ev-d8ff93e4df2e04baf5afcb1d"],"task'
    '_id":"task-02fca8f4164306d8","task_kind":"SPECIALIST_FINDINGS","unit_ids":["unit-085bee8621ac5b68ceb'
    '3"]},{"evidence_ids":["ev-065699951f269f92d32505bc","ev-7ef2b76f2637f9692cfd4a1d","ev-81d4df10959501'
    '5f954a73a3","ev-8b9cefc9a8663c79a1d2c968","ev-d8ff93e4df2e04baf5afcb1d","ev-af66ab2a87301d715bbc8aa5'
    '","ev-9ccb507a2f619cc41e06a1fb","ev-0fd051e134106f56f6aaeca3","ev-cc876aaec84d4ccd13926cd0","ev-7da3'
    'e672442ae193c3853e74","ev-863b46173281c84e2fa795e6","ev-de145a5003dea0ca81a30cf5","ev-b8fc43e5c8eee1'
    '441a28372a","ev-a811ebcdbf76a391c96b65ee"],"lens":"security","obligation_ids":["unit:unit-085bee8621'
    'ac5b68ceb3:lens:security"],"required_context_ids":["ev-8b9cefc9a8663c79a1d2c968","ev-d8ff93e4df2e04b'
    'af5afcb1d","ev-af66ab2a87301d715bbc8aa5","ev-9ccb507a2f619cc41e06a1fb","ev-0fd051e134106f56f6aaeca3"'
    ',"ev-cc876aaec84d4ccd13926cd0","ev-7da3e672442ae193c3853e74","ev-863b46173281c84e2fa795e6","ev-de145'
    'a5003dea0ca81a30cf5","ev-b8fc43e5c8eee1441a28372a","ev-a811ebcdbf76a391c96b65ee"],"task_id":"task-ba'
    '31ed7705450763","task_kind":"SPECIALIST_FINDINGS","unit_ids":["unit-085bee8621ac5b68ceb3"]},{"eviden'
    'ce_ids":[],"lens":"project_specific","obligation_ids":["check:portal-impact-evidence"],"required_con'
    'text_ids":[],"task_id":"task-0a6ce508701dac4e","task_kind":"DETERMINISTIC_CHECK","unit_ids":["unit-0'
    '85bee8621ac5b68ceb3"]},{"evidence_ids":[],"lens":"project_specific","obligation_ids":["check:portal-'
    'browser-evidence"],"required_context_ids":[],"task_id":"task-7fa3d9fdf579373b","task_kind":"DETERMIN'
    'ISTIC_CHECK","unit_ids":["unit-085bee8621ac5b68ceb3"]}],"planned_tasks":9,"primary_scope_admission_c'
    'omplete":true,"required_context_gaps":[],"required_unadmitted_obligation_ids":[],"skipped_units":[],'
    '"unadmitted_obligation_ids":[],"uncovered_or_unadmitted_units":[],"units_assigned_to_admitted_primar'
    'y_tasks":4},"source_revision":"85dd6066491932f6f4f6eee5dab298df6537d3cd","status":"PREPARED_ONLY","t'
    'arget_code_executed":false,"target_repository":"magnus919/SlopSearX"}'
)
V5_PROJECTION = {
    "path": "pyproject.toml",
    "source_kind": "dependency_projection",
    "source_revision": HEAD,
    "trust": "repository_evidence",
    "evidence_id": "ev-bb3be39416ea72e1f34c761f",
    "content_bytes": 858,
    "content_hash": "75a555a088593a00fe5bea36ef4c819dd035eb55c72c25642052865d81e00b3a",
    "included_primary_task_ids": [
        "task-2735ee06f988542a:chunk-1",
        "task-d064dd83824e8ee6:chunk-1",
        "task-76d469ce77f3df5a:chunk-1",
        "task-1b70be284ec5f3b0:chunk-1",
        "task-df30f66a227eba98:chunk-1",
    ],
}
V4_PROJECTION = {
    "path": "pyproject.toml",
    "source_kind": "dependency_projection",
    "source_revision": HEAD,
    "trust": "repository_evidence",
    "evidence_id": "ev-7d389ea2e58de8c54ed68109",
    "content_bytes": 858,
    "content_hash": "75a555a088593a00fe5bea36ef4c819dd035eb55c72c25642052865d81e00b3a",
    "included_primary_task_ids": [
        "task-73422d1d4452c592:chunk-1",
        "task-43fc1554597a6096:chunk-1",
        "task-37d44cb9339851be:chunk-1",
        "task-6a0aad87db4d05a9:chunk-1",
        "task-1191806e0932af14:chunk-1",
    ],
}
DEFAULT_CASE = "pr466-v1"
CASE_CHOICES = ("pr466-v1", "pr466-v2", "pr466-v3", "pr466-v4", "pr466-v5", "pr466-v6")
CALL_CAP = 10
CONTEXT_CAP = 600_000
INPUT_CAP = 64_000
V2_INPUT_CAP = 80_000
V3_INPUT_CAP = 80_000
V4_INPUT_CAP = 80_000
V5_INPUT_CAP = 80_000
V6_INPUT_CAP = 80_000

V2_PREPARE_OBSERVATION = {
    "status": "PREPARED_ONLY",
    "source_revision": "1b4598b1ce2776104817d8a9a03040259abcf412",
    "profile_sha256": V2_PROFILE_SHA256,
    "historical_checks_sha256": V2_CHECKS_SHA256,
    "limits_sha256": V2_LIMITS_SHA256,
    "max_claim_assessments": 1,
    "max_provider_calls": CALL_CAP,
    "max_input_bytes_per_task": V2_INPUT_CAP,
    "max_context_bytes": CONTEXT_CAP,
    "no_provider_calls": True,
    "no_target_code_execution": True,
    "primary_scope_admission_complete": True,
    "admitted_obligations": 15,
    "planned_obligations": 15,
    "primary_request_count": 7,
    "total_primary_serialized_input_bytes": 394_539,
    "remaining_call_slots_after_primary": 3,
    "dynamic_stage_demand": "UNKNOWN_UNTIL_PRIMARY_RESULTS_AND_OPTIONAL_STAGE_ADMISSION",
    "primary_requests": [
        {
            "task_id": "task-f685da4711ebfae2:chunk-1",
            "lens": "correctness",
            "input_bytes": 49_602,
            "input_sha256": "c63b26e08a43974ac0c7b1761cf93022824e9a428c5a55d12019ed3f408b3cb1",
        },
        {
            "task_id": "task-813d7e8d2d627d7e:chunk-1",
            "lens": "tests",
            "input_bytes": 50_091,
            "input_sha256": "ab4fc773dae19e547d3f829950eaf037748034caf6e818611f214e693a9969c8",
        },
        {
            "task_id": "task-33993a52e194db73:chunk-1",
            "lens": "maintainability",
            "input_bytes": 49_571,
            "input_sha256": "85a985a26f5523879c54d1735686724437b66d5040a534858f6d45ef7d54309f",
        },
        {
            "task_id": "task-e297e02db7eb5e40:chunk-1",
            "lens": "correctness",
            "input_bytes": 69_190,
            "input_sha256": "4621e00ad19b84178073f77d93d082dae3d13d8f3397f5f834cafaaaebe4ea70",
        },
        {
            "task_id": "task-9f233e011829dd31:chunk-1",
            "lens": "tests",
            "input_bytes": 69_691,
            "input_sha256": "c2b16f9c71cca0027b429d8030fba42a4f0580435b77ad59a6b2eeeb8e03dd99",
        },
        {
            "task_id": "task-0e194f0ef7319e20:chunk-1",
            "lens": "maintainability",
            "input_bytes": 36_647,
            "input_sha256": "07dcc45da53cd409c1ee5a73c90bb0f2841419af05cc6d0f2de3199aaeeba041",
        },
        {
            "task_id": "task-a7e35017ef6c5491:chunk-1",
            "lens": "security",
            "input_bytes": 69_747,
            "input_sha256": "36135c4e9dc61d49d90ba1a9d391ea7dd18f2865242310fda3848a21e63fa278",
        },
    ],
}

V3_PREPARE_OBSERVATION = {
    "status": "PREPARED_ONLY",
    "profile_sha256": V3_PROFILE_SHA256,
    "historical_checks_sha256": V3_CHECKS_SHA256,
    "limits_sha256": V3_LIMITS_SHA256,
    "max_claim_assessments": 1,
    "max_provider_calls": CALL_CAP,
    "max_input_bytes_per_task": V3_INPUT_CAP,
    "max_context_bytes": CONTEXT_CAP,
    "no_provider_calls": True,
    "no_target_code_execution": True,
    "primary_scope_admission_complete": True,
    "admitted_obligations": 15,
    "planned_obligations": 15,
    "primary_request_count": 7,
    "total_primary_serialized_input_bytes": 417_632,
    "remaining_call_slots_after_primary": 3,
    "dynamic_stage_demand": "UNKNOWN_UNTIL_PRIMARY_RESULTS_AND_OPTIONAL_STAGE_ADMISSION",
    "primary_requests": [
        {
            "task_id": "task-7235c1a0b2742b75:chunk-1",
            "lens": "correctness",
            "input_bytes": 72_737,
            "input_sha256": "6824360fd3f4ebcd49d9fd53f2d3200d61722b346798ac980c52e6009a47af44",
        },
        {
            "task_id": "task-128b51c6d6a45b4e:chunk-1",
            "lens": "tests",
            "input_bytes": 50_084,
            "input_sha256": "c2930bbb95ddf98895493437dba2901d28142b2ae225d7ef3e0b428beba86270",
        },
        {
            "task_id": "task-f25690174a4821ea:chunk-1",
            "lens": "maintainability",
            "input_bytes": 49_564,
            "input_sha256": "502b3a6fb29dea305d0d2665084cd7645f02cad1b96a18a58de93b9e55b557dd",
        },
        {
            "task_id": "task-c18fc5c7712504f4:chunk-1",
            "lens": "correctness",
            "input_bytes": 69_183,
            "input_sha256": "6c0cac81c46bfaf8982ad50c7d8743f8549c89f11b132558b4df6479dfdcff20",
        },
        {
            "task_id": "task-e02ef3e302eebc8f:chunk-1",
            "lens": "tests",
            "input_bytes": 69_684,
            "input_sha256": "ec1a613521d088ef2ecdd00e94792968c9d0d938bf4b9377839176fc8dcaf923",
        },
        {
            "task_id": "task-96bd3831b4d55a43:chunk-1",
            "lens": "maintainability",
            "input_bytes": 36_640,
            "input_sha256": "8beef41bc1e3334ec58613deeb26462f03779a84ce021ac710c548196d8f1858",
        },
        {
            "task_id": "task-e737705989075b6c:chunk-1",
            "lens": "security",
            "input_bytes": 69_740,
            "input_sha256": "dc28cb669b2d8085501dc7fcfb7decda85a8fb4ece8cf85caf3b503eed2bda61",
        },
    ],
}

V4_PREPARE_OBSERVATION = {
    "status": "PREPARED_ONLY",
    "source_revision": "1f99d58eb5bd009da62a0537be7e7eed7cf88f5b",
    "profile_sha256": V4_PROFILE_SHA256,
    "historical_checks_sha256": V4_CHECKS_SHA256,
    "limits_sha256": V4_LIMITS_SHA256,
    "max_claim_assessments": 1,
    "max_provider_calls": CALL_CAP,
    "max_input_bytes_per_task": V4_INPUT_CAP,
    "max_context_bytes": CONTEXT_CAP,
    "no_provider_calls": True,
    "no_target_code_execution": True,
    "primary_scope_admission_complete": True,
    "admitted_obligations": 15,
    "planned_obligations": 15,
    "primary_request_count": 7,
    "total_primary_serialized_input_bytes": 441_227,
    "remaining_call_slots_after_primary": 3,
    "dynamic_stage_demand": "UNKNOWN_UNTIL_PRIMARY_RESULTS_AND_OPTIONAL_STAGE_ADMISSION",
    "dependency_projection": V4_PROJECTION,
    "installed_runtime_resolution": "UNKNOWN_FROM_DECLARATION_PROJECTION",
    "primary_requests": [
        {
            "task_id": "task-73422d1d4452c592:chunk-1",
            "lens": "correctness",
            "input_bytes": 77_234,
            "input_sha256": "867f8adea5c83a2e933791438442f54866dadfc912a8cbf0e36db17197010f6b",
        },
        {
            "task_id": "task-43fc1554597a6096:chunk-1",
            "lens": "tests",
            "input_bytes": 53_981,
            "input_sha256": "c713acc5dc433175ca4349bcf484fd339927aa7b48a4f0d9b337485f8c8b0149",
        },
        {
            "task_id": "task-825e221a4a67ace3:chunk-1",
            "lens": "maintainability",
            "input_bytes": 51_019,
            "input_sha256": "594c47813e1bc391a3f00b47089b7189ce29d0592d1b69d2ddc064ffc1c622a4",
        },
        {
            "task_id": "task-37d44cb9339851be:chunk-1",
            "lens": "correctness",
            "input_bytes": 73_530,
            "input_sha256": "923adccd993b6bc79ed1e4d1feb86868cc99d3a19e88f99920da4bad316365e1",
        },
        {
            "task_id": "task-6a0aad87db4d05a9:chunk-1",
            "lens": "tests",
            "input_bytes": 74_031,
            "input_sha256": "b2d33f5b2fd0d613b2645a209eb7ab6da9d8600979e83996c17cf91be01d683f",
        },
        {
            "task_id": "task-05c73b1f0fbc97b4:chunk-1",
            "lens": "maintainability",
            "input_bytes": 37_345,
            "input_sha256": "06c581a5e50badb39ee5b5f3bc52675e7af4816c5cba4f4d73c8eb73b235e865",
        },
        {
            "task_id": "task-1191806e0932af14:chunk-1",
            "lens": "security",
            "input_bytes": 74_087,
            "input_sha256": "06702f1bc05acc9d738eb0b75193decce38c8e6b8084e4113fcd5a2e51d0338d",
        },
    ],
}


class SafeFailure(Exception):
    """A fixed diagnostic that contains no supplied data or credential."""


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise SafeFailure("fixed_input_unavailable")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(repo: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_NOSYSTEM": "1"},
        )
    except (OSError, subprocess.SubprocessError):
        raise SafeFailure("git_identity_unavailable") from None
    value = result.stdout.strip()
    if args and args[0] == "cat-file" and args[1:2] == ("-e",):
        return "present"
    if not value or "\n" in value:
        raise SafeFailure("git_identity_invalid")
    return value


V5_PREPARE_OBSERVATION = {'status': 'PREPARED_ONLY',
 'source_revision': '78434b77948e531fbfb7d1f1690ef8d6c95cdb1e',
 'profile_sha256': 'f1a566359a7a5a9af317159dcc962e8b0223e90513516cc25a4f785200ee3156',
 'historical_checks_sha256': 'c7d3a28b0e12583dceb0021b04814573706f202a188e4cbed2d1ebde821d5963',
 'limits_sha256': '964a11a8de3bfd47520ea62e358c954dceb1ac7da7f0648ef4db11d6f885870e',
 'max_claim_assessments': 1,
 'max_provider_calls': 10,
 'max_input_bytes_per_task': 80000,
 'max_context_bytes': 600000,
 'no_provider_calls': True,
 'no_target_code_execution': True,
 'primary_scope_admission_complete': True,
 'admitted_obligations': 15,
 'planned_obligations': 15,
 'primary_request_count': 7,
 'total_primary_serialized_input_bytes': 441143,
 'remaining_call_slots_after_primary': 3,
 'dynamic_stage_demand': 'UNKNOWN_UNTIL_PRIMARY_RESULTS_AND_OPTIONAL_STAGE_ADMISSION',
 'primary_requests': [{'task_id': 'task-2735ee06f988542a:chunk-1',
                       'lens': 'correctness',
                       'input_bytes': 77234,
                       'input_sha256': '420bbb1390155bf1f639f879f9b9382c1f2561d281a8bb06fa69bb464ce06dbd'},
                      {'task_id': 'task-d064dd83824e8ee6:chunk-1',
                       'lens': 'tests',
                       'input_bytes': 53939,
                       'input_sha256': '066794516e6f5dfa3b414998acaa9b1dc6200ea51387457b900e07a6d0948d13'},
                      {'task_id': 'task-7414494eadd41224:chunk-1',
                       'lens': 'maintainability',
                       'input_bytes': 51019,
                       'input_sha256': 'c4a297ad79ea93405fd0af19c71167e323798cff0dcfbe0ec4ac12dfe87c2bd5'},
                      {'task_id': 'task-76d469ce77f3df5a:chunk-1',
                       'lens': 'correctness',
                       'input_bytes': 73530,
                       'input_sha256': '186319fe6587e767f33cbd404691cc60d6b8569151cada1bbf4cb9cba03d5e18'},
                      {'task_id': 'task-1b70be284ec5f3b0:chunk-1',
                       'lens': 'tests',
                       'input_bytes': 73989,
                       'input_sha256': 'f31a2eabe7b603ed3474cf5b8463f508bd725a48e2b6468a9129950754fddd97'},
                      {'task_id': 'task-805e397ed0a1ad57:chunk-1',
                       'lens': 'maintainability',
                       'input_bytes': 37345,
                       'input_sha256': '52e33d7f8b10ba57d9e79fcd63cc9b87249d6bca64e43d485d2f52aa79c584ed'},
                      {'task_id': 'task-df30f66a227eba98:chunk-1',
                       'lens': 'security',
                       'input_bytes': 74087,
                       'input_sha256': '73fbff93e7752510273bbf37ca36704a6271b8b10fce542580ae62171e7472d4'}],
 'dependency_projection': {'path': 'pyproject.toml',
                           'source_kind': 'dependency_projection',
                           'source_revision': '7bce9dd246f141eb961c52ae96061203a98f083b',
                           'trust': 'repository_evidence',
                           'evidence_id': 'ev-bb3be39416ea72e1f34c761f',
                           'content_bytes': 858,
                           'content_hash': '75a555a088593a00fe5bea36ef4c819dd035eb55c72c25642052865d81e00b3a',
                           'included_primary_task_ids': ['task-2735ee06f988542a:chunk-1',
                                                         'task-d064dd83824e8ee6:chunk-1',
                                                         'task-76d469ce77f3df5a:chunk-1',
                                                         'task-1b70be284ec5f3b0:chunk-1',
                                                         'task-df30f66a227eba98:chunk-1']},
 'installed_runtime_resolution': 'UNKNOWN_FROM_DECLARATION_PROJECTION'}

def _case_spec(case_id: str) -> dict:
    if case_id == "pr466-v1":
        return {
            "case_dir": CASE_DIR,
            "manifest": MANIFEST,
            "checks": CHECKS,
            "limits": LIMITS,
            "profile": PROFILE,
            "schema": "historical-functional-review-pr466.v1",
            "profile_version": "slopsearx-production-v8-static-review-boundaries",
            "profile_sha256": PROFILE_SHA256,
            "checks_sha256": CHECKS_SHA256,
            "limits_sha256": LIMITS_SHA256,
            "input_cap": INPUT_CAP,
            "prepare_observation": None,
        }
    if case_id == "pr466-v2":
        return {
            "case_dir": V2_CASE_DIR,
            "manifest": V2_MANIFEST,
            "checks": V2_CHECKS,
            "limits": V2_LIMITS,
            "profile": V2_PROFILE,
            "schema": V2_MANIFEST_SCHEMA,
            "profile_version": V2_PROFILE_VERSION,
            "profile_sha256": V2_PROFILE_SHA256,
            "checks_sha256": V2_CHECKS_SHA256,
            "limits_sha256": V2_LIMITS_SHA256,
            "input_cap": V2_INPUT_CAP,
            "prepare_observation": V2_PREPARE_OBSERVATION,
        }
    if case_id == "pr466-v3":
        return {
            "case_dir": V3_CASE_DIR,
            "manifest": V3_MANIFEST,
            "checks": V3_CHECKS,
            "limits": V3_LIMITS,
            "profile": V3_PROFILE,
            "schema": V3_MANIFEST_SCHEMA,
            "profile_version": V3_PROFILE_VERSION,
            "profile_sha256": V3_PROFILE_SHA256,
            "checks_sha256": V3_CHECKS_SHA256,
            "limits_sha256": V3_LIMITS_SHA256,
            "input_cap": V3_INPUT_CAP,
            "prepare_observation": V3_PREPARE_OBSERVATION,
        }
    if case_id == "pr466-v4":
        return {
            "case_dir": V4_CASE_DIR,
            "manifest": V4_MANIFEST,
            "checks": V4_CHECKS,
            "limits": V4_LIMITS,
            "profile": V4_PROFILE,
            "schema": V4_MANIFEST_SCHEMA,
            "profile_version": V4_PROFILE_VERSION,
            "profile_sha256": V4_PROFILE_SHA256,
            "checks_sha256": V4_CHECKS_SHA256,
            "limits_sha256": V4_LIMITS_SHA256,
            "input_cap": V4_INPUT_CAP,
            "prepare_observation": V4_PREPARE_OBSERVATION,
        }
    if case_id == "pr466-v5":
        return {
            "case_dir": V5_CASE_DIR,
            "manifest": V5_MANIFEST,
            "checks": V5_CHECKS,
            "limits": V5_LIMITS,
            "profile": V5_PROFILE,
            "schema": V5_MANIFEST_SCHEMA,
            "profile_version": V5_PROFILE_VERSION,
            "profile_sha256": V5_PROFILE_SHA256,
            "checks_sha256": V5_CHECKS_SHA256,
            "limits_sha256": V5_LIMITS_SHA256,
            "input_cap": V5_INPUT_CAP,
            "prepare_observation": V5_PREPARE_OBSERVATION,
        }
    if case_id == "pr466-v6":
        return {
            "case_dir": V6_CASE_DIR,
            "manifest": V6_MANIFEST,
            "checks": V6_CHECKS,
            "limits": V6_LIMITS,
            "profile": V6_PROFILE,
            "schema": V6_MANIFEST_SCHEMA,
            "profile_version": V6_PROFILE_VERSION,
            "profile_sha256": V6_PROFILE_SHA256,
            "checks_sha256": V6_CHECKS_SHA256,
            "limits_sha256": V6_LIMITS_SHA256,
            "input_cap": V6_INPUT_CAP,
            "prepare_observation": V6_PREPARE_OBSERVATION,
        }
    raise SafeFailure("case_not_supported")


def _validate_source_and_inputs(case_id: str = DEFAULT_CASE, *, allow_unpinned_prepare: bool = False) -> dict:
    spec = _case_spec(case_id)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        if (
            os.environ.get("GITHUB_REPOSITORY") != "groktopus/codereview"
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_WORKFLOW_REF")
            != "groktopus/codereview/.github/workflows/historical-functional-review.yml@refs/heads/main"
        ):
            raise SafeFailure("untrusted_source_context")
        expected = os.environ.get("GITHUB_SHA", "")
        actual = _git(ROOT, "rev-parse", "HEAD")
        if not re.fullmatch(r"[0-9a-f]{40}", expected) or actual != expected:
            raise SafeFailure("untrusted_source_revision")
    if (
        _sha(spec["profile"]) != spec["profile_sha256"]
        or _sha(spec["checks"]) != spec["checks_sha256"]
        or _sha(spec["limits"]) != spec["limits_sha256"]
    ):
        raise SafeFailure("case_input_hash_mismatch")
    try:
        manifest_path = spec["manifest"]
        stat_result = manifest_path.lstat()
        if manifest_path.is_symlink() or not manifest_path.is_file() or stat_result.st_size > 32_000:
            raise SafeFailure("case_manifest_invalid")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise SafeFailure("case_manifest_invalid") from None
    if not isinstance(manifest, dict):
        raise SafeFailure("case_manifest_invalid")
    case = manifest.get("case", {})
    profile = manifest.get("profile", {})
    checks = manifest.get("historical_checks", {})
    limits = manifest.get("limits", {})
    if not all(isinstance(item, dict) for item in (case, profile, checks, limits)):
        raise SafeFailure("case_manifest_invalid")
    provider_identity = manifest.get("provider_identity", {})
    retained = manifest.get("retained_prepare_observation", {})
    scope = manifest.get("diagnostic_scope", {})
    if not all(isinstance(item, dict) for item in (provider_identity, retained, scope)):
        raise SafeFailure("case_manifest_invalid")
    expected_fields = (
        {
            "schema",
            "case",
            "profile",
            "historical_checks",
            "limits",
            "provider_identity",
            "prepare_observation",
            "diagnostic_scope",
        }
        if case_id == "pr466-v6"
        else
        {
            "schema",
            "case",
            "profile",
            "historical_checks",
            "limits",
            "provider_identity",
            "retained_prepare_observation",
            "diagnostic_scope",
        }
        if spec["prepare_observation"] is None
        else {
            "schema",
            "case",
            "profile",
            "historical_checks",
            "limits",
            "provider_identity",
            "prepare_observation",
            "diagnostic_scope",
        }
    )
    if (
        set(manifest) != expected_fields
        or manifest.get("schema") != spec["schema"]
        or case != {"repository": REPOSITORY, "pull_request_number": 466, "base_sha": BASE, "head_sha": HEAD}
        or profile.get("path") != str(spec["profile"].relative_to(ROOT))
        or profile.get("version") != spec["profile_version"]
        or profile.get("sha256") != spec["profile_sha256"]
        or checks.get("path") != str(spec["checks"].relative_to(ROOT))
        or checks.get("sha256") != spec["checks_sha256"]
        or checks.get("freshness_basis") != "HISTORICAL_SNAPSHOT"
        or limits.get("path") != str(spec["limits"].relative_to(ROOT))
        or limits.get("sha256") != spec["limits_sha256"]
        or provider_identity.get("status") != "UNKNOWN"
        or provider_identity.get("primary") != {"base_url": None, "model": None}
        or provider_identity.get("decision") != {"endpoint": None, "model": None}
        or scope.get("effect_policy") != "READ_ONLY"
        or scope.get("target_code_execution") is not False
        or scope.get("provider_calls_in_retained_prepare") != 0
        or scope.get("case_total_call_ceiling") != 12
        or scope.get("claim_assessment_max") != 1
        or scope.get("source_auditor_calls") != 0
    ):
        raise SafeFailure("case_manifest_binding_mismatch")
    if case_id == "pr466-v6":
        stored_observation = manifest.get("prepare_observation")
        if stored_observation is None:
            if not allow_unpinned_prepare:
                raise SafeFailure("case_prepare_observation_unbound")
        elif spec["prepare_observation"] is None:
            raise SafeFailure("case_prepare_observation_not_pinned_in_runner")
        elif stored_observation != spec["prepare_observation"]:
            raise SafeFailure("case_prepare_observation_mismatch")
    elif spec["prepare_observation"] is None:
        if (
            retained.get("status") != "PREPARED_ONLY"
            or retained.get("primary_request_count") != 7
            or retained.get("total_primary_serialized_input_bytes") != 353963
            or retained.get("max_claim_assessments") != 0
        ):
            raise SafeFailure("case_manifest_binding_mismatch")
    elif manifest.get("prepare_observation") != spec["prepare_observation"]:
        raise SafeFailure("case_prepare_observation_mismatch")
    return manifest


def _validate_target(repo: Path, case_id: str = DEFAULT_CASE) -> None:
    _case_spec(case_id)
    if repo.is_symlink() or not repo.is_dir():
        raise SafeFailure("target_bare_repository_unavailable")
    if _git(repo, "rev-parse", "--is-bare-repository") != "true":
        raise SafeFailure("target_must_be_bare_repository")
    for revision in (BASE, HEAD):
        _git(repo, "cat-file", "-e", f"{revision}^{{commit}}")


def _limits_valid(case_id: str = DEFAULT_CASE) -> None:
    spec = _case_spec(case_id)
    try:
        limits = json.loads(spec["limits"].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise SafeFailure("limits_invalid") from None
    if not isinstance(limits, dict):
        raise SafeFailure("limits_invalid")
    expected = {
        "deadline_seconds": 600,
        "max_concurrent_scopes": 4,
        "max_provider_calls": CALL_CAP,
        "max_retries_per_task": 0,
        "max_context_bytes": CONTEXT_CAP,
        "max_input_bytes_per_task": spec["input_cap"],
        "max_output_bytes_per_task": 16_000,
        "max_output_bytes": 192_000,
        "max_output_tokens": 1800,
        "max_context_retrievals": 8,
        "max_followup_tasks": 0,
    }
    if any(limits.get(key) != value for key, value in expected.items()):
        raise SafeFailure("limits_contract_mismatch")


def _configuration_identity_sha256(provider: dict, decision: dict) -> str:
    identity = {"primary": provider, "decision": decision}
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _configs(directory: Path, *, live: bool, case_id: str = DEFAULT_CASE) -> tuple[Path, Path, str]:
    sys.path.insert(0, str(ROOT / "src"))
    sys.path.insert(0, str(ROOT / "scripts"))
    from provider_config_from_env import configurations_from_environment, write_config_files

    if live:
        env = {
            name: os.environ.get(name, "")
            for name in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY", "JEV_BASE_URL", "JEV_MODEL", "JEV_API_KEY")
        }
    else:
        env = {
            "LLM_BASE_URL": "https://inference-api.nousresearch.com/v1",
            "LLM_MODEL": "openai/gpt-6-luna",
            "LLM_API_KEY": "SIZING_ONLY_NOT_A_CREDENTIAL",
            "JEV_BASE_URL": "https://api.typesafe.ai/v1",
            "JEV_MODEL": "jev-latest",
            "JEV_API_KEY": "SIZING_ONLY_NOT_A_CREDENTIAL",
        }
    try:
        provider, decision = configurations_from_environment(env)
        configuration_identity_sha256 = _configuration_identity_sha256(provider, decision)
        if case_id == "pr466-v6":
            sizing_env = {
                "LLM_BASE_URL": "https://inference-api.nousresearch.com/v1",
                "LLM_MODEL": "openai/gpt-6-luna",
                "LLM_API_KEY": "SIZING_ONLY_NOT_A_CREDENTIAL",
                "JEV_BASE_URL": "https://api.typesafe.ai/v1",
                "JEV_MODEL": "jev-latest",
                "JEV_API_KEY": "SIZING_ONLY_NOT_A_CREDENTIAL",
            }
            sizing_provider, sizing_decision = configurations_from_environment(sizing_env)
            if configuration_identity_sha256 != _configuration_identity_sha256(sizing_provider, sizing_decision):
                raise SafeFailure("v6_provider_configuration_identity_mismatch")
        paths = write_config_files(directory, provider, decision)
    except SafeFailure:
        raise
    except Exception:
        raise SafeFailure("provider_configuration_invalid") from None
    return Path(paths["provider_config"]), Path(paths["decision_config"]), configuration_identity_sha256


def _cli(
    target: Path, output: Path, provider: Path, decision: Path, *, prepare: bool, case_id: str = DEFAULT_CASE
) -> dict:
    spec = _case_spec(case_id)
    command = [
        sys.executable,
        "-c",
        "from pr_review_harness.cli import main; raise SystemExit(main())",
        "review",
        "--repo",
        str(target),
        "--profile",
        str(spec["profile"]),
        "--provider-config",
        str(provider),
        "--decision-config",
        str(decision),
        "--limits",
        str(spec["limits"]),
        "--base",
        BASE,
        "--head",
        HEAD,
        "--historical-checks-json",
        str(spec["checks"]),
        "--output",
        str(output),
        "--max-claim-assessments",
        "1",
        "--json",
    ]
    if prepare:
        command.append("--prepare-only")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    for inherited in (
        "GITHUB_EVENT_PATH",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_RUNTIME_URL",
        "ACTIONS_RESULTS_URL",
    ):
        env.pop(inherited, None)
    try:
        completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=630)
    except (OSError, subprocess.SubprocessError):
        raise SafeFailure("review_cli_failed") from None
    if completed.returncode:
        raise SafeFailure("review_cli_failed")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise SafeFailure("review_cli_output_invalid") from None
    if not isinstance(result, dict):
        raise SafeFailure("review_cli_output_invalid")
    return result


def _validate_prepare(result: dict, case_id: str = DEFAULT_CASE, *, reference_observation: bool = True) -> None:
    spec = _case_spec(case_id)
    if result.get("no_provider_calls") is not True or result.get("no_target_code_execution") is not True:
        raise SafeFailure("prepare_invariant_failed")
    capacity = result.get("capacity", {})
    calls = capacity.get("exact_primary_call_demand")
    total_bytes = capacity.get("exact_primary_serialized_input_bytes")
    requests = result.get("primary_requests")
    review_scope = result.get("scope")
    request_sizes_valid = (
        isinstance(requests, list)
        and len(requests) <= CALL_CAP
        and all(
            isinstance(item, dict)
            and isinstance(item.get("input_bytes"), int)
            and not isinstance(item.get("input_bytes"), bool)
            and item["input_bytes"] > 0
            and item["input_bytes"] <= spec["input_cap"]
            for item in requests
        )
    )
    if (
        isinstance(calls, bool)
        or not isinstance(calls, int)
        or calls < 1
        or calls > CALL_CAP
        or isinstance(total_bytes, bool)
        or not isinstance(total_bytes, int)
        or total_bytes > CONTEXT_CAP
        or not request_sizes_valid
        or calls != len(requests)
        or sum(item["input_bytes"] for item in requests) != total_bytes
        or not isinstance(review_scope, dict)
        or review_scope.get("primary_scope_admission_complete") is not True
    ):
        raise SafeFailure("primary_request_capacity_exceeded")
    if case_id in ("pr466-v4", "pr466-v5", "pr466-v6"):
        if case_id == "pr466-v6" and review_scope.get("required_context_gaps") != []:
            raise SafeFailure("case_required_context_gaps_present")
        if case_id == "pr466-v6" and V6_PREPARE_OBSERVATION is None:
            # The first v6 preparation measures this new, pinned profile and source code.
            # Live mode is rejected until the exact observation is committed in both
            # the packet and this runner's immutable descriptor.
            profile = json.loads(V6_PROFILE.read_text(encoding="utf-8"))
            required_lenses = profile.get("required_lenses")
            actual_lenses = {row.get("lens") for row in requests if isinstance(row, dict)}
            planned_scopes = review_scope.get("planned_task_scopes")
            specialist_scopes = (
                [row for row in planned_scopes if isinstance(row, dict) and row.get("task_kind") == "SPECIALIST_FINDINGS"]
                if isinstance(planned_scopes, list)
                else []
            )
            scope_by_task = {
                row.get("task_id"): row
                for row in specialist_scopes
                if isinstance(row.get("task_id"), str) and row.get("task_id")
            }

            def request_matches_planned_scope(row: object) -> bool:
                if not isinstance(row, dict):
                    return False
                task_id = row.get("task_id")
                if not isinstance(task_id, str) or not task_id.endswith(":chunk-1"):
                    return False
                planned = scope_by_task.get(task_id[:-len(":chunk-1")])
                if not isinstance(planned, dict):
                    return False
                required_context_ids = planned.get("required_context_ids")
                request_evidence_ids = row.get("evidence_ids")
                return (
                    row.get("lens") == planned.get("lens")
                    and row.get("unit_ids") == planned.get("unit_ids")
                    and row.get("obligation_ids") == planned.get("obligation_ids")
                    and isinstance(required_context_ids, list)
                    and all(isinstance(item, str) for item in required_context_ids)
                    and isinstance(request_evidence_ids, list)
                    and all(isinstance(item, str) for item in request_evidence_ids)
                    and set(required_context_ids) <= set(request_evidence_ids)
                )

            admitted_ids = review_scope.get("admitted_obligation_ids")
            planned_count = review_scope.get("planned_obligations")
            obligation_rows = review_scope.get("coverage_obligations")
            request_scopes_are_bound = (
                len(scope_by_task) == len(specialist_scopes)
                and len(requests) == len(specialist_scopes)
                and all(request_matches_planned_scope(row) for row in requests)
            )
            valid_obligations = (
                isinstance(planned_count, int)
                and not isinstance(planned_count, bool)
                and planned_count > 0
                and isinstance(admitted_ids, list)
                and len(admitted_ids) == planned_count
                and all(isinstance(item, str) and item for item in admitted_ids)
                and len(set(admitted_ids)) == len(admitted_ids)
                and isinstance(obligation_rows, list)
                and len(obligation_rows) == planned_count
                and all(isinstance(item, dict) and isinstance(item.get("obligation_id"), str) for item in obligation_rows)
                and {item["obligation_id"] for item in obligation_rows} == set(admitted_ids)
            )
            required_context_shape = (
                isinstance(review_scope.get("admitted_obligation_ids"), list)
                and isinstance(review_scope.get("unadmitted_obligation_ids"), list)
                and not review_scope["unadmitted_obligation_ids"]
                and isinstance(review_scope.get("uncovered_or_unadmitted_units"), list)
                and not review_scope["uncovered_or_unadmitted_units"]
                and isinstance(review_scope.get("skipped_units"), list)
                and not review_scope["skipped_units"]
                and valid_obligations
            )
            request_evidence_is_bound = all(
                isinstance(row.get("task_id"), str)
                and bool(row["task_id"])
                and isinstance(row.get("lens"), str)
                and isinstance(row.get("input_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", row["input_sha256"])
                and row.get("admitted") is True
                and isinstance(row.get("evidence_ids"), list)
                and isinstance(row.get("evidence_bindings"), list)
                and row["evidence_ids"]
                and len(row["evidence_ids"]) == len(row["evidence_bindings"])
                and [binding.get("evidence_id") for binding in row["evidence_bindings"] if isinstance(binding, dict)]
                == row["evidence_ids"]
                and all(
                    isinstance(binding, dict)
                    and isinstance(binding.get("evidence_id"), str)
                    and binding.get("evidence_id") in row["evidence_ids"]
                    and isinstance(binding.get("path"), str)
                    and isinstance(binding.get("source_revision"), str)
                    and binding["source_revision"] in {BASE, HEAD}
                    and isinstance(binding.get("content_hash"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", binding["content_hash"])
                    and isinstance(binding.get("source_kind"), str)
                    and binding["source_kind"] in {"source_window", "diff", "profile_context", "dependency_projection"}
                    and binding.get("trust") in {
                        "untrusted_pr_content",
                        "trusted_policy",
                        "repository_evidence",
                    }
                    and (
                        (binding["source_kind"] in {"source_window", "diff"}
                         and binding.get("trust") == "untrusted_pr_content")
                        or (binding["source_kind"] == "profile_context"
                            and binding.get("trust") in {"trusted_policy", "repository_evidence"})
                        or (binding["source_kind"] == "dependency_projection"
                            and binding.get("trust") == "repository_evidence")
                    )
                    and isinstance(binding.get("content_bytes"), int)
                    and not isinstance(binding.get("content_bytes"), bool)
                    and binding["content_bytes"] >= 0
                    for binding in row["evidence_bindings"]
                )
                and row.get("required_context_omissions") == []
                for row in requests
            )
            if (
                not isinstance(required_lenses, list)
                or not required_lenses
                or not set(required_lenses).issubset(actual_lenses)
                or not required_context_shape
                or not request_evidence_is_bound
                or not request_scopes_are_bound
                or not valid_obligations
                or len({row.get("task_id") for row in requests if isinstance(row, dict)}) != len(requests)
            ):
                raise SafeFailure("case_prepare_observation_mismatch")
            return
        projection = V4_PROJECTION if case_id == "pr466-v4" else V5_PROJECTION
        if case_id == "pr466-v6":
            observation = V6_PREPARE_OBSERVATION
        else:
            observation = V4_PREPARE_OBSERVATION if case_id == "pr466-v4" else V5_PREPARE_OBSERVATION
        if case_id == "pr466-v6":
            expected_requests = observation["primary_requests"]
            actual_requests = [
                {key: row.get(key) for key in ("task_id", "lens", "input_bytes", "input_sha256")}
                for row in requests
            ]
            if actual_requests != expected_requests:
                raise SafeFailure("case_prepare_observation_mismatch")
            expected_scopes = [(row["task_id"], row["lens"]) for row in expected_requests]
            actual_scopes = [(row["task_id"], row["lens"]) for row in actual_requests]
            if actual_scopes != expected_scopes or any(
                not isinstance(row.get("input_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", row["input_sha256"])
                for row in actual_requests
            ):
                raise SafeFailure("case_prepare_observation_mismatch")
            if review_scope != observation.get("scope"):
                raise SafeFailure("case_prepare_observation_mismatch")
            return
        if review_scope.get("required_context_gaps") != []:
            raise SafeFailure("dependency_projection_required_context_invalid")
        expected_requests = observation["primary_requests"]
        actual_requests = [
            {key: row.get(key) for key in ("task_id", "lens", "input_bytes", "input_sha256")} for row in requests
        ]
        if reference_observation:
            if actual_requests != expected_requests:
                raise SafeFailure("case_prepare_observation_mismatch")
        else:
            expected_scopes = [(row["task_id"], row["lens"]) for row in expected_requests]
            actual_scopes = [(row["task_id"], row["lens"]) for row in actual_requests]
            if actual_scopes != expected_scopes or any(
                not isinstance(row.get("input_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", row["input_sha256"])
                for row in actual_requests
            ):
                raise SafeFailure("case_prepare_observation_mismatch")
        projection_tasks = []
        for request in requests:
            bindings = request.get("evidence_bindings")
            if not isinstance(bindings, list):
                raise SafeFailure("dependency_projection_required_context_invalid")
            matches = [
                binding
                for binding in bindings
                if isinstance(binding, dict) and binding.get("source_kind") == "dependency_projection"
            ]
            task_id = request.get("task_id")
            if task_id in projection["included_primary_task_ids"]:
                if len(matches) != 1:
                    raise SafeFailure("dependency_projection_required_context_invalid")
                binding = matches[0]
                if any(
                    binding.get(key) != value
                    for key, value in projection.items()
                    if key != "included_primary_task_ids"
                ):
                    raise SafeFailure("dependency_projection_required_context_invalid")
                projection_tasks.append(task_id)
            elif matches:
                raise SafeFailure("dependency_projection_required_context_invalid")
        if projection_tasks != projection["included_primary_task_ids"]:
            raise SafeFailure("dependency_projection_required_context_invalid")


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "run"):
        item = sub.add_parser(name)
        item.add_argument("--target-bare", required=True, type=Path)
        item.add_argument("--output-dir", required=True, type=Path)
        item.add_argument("--case", choices=CASE_CHOICES, default=DEFAULT_CASE)
        item.add_argument("--manifest-dir", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _args()
    try:
        spec = _case_spec(args.case)
        # Preserve the legacy flag, but it may name only the selected committed case.
        if args.manifest_dir is not None and args.manifest_dir.resolve() != spec["case_dir"].resolve():
            raise SafeFailure("manifest_directory_not_trusted")
        if args.command == "run" and (
            os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != "groktopus/codereview"
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_WORKFLOW_REF")
            != "groktopus/codereview/.github/workflows/historical-functional-review.yml@refs/heads/main"
        ):
            raise SafeFailure("live_mode_requires_trusted_workflow_dispatch")
        _validate_source_and_inputs(args.case, allow_unpinned_prepare=args.command == "prepare")
        _limits_valid(args.case)
        _validate_target(args.target_bare, args.case)
        args.output_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        os.chmod(args.output_dir, 0o700)
        with tempfile.TemporaryDirectory(prefix="pr466-provider-config-") as temp:
            config_dir = Path(temp) / "config"
            provider, decision, configuration_identity_sha256 = _configs(
                config_dir, live=args.command == "run", case_id=args.case
            )
            prepared = _cli(
                args.target_bare.resolve(),
                args.output_dir / "prepare",
                provider,
                decision,
                prepare=True,
                case_id=args.case,
            )
            _validate_prepare(prepared, args.case, reference_observation=args.command == "prepare")
            observation = {
                "status": "PREPARED_ONLY",
                "provider_calls": 0,
                "target_code_executed": False,
                "case_id": args.case,
                "source_revision": _git(ROOT, "rev-parse", "HEAD"),
                "target_repository": REPOSITORY,
                "base_sha": BASE,
                "head_sha": HEAD,
                "profile_sha256": spec["profile_sha256"],
                "historical_checks_sha256": spec["checks_sha256"],
                "limits_sha256": spec["limits_sha256"],
                "capacity": prepared["capacity"],
                "scope": prepared.get("scope"),
                "primary_requests": [
                    {key: row.get(key) for key in ("task_id", "lens", "input_bytes", "input_sha256")}
                    for row in prepared.get("primary_requests", [])
                    if isinstance(row, dict)
                ],
            }
            if args.case == "pr466-v6":
                observation["configuration_identity_sha256"] = configuration_identity_sha256
            if args.case == "pr466-v4":
                observation["dependency_projection"] = V4_PROJECTION
            elif args.case == "pr466-v5":
                observation["dependency_projection"] = V5_PROJECTION
            if args.case in ("pr466-v4", "pr466-v5"):
                observation["installed_runtime_resolution"] = "UNKNOWN_FROM_DECLARATION_PROJECTION"
            (args.output_dir / "prepare-observation.json").write_text(
                json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
            )
            if args.command == "prepare":
                print(
                    json.dumps(
                        {
                            "status": "PREPARED_ONLY",
                            "provider_calls": 0,
                            "prepare_observation": "prepare-observation.json",
                        },
                        separators=(",", ":"),
                    )
                )
                return 0
            result = _cli(
                args.target_bare.resolve(),
                args.output_dir / "review",
                provider,
                decision,
                prepare=False,
                case_id=args.case,
            )
            artifacts = []
            for key, destination, limit in (
                ("artifact_path", args.output_dir / "review-result.json", 8_000_000),
                ("report_path", args.output_dir / "review-report.md", 1_000_000),
            ):
                raw_path = result.get(key)
                if not isinstance(raw_path, str):
                    raise SafeFailure("review_artifact_missing")
                source = Path(raw_path)
                if source.is_symlink() or source.resolve().parent != (args.output_dir / "review").resolve():
                    raise SafeFailure("review_artifact_path_invalid")
                if not source.is_file() or source.stat().st_size > limit:
                    raise SafeFailure("review_artifact_size_invalid")
                shutil.copyfile(source, destination)
                artifacts.append(destination.name)
            print(
                json.dumps(
                    {
                        "status": "REVIEW_FINISHED",
                        "result": result.get("artifact_path"),
                        "safe_artifacts": artifacts,
                        "provider_calls": "see bounded ledger",
                    },
                    separators=(",", ":"),
                )
            )
            return 0
    except SafeFailure as exc:
        print(f"historical-functional-review: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
