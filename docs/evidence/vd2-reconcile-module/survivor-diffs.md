## pr_review_harness.reconcile.x__norm__mutmut_11

```diff
# pr_review_harness.reconcile.x__norm__mutmut_11: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -1,2 +1,2 @@
 def _norm(value: Any) -> str:
-    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()
+    return re.sub(r"\s+", " ", str(value or "XXXX").strip()).casefold()
```

## pr_review_harness.reconcile.x_validate_location__mutmut_3

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_3: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -5,7 +5,7 @@
     unit_map: dict[str, dict[str, Any]],
 ) -> tuple[bool, dict[str, Any], int | None, str | None]:
     """Validate HEAD/BASE line or explicit file-level anchors against snapshot inventory."""
-    raw = candidate.get("location", {})
+    raw = candidate.get("location", None)
     location = dict(raw) if isinstance(raw, dict) else {}
     path = location.get("path") or candidate.get("path")
     line = location.get("line") if location.get("line") is not None else candidate.get("line")
```

## pr_review_harness.reconcile.x_validate_location__mutmut_5

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_5: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -5,7 +5,7 @@
     unit_map: dict[str, dict[str, Any]],
 ) -> tuple[bool, dict[str, Any], int | None, str | None]:
     """Validate HEAD/BASE line or explicit file-level anchors against snapshot inventory."""
-    raw = candidate.get("location", {})
+    raw = candidate.get("location", )
     location = dict(raw) if isinstance(raw, dict) else {}
     path = location.get("path") or candidate.get("path")
     line = location.get("line") if location.get("line") is not None else candidate.get("line")
```

## pr_review_harness.reconcile.x_validate_location__mutmut_91

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_91: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -21,7 +21,7 @@
     if not unit or uid not in task_units:
         return False, location, None, uid
     paths = {unit.get("path")}
-    change_type = {"added": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
+    change_type = {"XXaddedXX": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
         unit.get("change_type"), unit.get("change_type")
     )
     if change_type == "rename":
```

## pr_review_harness.reconcile.x_validate_location__mutmut_92

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_92: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -21,7 +21,7 @@
     if not unit or uid not in task_units:
         return False, location, None, uid
     paths = {unit.get("path")}
-    change_type = {"added": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
+    change_type = {"ADDED": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
         unit.get("change_type"), unit.get("change_type")
     )
     if change_type == "rename":
```

## pr_review_harness.reconcile.x_validate_location__mutmut_93

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_93: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -21,7 +21,7 @@
     if not unit or uid not in task_units:
         return False, location, None, uid
     paths = {unit.get("path")}
-    change_type = {"added": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
+    change_type = {"added": "XXaddXX", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
         unit.get("change_type"), unit.get("change_type")
     )
     if change_type == "rename":
```

## pr_review_harness.reconcile.x_validate_location__mutmut_94

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_94: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -21,7 +21,7 @@
     if not unit or uid not in task_units:
         return False, location, None, uid
     paths = {unit.get("path")}
-    change_type = {"added": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
+    change_type = {"added": "ADD", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
         unit.get("change_type"), unit.get("change_type")
     )
     if change_type == "rename":
```

## pr_review_harness.reconcile.x_validate_location__mutmut_95

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_95: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -21,7 +21,7 @@
     if not unit or uid not in task_units:
         return False, location, None, uid
     paths = {unit.get("path")}
-    change_type = {"added": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
+    change_type = {"added": "add", "XXdeletedXX": "delete", "modified": "modify", "renamed": "rename"}.get(
         unit.get("change_type"), unit.get("change_type")
     )
     if change_type == "rename":
```

## pr_review_harness.reconcile.x_validate_location__mutmut_96

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_96: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -21,7 +21,7 @@
     if not unit or uid not in task_units:
         return False, location, None, uid
     paths = {unit.get("path")}
-    change_type = {"added": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
+    change_type = {"added": "add", "DELETED": "delete", "modified": "modify", "renamed": "rename"}.get(
         unit.get("change_type"), unit.get("change_type")
     )
     if change_type == "rename":
```

## pr_review_harness.reconcile.x_validate_location__mutmut_97

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_97: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -21,7 +21,7 @@
     if not unit or uid not in task_units:
         return False, location, None, uid
     paths = {unit.get("path")}
-    change_type = {"added": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
+    change_type = {"added": "add", "deleted": "XXdeleteXX", "modified": "modify", "renamed": "rename"}.get(
         unit.get("change_type"), unit.get("change_type")
     )
     if change_type == "rename":
```

## pr_review_harness.reconcile.x_validate_location__mutmut_98

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_98: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -21,7 +21,7 @@
     if not unit or uid not in task_units:
         return False, location, None, uid
     paths = {unit.get("path")}
-    change_type = {"added": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
+    change_type = {"added": "add", "deleted": "DELETE", "modified": "modify", "renamed": "rename"}.get(
         unit.get("change_type"), unit.get("change_type")
     )
     if change_type == "rename":
```

## pr_review_harness.reconcile.x_validate_location__mutmut_99

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_99: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -21,7 +21,7 @@
     if not unit or uid not in task_units:
         return False, location, None, uid
     paths = {unit.get("path")}
-    change_type = {"added": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
+    change_type = {"added": "add", "deleted": "delete", "XXmodifiedXX": "modify", "renamed": "rename"}.get(
         unit.get("change_type"), unit.get("change_type")
     )
     if change_type == "rename":
```

## pr_review_harness.reconcile.x_validate_location__mutmut_100

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_100: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -21,7 +21,7 @@
     if not unit or uid not in task_units:
         return False, location, None, uid
     paths = {unit.get("path")}
-    change_type = {"added": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
+    change_type = {"added": "add", "deleted": "delete", "MODIFIED": "modify", "renamed": "rename"}.get(
         unit.get("change_type"), unit.get("change_type")
     )
     if change_type == "rename":
```

## pr_review_harness.reconcile.x_validate_location__mutmut_101

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_101: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -21,7 +21,7 @@
     if not unit or uid not in task_units:
         return False, location, None, uid
     paths = {unit.get("path")}
-    change_type = {"added": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
+    change_type = {"added": "add", "deleted": "delete", "modified": "XXmodifyXX", "renamed": "rename"}.get(
         unit.get("change_type"), unit.get("change_type")
     )
     if change_type == "rename":
```

## pr_review_harness.reconcile.x_validate_location__mutmut_102

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_102: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -21,7 +21,7 @@
     if not unit or uid not in task_units:
         return False, location, None, uid
     paths = {unit.get("path")}
-    change_type = {"added": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
+    change_type = {"added": "add", "deleted": "delete", "modified": "MODIFY", "renamed": "rename"}.get(
         unit.get("change_type"), unit.get("change_type")
     )
     if change_type == "rename":
```

## pr_review_harness.reconcile.x_validate_location__mutmut_130

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_130: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -28,7 +28,7 @@
         paths.add(unit.get("old_path"))
     if path not in paths or side not in {"HEAD", "BASE"}:
         return False, location, None, uid
-    kind = location.get("kind", "line" if line is not None else None)
+    kind = location.get("kind", None)
     if kind == "file":
         expected = unit.get("file_level_location")
         ok = bool(
```

## pr_review_harness.reconcile.x_validate_location__mutmut_132

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_132: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -28,7 +28,7 @@
         paths.add(unit.get("old_path"))
     if path not in paths or side not in {"HEAD", "BASE"}:
         return False, location, None, uid
-    kind = location.get("kind", "line" if line is not None else None)
+    kind = location.get("kind", )
     if kind == "file":
         expected = unit.get("file_level_location")
         ok = bool(
```

## pr_review_harness.reconcile.x_validate_location__mutmut_135

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_135: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -28,7 +28,7 @@
         paths.add(unit.get("old_path"))
     if path not in paths or side not in {"HEAD", "BASE"}:
         return False, location, None, uid
-    kind = location.get("kind", "line" if line is not None else None)
+    kind = location.get("kind", "line" if (line is not None) and False else None)
     if kind == "file":
         expected = unit.get("file_level_location")
         ok = bool(
```

## pr_review_harness.reconcile.x_validate_location__mutmut_136

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_136: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -28,7 +28,7 @@
         paths.add(unit.get("old_path"))
     if path not in paths or side not in {"HEAD", "BASE"}:
         return False, location, None, uid
-    kind = location.get("kind", "line" if line is not None else None)
+    kind = location.get("kind", "line" if (line is not None) or True else None)
     if kind == "file":
         expected = unit.get("file_level_location")
         ok = bool(
```

## pr_review_harness.reconcile.x_validate_location__mutmut_137

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_137: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -28,7 +28,7 @@
         paths.add(unit.get("old_path"))
     if path not in paths or side not in {"HEAD", "BASE"}:
         return False, location, None, uid
-    kind = location.get("kind", "line" if line is not None else None)
+    kind = location.get("kind", "XXlineXX" if line is not None else None)
     if kind == "file":
         expected = unit.get("file_level_location")
         ok = bool(
```

## pr_review_harness.reconcile.x_validate_location__mutmut_138

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_138: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -28,7 +28,7 @@
         paths.add(unit.get("old_path"))
     if path not in paths or side not in {"HEAD", "BASE"}:
         return False, location, None, uid
-    kind = location.get("kind", "line" if line is not None else None)
+    kind = location.get("kind", "LINE" if line is not None else None)
     if kind == "file":
         expected = unit.get("file_level_location")
         ok = bool(
```

## pr_review_harness.reconcile.x_validate_location__mutmut_139

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_139: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -28,7 +28,7 @@
         paths.add(unit.get("old_path"))
     if path not in paths or side not in {"HEAD", "BASE"}:
         return False, location, None, uid
-    kind = location.get("kind", "line" if line is not None else None)
+    kind = location.get("kind", "line" if line is None else None)
     if kind == "file":
         expected = unit.get("file_level_location")
         ok = bool(
```

## pr_review_harness.reconcile.x_validate_location__mutmut_178

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_178: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -39,7 +39,7 @@
         )
         location.update({"path": path, "side": side, "kind": "file"})
         return ok, location, None, uid
-    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
+    if isinstance(line, bool) or not isinstance(line, int) or line <= 1:
         return False, location, None, uid
     if side == "BASE":
         ranges = unit.get("old_line_ranges", [])
```

## pr_review_harness.reconcile.x_validate_location__mutmut_179

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_179: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -39,7 +39,7 @@
         )
         location.update({"path": path, "side": side, "kind": "file"})
         return ok, location, None, uid
-    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
+    if isinstance(line, bool) or not isinstance(line, int) or line < 2:
         return False, location, None, uid
     if side == "BASE":
         ranges = unit.get("old_line_ranges", [])
```

## pr_review_harness.reconcile.x_validate_location__mutmut_193

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_193: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -43,7 +43,7 @@
         return False, location, None, uid
     if side == "BASE":
         ranges = unit.get("old_line_ranges", [])
-        expected_path = unit.get("old_path") if change_type == "rename" else unit.get("path")
+        expected_path = unit.get("old_path") if (change_type == "rename") or True else unit.get("path")
         ok = path == expected_path and any(
             isinstance(r, (list, tuple)) and len(r) >= 2 and int(r[0]) <= line <= int(r[1]) for r in ranges
         )
```

## pr_review_harness.reconcile.x_validate_location__mutmut_200

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_200: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -43,7 +43,7 @@
         return False, location, None, uid
     if side == "BASE":
         ranges = unit.get("old_line_ranges", [])
-        expected_path = unit.get("old_path") if change_type == "rename" else unit.get("path")
+        expected_path = unit.get("old_path") if change_type == "rename" else unit.get(None)
         ok = path == expected_path and any(
             isinstance(r, (list, tuple)) and len(r) >= 2 and int(r[0]) <= line <= int(r[1]) for r in ranges
         )
```

## pr_review_harness.reconcile.x_validate_location__mutmut_201

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_201: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -43,7 +43,7 @@
         return False, location, None, uid
     if side == "BASE":
         ranges = unit.get("old_line_ranges", [])
-        expected_path = unit.get("old_path") if change_type == "rename" else unit.get("path")
+        expected_path = unit.get("old_path") if change_type == "rename" else unit.get("XXpathXX")
         ok = path == expected_path and any(
             isinstance(r, (list, tuple)) and len(r) >= 2 and int(r[0]) <= line <= int(r[1]) for r in ranges
         )
```

## pr_review_harness.reconcile.x_validate_location__mutmut_202

```diff
# pr_review_harness.reconcile.x_validate_location__mutmut_202: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -43,7 +43,7 @@
         return False, location, None, uid
     if side == "BASE":
         ranges = unit.get("old_line_ranges", [])
-        expected_path = unit.get("old_path") if change_type == "rename" else unit.get("path")
+        expected_path = unit.get("old_path") if change_type == "rename" else unit.get("PATH")
         ok = path == expected_path and any(
             isinstance(r, (list, tuple)) and len(r) >= 2 and int(r[0]) <= line <= int(r[1]) for r in ranges
         )
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_6

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_6: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -2,7 +2,7 @@
     """Merge exact duplicates; conflicting assessments become unresolved, never votes."""
     groups: dict[str, list[dict]] = {}
     for finding in findings:
-        loc = finding.get("location", {}) if isinstance(finding.get("location"), dict) else {}
+        loc = finding.get("location", None) if isinstance(finding.get("location"), dict) else {}
         basis = {
             "snapshot_id": finding.get("snapshot_id"),
             "unit_id": finding.get("unit_id"),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_8

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_8: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -2,7 +2,7 @@
     """Merge exact duplicates; conflicting assessments become unresolved, never votes."""
     groups: dict[str, list[dict]] = {}
     for finding in findings:
-        loc = finding.get("location", {}) if isinstance(finding.get("location"), dict) else {}
+        loc = finding.get("location", ) if isinstance(finding.get("location"), dict) else {}
         basis = {
             "snapshot_id": finding.get("snapshot_id"),
             "unit_id": finding.get("unit_id"),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_51

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_51: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -8,7 +8,7 @@
             "unit_id": finding.get("unit_id"),
             "path": loc.get("path", finding.get("path")),
             "side": loc.get("side", "HEAD"),
-            "kind": loc.get("kind", "line" if loc.get("line") else "file"),
+            "kind": loc.get("kind", "line" if (loc.get("line")) and False else "file"),
             "line": loc.get("line"),
             "observation": _norm(finding.get("observation")),
             "consequence": _norm(finding.get("consequence")),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_53

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_53: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -8,7 +8,7 @@
             "unit_id": finding.get("unit_id"),
             "path": loc.get("path", finding.get("path")),
             "side": loc.get("side", "HEAD"),
-            "kind": loc.get("kind", "line" if loc.get("line") else "file"),
+            "kind": loc.get("kind", "XXlineXX" if loc.get("line") else "file"),
             "line": loc.get("line"),
             "observation": _norm(finding.get("observation")),
             "consequence": _norm(finding.get("consequence")),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_54

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_54: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -8,7 +8,7 @@
             "unit_id": finding.get("unit_id"),
             "path": loc.get("path", finding.get("path")),
             "side": loc.get("side", "HEAD"),
-            "kind": loc.get("kind", "line" if loc.get("line") else "file"),
+            "kind": loc.get("kind", "LINE" if loc.get("line") else "file"),
             "line": loc.get("line"),
             "observation": _norm(finding.get("observation")),
             "consequence": _norm(finding.get("consequence")),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_55

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_55: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -8,7 +8,7 @@
             "unit_id": finding.get("unit_id"),
             "path": loc.get("path", finding.get("path")),
             "side": loc.get("side", "HEAD"),
-            "kind": loc.get("kind", "line" if loc.get("line") else "file"),
+            "kind": loc.get("kind", "line" if loc.get(None) else "file"),
             "line": loc.get("line"),
             "observation": _norm(finding.get("observation")),
             "consequence": _norm(finding.get("consequence")),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_56

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_56: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -8,7 +8,7 @@
             "unit_id": finding.get("unit_id"),
             "path": loc.get("path", finding.get("path")),
             "side": loc.get("side", "HEAD"),
-            "kind": loc.get("kind", "line" if loc.get("line") else "file"),
+            "kind": loc.get("kind", "line" if loc.get("XXlineXX") else "file"),
             "line": loc.get("line"),
             "observation": _norm(finding.get("observation")),
             "consequence": _norm(finding.get("consequence")),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_57

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_57: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -8,7 +8,7 @@
             "unit_id": finding.get("unit_id"),
             "path": loc.get("path", finding.get("path")),
             "side": loc.get("side", "HEAD"),
-            "kind": loc.get("kind", "line" if loc.get("line") else "file"),
+            "kind": loc.get("kind", "line" if loc.get("LINE") else "file"),
             "line": loc.get("line"),
             "observation": _norm(finding.get("observation")),
             "consequence": _norm(finding.get("consequence")),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_93

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_93: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -19,7 +19,7 @@
 
     result: list[FindingRecord] = []
     for key, members in groups.items():
-        canonical = cast(FindingRecord, dict(sorted(members, key=lambda item: item.get("finding_id", ""))[0]))
+        canonical = cast(None, dict(sorted(members, key=lambda item: item.get("finding_id", ""))[0]))
         assessments = [m.get("semantic_assessment") for m in members if isinstance(m.get("semantic_assessment"), dict)]
         outcomes = {a.get("outcome") for a in assessments}
         support_shapes = {
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_104

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_104: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -19,7 +19,7 @@
 
     result: list[FindingRecord] = []
     for key, members in groups.items():
-        canonical = cast(FindingRecord, dict(sorted(members, key=lambda item: item.get("finding_id", ""))[0]))
+        canonical = cast(FindingRecord, dict(sorted(members, key=lambda item: item.get("finding_id", None))[0]))
         assessments = [m.get("semantic_assessment") for m in members if isinstance(m.get("semantic_assessment"), dict)]
         outcomes = {a.get("outcome") for a in assessments}
         support_shapes = {
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_106

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_106: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -19,7 +19,7 @@
 
     result: list[FindingRecord] = []
     for key, members in groups.items():
-        canonical = cast(FindingRecord, dict(sorted(members, key=lambda item: item.get("finding_id", ""))[0]))
+        canonical = cast(FindingRecord, dict(sorted(members, key=lambda item: item.get("finding_id", ))[0]))
         assessments = [m.get("semantic_assessment") for m in members if isinstance(m.get("semantic_assessment"), dict)]
         outcomes = {a.get("outcome") for a in assessments}
         support_shapes = {
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_109

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_109: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -19,7 +19,7 @@
 
     result: list[FindingRecord] = []
     for key, members in groups.items():
-        canonical = cast(FindingRecord, dict(sorted(members, key=lambda item: item.get("finding_id", ""))[0]))
+        canonical = cast(FindingRecord, dict(sorted(members, key=lambda item: item.get("finding_id", "XXXX"))[0]))
         assessments = [m.get("semantic_assessment") for m in members if isinstance(m.get("semantic_assessment"), dict)]
         outcomes = {a.get("outcome") for a in assessments}
         support_shapes = {
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_122

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_122: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -26,7 +26,7 @@
             tuple(
                 a.get(k)
                 for k in (
-                    "outcome",
+                    "XXoutcomeXX",
                     "observation_support",
                     "consequence_support",
                     "rule_connection_support",
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_123

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_123: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -26,7 +26,7 @@
             tuple(
                 a.get(k)
                 for k in (
-                    "outcome",
+                    "OUTCOME",
                     "observation_support",
                     "consequence_support",
                     "rule_connection_support",
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_136

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_136: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -37,7 +37,7 @@
             for a in assessments
         }
         conflict = (
-            "CONTRADICTED" in outcomes
+            "XXCONTRADICTEDXX" in outcomes
             or len({shape for shape in support_shapes if shape}) > 1
             and ("SUPPORTED" in outcomes or "CONTRADICTED" in outcomes)
         )
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_137

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_137: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -37,7 +37,7 @@
             for a in assessments
         }
         conflict = (
-            "CONTRADICTED" in outcomes
+            "contradicted" in outcomes
             or len({shape for shape in support_shapes if shape}) > 1
             and ("SUPPORTED" in outcomes or "CONTRADICTED" in outcomes)
         )
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_146

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_146: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -39,7 +39,7 @@
         conflict = (
             "CONTRADICTED" in outcomes
             or len({shape for shape in support_shapes if shape}) > 1
-            and ("SUPPORTED" in outcomes or "CONTRADICTED" in outcomes)
+            and ("SUPPORTED" in outcomes or "XXCONTRADICTEDXX" in outcomes)
         )
         canonical["candidate_ids"] = sorted(
             {m.get("candidate_id", m.get("finding_id")) for m in members if m.get("candidate_id", m.get("finding_id"))}
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_147

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_147: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -39,7 +39,7 @@
         conflict = (
             "CONTRADICTED" in outcomes
             or len({shape for shape in support_shapes if shape}) > 1
-            and ("SUPPORTED" in outcomes or "CONTRADICTED" in outcomes)
+            and ("SUPPORTED" in outcomes or "contradicted" in outcomes)
         )
         canonical["candidate_ids"] = sorted(
             {m.get("candidate_id", m.get("finding_id")) for m in members if m.get("candidate_id", m.get("finding_id"))}
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_162

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_162: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -42,7 +42,7 @@
             and ("SUPPORTED" in outcomes or "CONTRADICTED" in outcomes)
         )
         canonical["candidate_ids"] = sorted(
-            {m.get("candidate_id", m.get("finding_id")) for m in members if m.get("candidate_id", m.get("finding_id"))}
+            {m.get("candidate_id", m.get("finding_id")) for m in members if m.get(None, m.get("finding_id"))}
         )
         canonical["task_ids"] = sorted({m.get("task_id") for m in members if m.get("task_id")})
         canonical["evidence_refs"] = sorted({ref for m in members for ref in m.get("evidence_refs", [])})
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_166

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_166: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -42,7 +42,7 @@
             and ("SUPPORTED" in outcomes or "CONTRADICTED" in outcomes)
         )
         canonical["candidate_ids"] = sorted(
-            {m.get("candidate_id", m.get("finding_id")) for m in members if m.get("candidate_id", m.get("finding_id"))}
+            {m.get("candidate_id", m.get("finding_id")) for m in members if m.get("XXcandidate_idXX", m.get("finding_id"))}
         )
         canonical["task_ids"] = sorted({m.get("task_id") for m in members if m.get("task_id")})
         canonical["evidence_refs"] = sorted({ref for m in members for ref in m.get("evidence_refs", [])})
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_167

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_167: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -42,7 +42,7 @@
             and ("SUPPORTED" in outcomes or "CONTRADICTED" in outcomes)
         )
         canonical["candidate_ids"] = sorted(
-            {m.get("candidate_id", m.get("finding_id")) for m in members if m.get("candidate_id", m.get("finding_id"))}
+            {m.get("candidate_id", m.get("finding_id")) for m in members if m.get("CANDIDATE_ID", m.get("finding_id"))}
         )
         canonical["task_ids"] = sorted({m.get("task_id") for m in members if m.get("task_id")})
         canonical["evidence_refs"] = sorted({ref for m in members for ref in m.get("evidence_refs", [])})
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_186

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_186: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -45,7 +45,7 @@
             {m.get("candidate_id", m.get("finding_id")) for m in members if m.get("candidate_id", m.get("finding_id"))}
         )
         canonical["task_ids"] = sorted({m.get("task_id") for m in members if m.get("task_id")})
-        canonical["evidence_refs"] = sorted({ref for m in members for ref in m.get("evidence_refs", [])})
+        canonical["evidence_refs"] = sorted({ref for m in members for ref in m.get("evidence_refs", None)})
         canonical["assessment_records"] = [
             {
                 "candidate_id": m.get("candidate_id", m.get("finding_id")),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_188

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_188: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -45,7 +45,7 @@
             {m.get("candidate_id", m.get("finding_id")) for m in members if m.get("candidate_id", m.get("finding_id"))}
         )
         canonical["task_ids"] = sorted({m.get("task_id") for m in members if m.get("task_id")})
-        canonical["evidence_refs"] = sorted({ref for m in members for ref in m.get("evidence_refs", [])})
+        canonical["evidence_refs"] = sorted({ref for m in members for ref in m.get("evidence_refs", )})
         canonical["assessment_records"] = [
             {
                 "candidate_id": m.get("candidate_id", m.get("finding_id")),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_197

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_197: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -48,7 +48,7 @@
         canonical["evidence_refs"] = sorted({ref for m in members for ref in m.get("evidence_refs", [])})
         canonical["assessment_records"] = [
             {
-                "candidate_id": m.get("candidate_id", m.get("finding_id")),
+                "candidate_id": m.get("candidate_id", None),
                 "task_id": m.get("task_id"),
                 "semantic_assessment": m.get("semantic_assessment"),
                 "semantic_usage": m.get("semantic_usage", {}),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_199

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_199: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -48,7 +48,7 @@
         canonical["evidence_refs"] = sorted({ref for m in members for ref in m.get("evidence_refs", [])})
         canonical["assessment_records"] = [
             {
-                "candidate_id": m.get("candidate_id", m.get("finding_id")),
+                "candidate_id": m.get("candidate_id", ),
                 "task_id": m.get("task_id"),
                 "semantic_assessment": m.get("semantic_assessment"),
                 "semantic_usage": m.get("semantic_usage", {}),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_202

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_202: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -48,7 +48,7 @@
         canonical["evidence_refs"] = sorted({ref for m in members for ref in m.get("evidence_refs", [])})
         canonical["assessment_records"] = [
             {
-                "candidate_id": m.get("candidate_id", m.get("finding_id")),
+                "candidate_id": m.get("candidate_id", m.get(None)),
                 "task_id": m.get("task_id"),
                 "semantic_assessment": m.get("semantic_assessment"),
                 "semantic_usage": m.get("semantic_usage", {}),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_203

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_203: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -48,7 +48,7 @@
         canonical["evidence_refs"] = sorted({ref for m in members for ref in m.get("evidence_refs", [])})
         canonical["assessment_records"] = [
             {
-                "candidate_id": m.get("candidate_id", m.get("finding_id")),
+                "candidate_id": m.get("candidate_id", m.get("XXfinding_idXX")),
                 "task_id": m.get("task_id"),
                 "semantic_assessment": m.get("semantic_assessment"),
                 "semantic_usage": m.get("semantic_usage", {}),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_204

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_204: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -48,7 +48,7 @@
         canonical["evidence_refs"] = sorted({ref for m in members for ref in m.get("evidence_refs", [])})
         canonical["assessment_records"] = [
             {
-                "candidate_id": m.get("candidate_id", m.get("finding_id")),
+                "candidate_id": m.get("candidate_id", m.get("FINDING_ID")),
                 "task_id": m.get("task_id"),
                 "semantic_assessment": m.get("semantic_assessment"),
                 "semantic_usage": m.get("semantic_usage", {}),
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_236

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_236: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -57,7 +57,7 @@
             for m in sorted(
                 members,
                 key=lambda item: (
-                    str(item.get("task_id", "")),
+                    str(None),
                     str(item.get("candidate_id", item.get("finding_id", ""))),
                 ),
             )
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_237

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_237: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -57,7 +57,7 @@
             for m in sorted(
                 members,
                 key=lambda item: (
-                    str(item.get("task_id", "")),
+                    str(item.get(None, "")),
                     str(item.get("candidate_id", item.get("finding_id", ""))),
                 ),
             )
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_238

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_238: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -57,7 +57,7 @@
             for m in sorted(
                 members,
                 key=lambda item: (
-                    str(item.get("task_id", "")),
+                    str(item.get("task_id", None)),
                     str(item.get("candidate_id", item.get("finding_id", ""))),
                 ),
             )
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_239

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_239: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -57,7 +57,7 @@
             for m in sorted(
                 members,
                 key=lambda item: (
-                    str(item.get("task_id", "")),
+                    str(item.get("")),
                     str(item.get("candidate_id", item.get("finding_id", ""))),
                 ),
             )
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_240

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_240: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -57,7 +57,7 @@
             for m in sorted(
                 members,
                 key=lambda item: (
-                    str(item.get("task_id", "")),
+                    str(item.get("task_id", )),
                     str(item.get("candidate_id", item.get("finding_id", ""))),
                 ),
             )
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_241

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_241: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -57,7 +57,7 @@
             for m in sorted(
                 members,
                 key=lambda item: (
-                    str(item.get("task_id", "")),
+                    str(item.get("XXtask_idXX", "")),
                     str(item.get("candidate_id", item.get("finding_id", ""))),
                 ),
             )
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_242

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_242: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -57,7 +57,7 @@
             for m in sorted(
                 members,
                 key=lambda item: (
-                    str(item.get("task_id", "")),
+                    str(item.get("TASK_ID", "")),
                     str(item.get("candidate_id", item.get("finding_id", ""))),
                 ),
             )
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_243

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_243: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -57,7 +57,7 @@
             for m in sorted(
                 members,
                 key=lambda item: (
-                    str(item.get("task_id", "")),
+                    str(item.get("task_id", "XXXX")),
                     str(item.get("candidate_id", item.get("finding_id", ""))),
                 ),
             )
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_244

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_244: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(None),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_245

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_245: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(item.get(None, item.get("finding_id", ""))),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_246

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_246: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(item.get("candidate_id", None)),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_247

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_247: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(item.get(item.get("finding_id", ""))),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_248

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_248: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(item.get("candidate_id", )),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_249

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_249: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(item.get("XXcandidate_idXX", item.get("finding_id", ""))),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_250

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_250: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(item.get("CANDIDATE_ID", item.get("finding_id", ""))),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_251

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_251: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(item.get("candidate_id", item.get(None, ""))),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_252

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_252: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(item.get("candidate_id", item.get("finding_id", None))),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_253

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_253: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(item.get("candidate_id", item.get(""))),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_254

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_254: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(item.get("candidate_id", item.get("finding_id", ))),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_255

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_255: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(item.get("candidate_id", item.get("XXfinding_idXX", ""))),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_256

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_256: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(item.get("candidate_id", item.get("FINDING_ID", ""))),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_257

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_257: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -58,7 +58,7 @@
                 members,
                 key=lambda item: (
                     str(item.get("task_id", "")),
-                    str(item.get("candidate_id", item.get("finding_id", ""))),
+                    str(item.get("candidate_id", item.get("finding_id", "XXXX"))),
                 ),
             )
         ]
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_267

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_267: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -63,7 +63,7 @@
             )
         ]
         canonical["duplicate_count"] = len(members) - 1
-        canonical["correlation_group_id"] = "correlation-" + key[:16] if len(members) > 1 or conflict else None
+        canonical["correlation_group_id"] = "correlation-" + key[:16] if (len(members) > 1 or conflict) or True else None
         if conflict:
             canonical["status"] = "CONTRADICTED"
             canonical["blocking_class"] = "UNRESOLVED"
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_273

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_273: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -63,7 +63,7 @@
             )
         ]
         canonical["duplicate_count"] = len(members) - 1
-        canonical["correlation_group_id"] = "correlation-" + key[:16] if len(members) > 1 or conflict else None
+        canonical["correlation_group_id"] = "correlation-" + key[:16] if len(members) >= 1 or conflict else None
         if conflict:
             canonical["status"] = "CONTRADICTED"
             canonical["blocking_class"] = "UNRESOLVED"
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_302

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_302: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -72,4 +72,4 @@
             )
             canonical["reconciliation_conflict"] = True
         result.append(canonical)
-    return sorted(result, key=lambda finding: finding.get("finding_id", ""))
+    return sorted(result, key=lambda finding: finding.get("finding_id", None))
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_304

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_304: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -72,4 +72,4 @@
             )
             canonical["reconciliation_conflict"] = True
         result.append(canonical)
-    return sorted(result, key=lambda finding: finding.get("finding_id", ""))
+    return sorted(result, key=lambda finding: finding.get("finding_id", ))
```

## pr_review_harness.reconcile.x_consolidate_findings__mutmut_307

```diff
# pr_review_harness.reconcile.x_consolidate_findings__mutmut_307: survived
--- src/pr_review_harness/reconcile.py
+++ src/pr_review_harness/reconcile.py
@@ -72,4 +72,4 @@
             )
             canonical["reconciliation_conflict"] = True
         result.append(canonical)
-    return sorted(result, key=lambda finding: finding.get("finding_id", ""))
+    return sorted(result, key=lambda finding: finding.get("finding_id", "XXXX"))
```
