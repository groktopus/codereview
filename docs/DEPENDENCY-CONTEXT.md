# Source-bound dependency context

The opt-in `dependency_context` profile setting (`dependency-context.v1`) projects a small, selected view of Python dependency metadata into review-task inputs. It supports PEP 621 direct declarations in `pyproject.toml` and package name/version rows in a uv `uv.lock` file. The projection describes repository files at an immutable BASE or HEAD revision; it does not establish which versions are installed by the application at runtime.

```json
{
  "dependency_context": {
    "version": "dependency-context.v1",
    "max_total_projection_bytes": 24000,
    "max_source_bytes": 262144,
    "bindings": [
      {
        "unit_patterns": ["src/service/*.py", "tests/test_service*.py", "docs/service.md"],
        "lenses": ["correctness", "security", "tests"],
        "sides": ["BASE", "HEAD"],
        "manifest_path": "pyproject.toml",
        "lock_path": "uv.lock",
        "packages": ["fastmcp", "mcp"],
        "max_bytes": 4000
      }
    ]
  }
}
```

Both paths are exact relative paths and must already be allowed by the profile's `context_paths` or `retrieval_context_patterns`. Package names, changed-unit patterns, review lenses, source sides, and all byte limits come from the trusted profile; model output cannot add packages or paths. A binding applies only to matching changed units and listed lenses. BASE and HEAD are separate records bound to their respective commit SHA and manifest blob ID. Lock metadata is likewise bound to its blob ID and hash when present.

Each projection includes only the selected direct requirements and matching lock facts. Repeated conditional requirements are retained. Multiple locked versions are reported as multiple entries; the projector does not choose one. A missing lock file is reported as `LOCK_FILE_ABSENT`; a present lock without a selected package is `PACKAGE_NOT_IN_LOCK`. Those differ from a missing, unsafe, oversized, or malformed manifest/lock, which creates a required context gap and a planner omission sentinel. The normal task input byte ceiling still applies after projection bytes are added.

The projection is derived evidence, not a raw source excerpt. It has no source line anchors; reviewers may cite its evidence ID and inspect the bound manifest/lock identity, but must not describe it as a line-level quote. It does not prove environment resolution, installation, vulnerability status, or supply-chain integrity. Use the ordinary CLI's `--prepare-only` path with the trusted profile and fixed BASE/HEAD revisions to verify exact task routing and serialized request sizes before any provider review. Prepare-only does not dispatch a provider or execute target code.
