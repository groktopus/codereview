# FastMCP/MCP HTTP API evidence audit

Date: 2026-10-01. This is a source-only compatibility review; no SlopSearX code was executed and no installed target environment was inspected.

## Target evidence

The immutable target is PR 466, BASE `63e3ecd2f09d79c34e3594a3be74f017a1c5a12c`, HEAD `7bce9dd246f141eb961c52ae96061203a98f083b`. In `slopsearx/mcp/security.py`, BASE calls `server.http_app(transport="streamable-http")` when `hasattr(server, "http_app")`; HEAD adds `stateless_http=True, json_response=True` to that call. The fallback `server.streamable_http_app()` is byte-identical. Thus the new keywords only affect the existing method-present branch; they do not introduce that branch or the fallback selection.

Target `pyproject.toml` declares `fastmcp>=2.0,<4` and `mcp>=1.0,<3`. More importantly, `slopsearx/mcp/server.py` chooses the imported class: when installed `fastmcp` major is below 4 it imports `FastMCP` from `mcp.server.fastmcp`; for major 4+ it imports from `fastmcp`. It then sets `_MODERN_FASTMCP = hasattr(FastMCP, "http_app")`. Therefore PrefectHQ FastMCP's own `FastMCP` class is not the class selected by this target for its declared 2.x/3.x branch. Its source is useful only as adjacent API history, not proof of this target's runtime behavior.

## Immutable upstream source samples

GitHub API resolved the release refs to these commits. The commit objects report GitHub verification `verified=true, reason=valid`; the refs are lightweight commit refs, so this is commit-signature verification rather than a signed annotated-tag claim. Blob hashes below identify the exact source files inspected.

| Upstream tag | Commit | File blob | Observed API |
|---|---|---|---|
| PrefectHQ/fastmcp v2.3.0 | `c482c990766edbd6620156f0ec9b52558f98595a` | `src/fastmcp/server/server.py` `0d7c60ef8db084b747354a2887dcfbc7abcb18d6` | Has `streamable_http_app`; no `http_app` in this file. It passes `json_response` and `stateless_http` from settings to its app factory. |
| PrefectHQ/fastmcp v2.10.0 | `39f7b30a8bd944b8adc82fc9c3819af54e9bba86` | `src/fastmcp/server/server.py` `e365efbec418fd08c49221be1924c979ada91514` | `http_app` accepts `json_response`, `stateless_http`, and `transport`. |
| PrefectHQ/fastmcp v2.13.0 | `716e50dae0b445fb7fd0251725fc827c045d5fdd` | `src/fastmcp/server/server.py` `15dd1ac7b5bf0a0db6e069f5157c4db3d364479a` | `http_app` accepts `json_response`, `stateless_http`, and `transport`. |
| PrefectHQ/fastmcp v3.1.0 | `8bc31360e85b1192e78615f09fc525d57ff5c5f7` | `src/fastmcp/server/mixins/transport.py` `833b5e385166085f9a67cec846e700e0a02904f4` | `TransportMixin.http_app` accepts `json_response`, `stateless_http`, and `transport`. The class uses this mixin. |

These samples establish that the Prefect FastMCP API differs across those sampled tags, but do not establish behavior for every release in `>=2,<4` or for the MCP SDK class this target imports. The FastMCP v3.1.0 `pyproject.toml` at blob `3ada527fa88e716e360047e10abe9af44edb0469` requires `mcp>=1.24.0,<2.0`; sampled FastMCP v2 tags likewise depend on the separately published MCP SDK. This reinforces that the resolved SDK class must be checked directly.

The official `modelcontextprotocol/python-sdk` samples show the MCP SDK's `mcp.server.fastmcp.server.FastMCP` class exposes `streamable_http_app()` at v1.9.0 (commit `6353dd192c41b891ef3bf1dfc093db46f6e2175a`, blob `21c31b0b336e79a91dfa35e5c7a1eece8ff3ba97`), v1.12.0 (commit `99c4f3c906a130ab7f4a03e5f255280e0cdce395`, blob `2fe7c122423224e1bebb26f279c1ff9a3d3bce78`), and v1.26.0 (commit `3d9d34552a9ab8988acf8d06e4a705bd799fc32b`, blob `7a43bd7cf0f468c94e95677781a468ede244152a`). All three commit objects report GitHub verification `true/valid`. In these inspected source files the method has no explicit mode arguments and no `http_app` method appears. The signed annotated v1.0.0 tag resolves to commit `91b255f83f9790e924becc5854dc33265cf4bead`; its tree has no `src/mcp/server/fastmcp` path. This only shows the raw direct lower bound does not itself identify a usable class—the `fastmcp` distribution's transitive constraints also affect resolution. MCP SDK v2.0.0 commit `6f69a3758ebf2ee55ce050f58b470ce11af71133` reports GitHub verification `true/valid` and has a reorganized tree (`mcp.server.mcpserver`) with no `mcp.server.fastmcp` path. These sampled trees reinforce that the target's two broad direct dependency bounds do not, by themselves, identify a valid resolved import or method contract.

Source permalinks:

- [FastMCP 2.3.0 server](https://github.com/PrefectHQ/fastmcp/blob/c482c990766edbd6620156f0ec9b52558f98595a/src/fastmcp/server/server.py#L759)
- [FastMCP 2.10.0 server](https://github.com/PrefectHQ/fastmcp/blob/39f7b30a8bd944b8adc82fc9c3819af54e9bba86/src/fastmcp/server/server.py#L1508)
- [FastMCP 2.13.0 server](https://github.com/PrefectHQ/fastmcp/blob/716e50dae0b445fb7fd0251725fc827c045d5fdd/src/fastmcp/server/server.py#L2135)
- [FastMCP 3.1.0 transport mixin](https://github.com/PrefectHQ/fastmcp/blob/8bc31360e85b1192e78615f09fc525d57ff5c5f7/src/fastmcp/server/mixins/transport.py#L279)
- [MCP SDK 1.26.0 FastMCP server](https://github.com/modelcontextprotocol/python-sdk/blob/3d9d34552a9ab8988acf8d06e4a705bd799fc32b/src/mcp/server/fastmcp/server.py#L950)
- [MCP SDK 2.0.0 source tree](https://github.com/modelcontextprotocol/python-sdk/tree/6f69a3758ebf2ee55ce050f58b470ce11af71133/src/mcp/server)

## Assessment and smallest useful next evidence

The PR change does not newly create the `http_app` feature-detection branch; that branch and its fallback are already present in BASE. The new keyword call is compatible with the sampled Prefect FastMCP 2.10/2.13/3.1 implementations, but those are not the class imported by the target's below-v4 branch. The sampled MCP SDK implementations show a `streamable_http_app()` path without the new explicit keywords, while the package bounds and sampled SDK trees also leave import availability/version compatibility unresolved. This is an incomplete dependency/API-contract question, not evidence that PR466 newly breaks the supported range, and not a verified runtime outcome.

The smallest general evidence addition is an operator-curated, versioned contract record for the actually resolved `fastmcp` and `mcp` distributions: exact installed versions and artifact hashes, the imported class/module, and immutable upstream source/signature evidence for `http_app` or `streamable_http_app` plus the effective stateless/JSON settings path. Bind that record to the tested source revision and runtime environment, and mark it unknown when unavailable. Do not fetch arbitrary dependency documentation during review or execute target code to discover the API. A trusted lockfile/runtime inventory or explicit compatibility matrix can later constrain support; sampled tags alone cannot.
