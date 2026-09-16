"""Compatibility shim for the two generations of the MCP Python SDK.

Added by Telegram MCP Enhanced.

The upstream project depends on ``mcp[cli]>=1.6.0`` with no upper bound. In
``mcp`` 2.0 the server class was renamed (``FastMCP`` -> ``MCPServer``) and
``Tool.inputSchema`` became ``Tool.input_schema``, so a fresh install of the
unbounded requirement fails at import time. This module hides that difference
so the server runs on both SDK generations.

`ToolError` matters as much as the server class: mcp 2.x treats any other
exception as a server-side crash and withholds its text from the model, so a
structured refusal has to be raised as a `ToolError` to reach the agent at all.
"""

from typing import Any

try:  # mcp < 2
    from mcp.server.fastmcp import FastMCP as MCPServer  # type: ignore[attr-defined]
    from mcp.server.fastmcp.exceptions import ToolError  # type: ignore[attr-defined]

    _GENERATION = 1
except ModuleNotFoundError:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer  # type: ignore[no-redef]
    from mcp.server.mcpserver.exceptions import ToolError  # type: ignore[no-redef]

    _GENERATION = 2

MCP_SDK_GENERATION: int = _GENERATION
"""Which generation of the MCP SDK is installed: 1 or 2."""

__all__ = [
    "MCPServer",
    "MCP_SDK_GENERATION",
    "ToolError",
    "make_server",
    "server_handshake",
    "tool_input_schema",
    "tool_parameter_schema",
]


def make_server(name: str, *, version: str, **kwargs: Any) -> Any:
    """Build the server, reporting ``version`` on either SDK generation.

    The two generations take the version in different places, and getting this
    wrong is not a cosmetic failure: mcp 1.x's `FastMCP.__init__` accepts
    neither `version` nor `**kwargs`, so passing it raises `TypeError` at import
    time and breaks the server and every CLI command on a supported install.

    mcp 2.x takes it as a constructor argument. On 1.x the wrapped lowlevel
    `Server` holds it instead, defaulting to `None`, and FastMCP exposes that as
    `_mcp_server` -- a private attribute, so the assignment is guarded and a
    missing version degrades to an unset one rather than a crash.
    """
    if MCP_SDK_GENERATION >= 2:
        return MCPServer(name, version=version, **kwargs)
    server = MCPServer(name, **kwargs)
    low = getattr(server, "_mcp_server", None)
    if low is not None:
        try:
            low.version = version
        except AttributeError:  # pragma: no cover - a future 1.x rename
            pass
    return server


def server_handshake(server: Any) -> Any:
    """The initialization options a client receives from ``server``.

    Both generations wrap a lowlevel server that builds the handshake, and each
    keeps it under a different private name -- `_mcp_server` on 1.x,
    `_lowlevel_server` on 2.x. Reading the version back through this is what
    distinguishes "the constructor accepted the argument" from "clients can see
    it", which on 1.x were not the same thing.
    """
    for attribute in ("_mcp_server", "_lowlevel_server"):
        low = getattr(server, attribute, None)
        if low is not None and hasattr(low, "create_initialization_options"):
            return low.create_initialization_options()
    raise AttributeError(
        "no lowlevel server found; this SDK generation renamed it again"
    )


def tool_parameter_schema(tool: Any) -> dict[str, Any]:
    """Return a registered tool's JSON schema, wherever this SDK keeps it.

    `tool_input_schema` reads the wire-format field. The *internal* `Tool`
    objects a tool manager hands back are a different shape -- mcp 1.x and 2.x
    have both used `parameters` -- and reading only the wire field there returns
    `{}` for every tool, which silently turns any check over those schemas into
    one that inspects nothing.
    """
    for attribute in ("parameters", "input_schema", "inputSchema"):
        schema = getattr(tool, attribute, None)
        if isinstance(schema, dict) and schema:
            return schema
    return {}


def tool_input_schema(tool: Any) -> dict[str, Any]:
    """Return a tool's JSON input schema regardless of SDK generation."""
    schema = getattr(tool, "input_schema", None)
    if schema is None:
        schema = getattr(tool, "inputSchema", None)
    return schema or {}
