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
    from mcp.server.fastmcp.exceptions import ToolError

    MCP_SDK_GENERATION = 1
except ModuleNotFoundError:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer  # type: ignore[no-redef]
    from mcp.server.mcpserver.exceptions import ToolError  # type: ignore[no-redef]

    MCP_SDK_GENERATION = 2

__all__ = ["MCPServer", "MCP_SDK_GENERATION", "ToolError", "tool_input_schema"]


def tool_input_schema(tool: Any) -> dict[str, Any]:
    """Return a tool's JSON input schema regardless of SDK generation."""
    schema = getattr(tool, "input_schema", None)
    if schema is None:
        schema = getattr(tool, "inputSchema", None)
    return schema or {}
