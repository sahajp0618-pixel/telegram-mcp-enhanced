"""The SDK compatibility shim, on whichever generation is installed.

Added by Telegram MCP Enhanced.

The project supports both generations of the MCP Python SDK, and the ways they
differ are exactly the ways a change breaks one while passing on the other. CI
runs the whole suite against both; these tests exist so that when it does, the
failure names the shim instead of surfacing as a hundred unrelated errors.

An adversarial review caught the case that motivated this file: passing
``version=`` straight to the server class worked on 2.x and raised ``TypeError``
at *import* time on 1.x, breaking the server and every CLI command on a
supported install.
"""

from __future__ import annotations

from mcp_telegram._compat import (
    MCP_SDK_GENERATION,
    make_server,
    server_handshake,
    tool_parameter_schema,
)


def test_the_generation_is_one_the_shim_knows() -> None:
    assert MCP_SDK_GENERATION in (1, 2)


def test_a_server_can_be_built_with_a_version() -> None:
    """The regression that motivated this file.

    `FastMCP.__init__` on mcp 1.x accepts neither `version` nor `**kwargs`, so
    a constructor call carrying it raises `TypeError` before anything runs.
    """
    server = make_server("test-server", version="9.9.9")
    assert server is not None


def test_the_version_reaches_the_handshake() -> None:
    """Building without raising is not enough; clients must actually see it.

    The two generations hold the version in different places: 2.x on the server
    object, 1.x on the wrapped lowlevel server. Reading it back through the
    initialization options checks the value a client receives rather than the
    one we passed in.
    """
    options = server_handshake(make_server("test-server", version="9.9.9"))
    assert options.server_name == "test-server"
    assert options.server_version == "9.9.9", (
        f"the handshake reports {options.server_version!r}; the version is not "
        "reaching clients on SDK generation "
        f"{MCP_SDK_GENERATION}"
    )


def test_the_real_server_reports_its_version() -> None:
    """The shipped server, not a synthetic one."""
    from mcp_telegram.server import mcp

    options = server_handshake(mcp)
    assert options.server_name == "mcp-telegram"
    assert options.server_version
    assert options.server_version != "0.0.0+unknown", (
        "the installed distribution was not found, so the handshake reports a "
        "placeholder version"
    )


def test_the_schema_reader_handles_an_absent_schema() -> None:
    """A tool with no arguments is legitimate and must not raise."""
    assert tool_parameter_schema(object()) == {}


def test_registered_tools_expose_readable_schemas() -> None:
    """Guards that read tool schemas are worthless if the reader returns {}.

    This is the vacuity check for every other schema-based test: it fails when
    a new SDK generation moves the field, rather than letting those tests
    quietly start inspecting nothing.
    """
    from mcp_telegram.server import mcp

    tools = mcp._tool_manager.list_tools()  # type: ignore[attr-defined]
    assert tools, "no tools registered"
    with_schemas = [tool for tool in tools if tool_parameter_schema(tool)]
    assert len(with_schemas) >= 9, (
        f"only {len(with_schemas)} of {len(tools)} tools exposed a readable "
        "schema; tool_parameter_schema needs to learn where this SDK keeps it"
    )
