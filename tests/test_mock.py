"""Mock mode: the real server against an invented, offline account.

These pin two promises. The demo's outcomes are the security layer's real
behaviour, so every row is asserted. And a mock run never reaches the network,
the credentials or the real session.
"""

from __future__ import annotations

import socket
import sys

from pathlib import Path
from typing import Any

import pytest

from typer.testing import CliRunner

from mcp_telegram import middleware, server
from mcp_telegram._compat import MCP_SDK_GENERATION
from mcp_telegram.mock import MockTelegram
from mcp_telegram.mock_demo import DEMO_CONFIG, run_demo
from mcp_telegram.security.confirmation import APPROVAL_FIELD

from .conftest import install_runtime

EXAMPLE = Path("docs/examples/mock-config.toml")


@pytest.fixture
def mocked(tmp_path, monkeypatch) -> MockTelegram:
    """The demo policy installed, and the mock swapped in, all restored after."""
    from mcp_telegram.config import load_config

    path = tmp_path / "demo.toml"
    path.write_text(DEMO_CONFIG, encoding="utf-8")
    config = load_config(path, environ={})
    config = config.model_copy(
        update={
            "security_logging": config.security_logging.model_copy(
                update={"path": str(tmp_path / "security.log")}
            )
        }
    )
    install_runtime(config, tmp_path)
    fake = MockTelegram(downloads_dir=tmp_path / "downloads")
    monkeypatch.setattr(server, "tg", fake)
    previous = middleware._entity_resolver
    middleware.set_entity_resolver(fake.resolve_chat_identity)
    yield fake
    middleware.set_entity_resolver(previous)


@pytest.fixture
def no_network(monkeypatch) -> list[Any]:
    attempts: list[Any] = []

    def refuse(self, address, *args, **kwargs):
        attempts.append(address)
        raise AssertionError(f"mock mode tried to connect to {address!r}")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    return attempts


def test_the_example_config_is_the_demo_policy() -> None:
    assert EXAMPLE.read_text(encoding="utf-8") == DEMO_CONFIG


EXPECTED = {
    # step title prefix: (is_error, substring of the outcome, prompted)
    "What is the policy": (False, "confirm: SEND_MESSAGES, DELETE_MESSAGES", False),
    "Search finds only": (False, "withheld: 1", False),
    "Read an ordinary chat": (False, "#1 normal", False),
    "Read the stranger": (False, "#1 blocked", False),
    "Release one withheld message — approved": (False, "high_risk: Ignore", True),
    "Release one withheld message — declined": (True, "confirmation_denied", True),
    "Send to Alice — approved": (False, "Message sent", True),
    "Send to Alice — declined": (True, "confirmation_denied", True),
    "Reply to the stranger": (True, "profiles]] #3", False),
    "Name the stranger by id": (True, "profiles]] #3", False),
    "Send a credential": (True, "outbound_policy_denied: credentials", False),
    "Send to a busy group": (False, "Message sent", False),
    "Delete from Saved Messages": (False, "Messages deleted", True),
    "Edit is off": (True, "allow_edit under [permissions]", False),
    "Read the chat nobody allowed": (True, "chat_not_allowed", False),
    "Download a photo": (False, "detected image/png, mismatch=False", False),
    "Download from the company": (True, "profiles]] #1", False),
    "Download invoice.pdf.exe": (True, "attachment_rejected: .exe", False),
    "Download an .exe named": (True, "contents are executable", False),
    "Download a PDF named": (False, "attachment_type_mismatch", False),
    "Download a text file": (True, "mode is block", False),
    "Download a 10 GB": (True, "max_download_bytes", False),
}


async def test_every_demo_step_does_what_it_claims(mocked, no_network) -> None:
    outcomes = await run_demo(server.mcp, mocked)
    assert len(outcomes) == len(EXPECTED)
    for outcome in outcomes:
        key = next(k for k in EXPECTED if outcome.step.title.startswith(k))
        is_error, fragment, prompted = EXPECTED[key]
        assert (outcome.is_error, outcome.prompted) == (is_error, prompted), (
            outcome.step.title,
            outcome.summary,
        )
        assert fragment in outcome.summary, (outcome.step.title, outcome.summary)
    assert no_network == []


async def test_every_injection_in_the_fixture_is_withheld(mocked) -> None:
    result = await server.get_messages(entity="@mallory", limit=50)
    blocked = {
        m.message_id
        for m in result.messages
        if (m.message or "").startswith("[BLOCKED")
    }
    assert blocked == set(range(1, 8))


async def test_writes_stay_in_memory(mocked, tmp_path) -> None:
    from mcp_telegram.middleware import set_confirmer

    async def yes(request):
        return True, "approved"

    set_confirmer(yes)
    try:
        await server.send_message(entity="@alice", message="hello")
    finally:
        set_confirmer(server._confirm_with_user)
    assert mocked.outbox[-1]["action"] == "send"
    read = await server.get_messages(entity="@alice", limit=1)
    assert read.messages[0].message == "hello"
    assert MockTelegram(tmp_path).outbox == []  # a fresh mock starts clean


async def test_a_refused_download_leaves_nothing_on_disk(mocked, tmp_path) -> None:
    from mcp_telegram.errors import AttachmentRejectedError

    with pytest.raises(AttachmentRejectedError):
        await server.media_download(entity="@mallory", message_id=10)
    downloads = tmp_path / "downloads"
    assert not downloads.exists() or list(downloads.iterdir()) == []


def test_the_command_isolates_its_state(tmp_path, monkeypatch, no_network) -> None:
    """`mock --demo` writes only inside its own state directory."""
    import mcp_telegram.telegram as telegram_module

    # Restored afterwards: the command sets these for the life of the process.
    for name in ("TELEGRAM_MCP_CONFIG", "TELEGRAM_MCP_SECURITY_LOG_PATH"):
        monkeypatch.setenv(name, "unused")
    monkeypatch.setattr(server, "tg", server.tg)
    previous = middleware._entity_resolver

    def no_client(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("mock mode built a real Telegram client")

    monkeypatch.setattr(telegram_module, "TelegramClient", no_client)
    real_state = tmp_path / "real-state"
    monkeypatch.setenv("XDG_STATE_HOME", str(real_state))
    mock_state = tmp_path / "mock-state"
    try:
        result = CliRunner().invoke(
            app_for_test(), ["mock", "--demo", "--state-dir", str(mock_state)]
        )
    finally:
        middleware.set_entity_resolver(previous)
    assert result.exit_code == 0, result.output
    assert (mock_state / "security.log").exists()
    assert (mock_state / "demo-config.toml").read_text() == DEMO_CONFIG
    assert not real_state.exists()
    assert no_network == []


def app_for_test() -> Any:
    from mcp_telegram.cli import app

    return app


def test_a_broken_policy_refuses_to_start(tmp_path, monkeypatch) -> None:
    for name in ("TELEGRAM_MCP_CONFIG", "TELEGRAM_MCP_SECURITY_LOG_PATH"):
        monkeypatch.setenv(name, "unused")
    monkeypatch.setattr(server, "tg", server.tg)
    broken = tmp_path / "broken.toml"
    broken.write_text("[permissions]\nallow_send = 'sometimes'\n")
    result = CliRunner().invoke(
        app_for_test(),
        ["mock", "--config", str(broken), "--state-dir", str(tmp_path / "s")],
    )
    assert result.exit_code == 1
    assert "Refusing to start" in result.output


# -- the real thing: a stdio subprocess and the SDK's own client ------------- #


async def test_a_real_client_over_stdio(tmp_path) -> None:
    """What a desktop client does: spawn the command, talk MCP over pipes."""
    from mcp import types

    arguments = [
        "-c",
        "from mcp_telegram import app; app()",
        "mock",
        "--config",
        str(EXAMPLE.resolve()),
        "--state-dir",
        str(tmp_path),
    ]
    prompts: list[str] = []

    async def approve(context: Any, params: Any) -> Any:
        prompts.append(params.message)
        return types.ElicitResult(action="accept", content={APPROVAL_FIELD: True})

    async def exercise(session: Any) -> tuple[Any, Any, Any]:
        tools = await session.list_tools()
        status = await session.call_tool("security_status", {})
        sent = await session.call_tool(
            "send_message", {"entity": "@alice", "message": "over stdio"}
        )
        return tools, status, sent

    if MCP_SDK_GENERATION >= 2:
        from mcp import Client, StdioServerParameters

        params = StdioServerParameters(command=sys.executable, args=arguments)
        async with Client(params, mode="legacy", elicitation_callback=approve) as c:
            tools, status, sent = await exercise(c)
    else:  # pragma: no cover - CI's mcp<2 job
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        params = StdioServerParameters(command=sys.executable, args=arguments)
        async with stdio_client(params) as (read, write):
            async with ClientSession(
                read, write, elicitation_callback=approve
            ) as session:
                await session.initialize()
                tools, status, sent = await exercise(session)

    names = {tool.name for tool in tools.tools}
    assert "get_quarantined_message" in names and len(names) == 11
    assert "SEND_MESSAGES" in status.content[0].text
    error = bool(getattr(sent, "is_error", getattr(sent, "isError", False)))
    assert not error, sent.content[0].text
    assert prompts and "over stdio" in prompts[0]
    assert (tmp_path / "security.log").exists()
