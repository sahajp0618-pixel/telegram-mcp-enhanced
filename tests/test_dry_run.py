"""Dry-run mode: every check runs, nothing on Telegram changes.

Added by Telegram MCP Enhanced.

The value of a dry run is entirely in what it still does. A mode that returned
early would test a code path the operator will never run in production, so these
tests pin the opposite: the policy chain is intact, refusals still refuse, and
only the final Telegram call is missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_telegram import server
from mcp_telegram.errors import (
    ChatAccessDeniedError,
    DryRunUnsupportedError,
    OutboundPolicyError,
    PermissionDeniedError,
)
from mcp_telegram.runtime import Runtime

from .conftest import install_runtime, make_config
from .fakes import FakeTelegram

API_HASH = "abcdef0123456789abcdef0123456789"


@pytest.fixture
def dry(tmp_path: Path, fake_tg: FakeTelegram) -> Runtime:
    config = make_config(tmp_path)
    config.dry_run = True
    return install_runtime(config, tmp_path)


@pytest.mark.parametrize(
    ("tool", "kwargs"),
    [
        ("send_message", {"entity": "@alice", "message": "hello"}),
        ("set_draft", {"entity": "@alice", "message": "hello"}),
        ("edit_message", {"entity": "@alice", "message_id": 7, "message": "hi"}),
        ("delete_message", {"entity": "@alice", "message_ids": [7]}),
    ],
)
async def test_writes_are_simulated_and_never_reach_telegram(
    tool: str, kwargs: dict, dry: Runtime, fake_tg: FakeTelegram
) -> None:
    dry.config.permissions.allow_edit = True
    dry.config.permissions.allow_delete = True
    result = await getattr(server, tool)(**kwargs)
    assert not fake_tg.calls, f"{tool} reached Telegram during a dry run"
    assert str(result).startswith("DRY RUN")
    assert "nothing actually happened" in str(result)


async def test_the_result_says_what_would_have_happened(
    dry: Runtime, fake_tg: FakeTelegram
) -> None:
    """A model that cannot tell what was skipped will report it as done."""
    result = await server.send_message(entity="@alice", message="x" * 41)
    assert "send_message" in result
    assert "41 characters" in result
    assert "@alice" in result


async def test_the_result_never_quotes_the_message(
    dry: Runtime, fake_tg: FakeTelegram
) -> None:
    """The description travels to the model and the log; keep content out of it."""
    secret = "meet me at the safehouse at midnight"
    result = await server.send_message(entity="@alice", message=secret)
    assert secret not in result
    assert not fake_tg.calls


async def test_a_dry_run_is_written_to_the_security_log(
    dry: Runtime, fake_tg: FakeTelegram
) -> None:
    records = []
    dry.audit.record = lambda event, **fields: records.append((event, fields))  # type: ignore[method-assign]
    await server.send_message(entity="@alice", message="hello")
    assert [event for event, _ in records] == ["dry_run_write"]
    assert records[0][1]["tool"] == "send_message"


# --------------------------------------------------------------------------- #
# The policy chain must be intact. A dry run that skips checks tests nothing.
# --------------------------------------------------------------------------- #


async def test_a_denied_operation_is_still_denied(
    dry: Runtime, fake_tg: FakeTelegram
) -> None:
    dry.config.permissions.allow_send = False
    with pytest.raises(PermissionDeniedError):
        await server.send_message(entity="@alice", message="hello")
    assert not fake_tg.calls


async def test_a_denied_chat_is_still_denied(
    tmp_path: Path, fake_tg: FakeTelegram
) -> None:
    # Built with the rule in place: the enforcer compiles chat rules once, so
    # assigning to denied_chats afterwards would test nothing.
    config = make_config(tmp_path)
    config.dry_run = True
    config.permissions.denied_chats = ["@alice"]
    install_runtime(config, tmp_path)
    with pytest.raises(ChatAccessDeniedError):
        await server.send_message(entity="@alice", message="hello")
    assert not fake_tg.calls


async def test_the_outbound_policy_still_refuses(
    dry: Runtime, fake_tg: FakeTelegram
) -> None:
    """Otherwise a dry run would be the way to find out what gets through."""
    with pytest.raises(OutboundPolicyError):
        await server.send_message(entity="@alice", message=f"key: {API_HASH}")
    assert not fake_tg.calls


async def test_rate_limit_tokens_are_still_spent(
    dry: Runtime, fake_tg: FakeTelegram
) -> None:
    """A dry run is how you would tune rate limits, so it must consume them."""
    before = dry.scheduler.stats()
    await server.send_message(entity="@alice", message="hello")
    assert dry.scheduler.stats() != before


# --------------------------------------------------------------------------- #
# Reads and downloads
# --------------------------------------------------------------------------- #


async def test_reads_are_not_simulated(dry: Runtime, fake_tg: FakeTelegram) -> None:
    """An agent exercised against nothing teaches nothing about the agent."""
    await server.get_messages(entity="@alice")
    assert [call[0] for call in fake_tg.calls] == ["get_messages"]


async def test_a_read_that_acknowledges_messages_is_refused(
    dry: Runtime, fake_tg: FakeTelegram
) -> None:
    """`mark_as_read` acknowledges on Telegram while being charged as a read.

    Classifying by rate-limit class alone would let this through: the class says
    how expensive an operation is, not whether it changes anything.
    """
    with pytest.raises(DryRunUnsupportedError) as caught:
        await server.get_messages(entity="@alice", mark_as_read=True)
    assert not fake_tg.calls
    assert caught.value.payload["reason"] == "mark_as_read changes state on Telegram"
    assert "mark_as_read=false" in caught.value.payload["hint"]


async def test_the_same_read_is_allowed_without_the_flag(
    dry: Runtime, fake_tg: FakeTelegram
) -> None:
    """Only the acknowledgement is refused, not the read it was attached to."""
    await server.get_messages(entity="@alice", mark_as_read=False)
    assert [call[0] for call in fake_tg.calls] == ["get_messages"]


async def test_reading_a_draft_is_not_simulated(
    dry: Runtime, fake_tg: FakeTelegram
) -> None:
    """`get_draft` is charged as a write because it shares the permission.

    Simulating it would answer "nothing was sent" to a question about what the
    draft currently says — the rate-limiting class is a cost model, not a
    statement about mutation.
    """
    result = await server.get_draft(entity="@alice")
    assert "DRY RUN" not in str(result)
    assert [call[0] for call in fake_tg.calls] == ["get_draft"]


def test_exactly_these_tools_are_simulated() -> None:
    """Pin the set, so adding a tool forces a decision instead of inheriting one.

    Both directions have bitten: a read charged as a write was simulated, and a
    write charged as a read was not.
    """
    from mcp_telegram.security.permissions import OPERATION_CLASS, OperationClass

    simulated = set()
    for name in dir(server):
        tool = getattr(server, name)
        operation = getattr(tool, "_guarded_operation", None)
        if operation is None:
            continue
        declared = getattr(tool, "_guarded_mutates", None)
        if declared is None:
            declared = OPERATION_CLASS[operation] is OperationClass.WRITE
        if declared:
            simulated.add(name)
    assert simulated == {
        "send_message",
        "edit_message",
        "delete_message",
        "set_draft",
    }


def test_every_mutating_flag_on_a_non_write_tool_is_declared() -> None:
    """The next tool with a state-changing option must not silently escape.

    A boolean parameter on a read-classified tool is the shape of this bug, so
    the check is on that shape rather than on the one name known today.
    """
    import inspect

    from mcp_telegram.security.permissions import OPERATION_CLASS, OperationClass

    known_safe = {"unread", "global_search"}  # filters, not state changes
    undeclared: list[str] = []
    for name in dir(server):
        tool = getattr(server, name)
        wrapped = getattr(tool, "__wrapped__", None)
        operation = getattr(tool, "_guarded_operation", None)
        if wrapped is None or operation is None:
            continue
        if OPERATION_CLASS[operation] is OperationClass.WRITE:
            continue
        declared = set(getattr(tool, "_guarded_mutating_flags", ()))
        for parameter, value in inspect.signature(wrapped).parameters.items():
            if value.annotation is bool and parameter not in declared | known_safe:
                undeclared.append(f"{name}.{parameter}")
    assert not undeclared, (
        "boolean options on non-write tools that are neither declared as "
        f"mutating_flags nor known to be pure filters: {undeclared}"
    )


async def test_download_is_refused_rather_than_faked(
    dry: Runtime, fake_tg: FakeTelegram
) -> None:
    """Silently writing files during a dry run is the surprise to avoid."""
    with pytest.raises(DryRunUnsupportedError) as caught:
        await server.media_download(entity="@alice", message_id=7)
    assert not fake_tg.calls
    assert caught.value.payload["operation"] == "DOWNLOAD_MEDIA"
    assert "dry-run mode" in str(caught.value)


# --------------------------------------------------------------------------- #
# Off by default
# --------------------------------------------------------------------------- #


async def test_writes_are_real_when_dry_run_is_off(
    runtime: Runtime, fake_tg: FakeTelegram
) -> None:
    assert runtime.config.dry_run is False
    result = await server.send_message(entity="@alice", message="hello")
    assert [call[0] for call in fake_tg.calls] == ["send_message"]
    assert "DRY RUN" not in result


async def test_security_status_reports_dry_run(
    dry: Runtime, fake_tg: FakeTelegram
) -> None:
    """The model must be able to warn before it reports having sent something."""
    assert (await server.security_status()).dry_run is True


def test_startup_says_loudly_that_writes_are_simulated(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Left on by accident this looks like a server whose messages never arrive."""
    from mcp_telegram.runtime import build_runtime, log_startup

    config = make_config(tmp_path)
    config.dry_run = True
    with caplog.at_level("WARNING"):
        log_startup(build_runtime(config, state_directory=tmp_path))
    warnings = [r.message for r in caplog.records if r.levelname == "WARNING"]
    assert any("DRY RUN MODE" in message for message in warnings)


def test_dry_run_loads_from_toml_and_env(tmp_path: Path) -> None:
    from mcp_telegram.config import load_config

    path = tmp_path / "c.toml"
    path.write_text("dry_run = true\n")
    assert load_config(path, environ={}).dry_run is True

    path.write_text("dry_run = false\n")
    assert load_config(path, environ={}).dry_run is False
    overridden = load_config(path, environ={"TELEGRAM_MCP_DRY_RUN": "1"})
    assert overridden.dry_run is True
