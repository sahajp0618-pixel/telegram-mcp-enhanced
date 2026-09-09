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
