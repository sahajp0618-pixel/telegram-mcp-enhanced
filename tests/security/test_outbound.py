"""Outbound refusals must stop Telegram calls, not just annotate their results."""

from __future__ import annotations

from pathlib import Path
from typing import Any, get_args

import pytest

from mcp_telegram import middleware, server
from mcp_telegram._compat import ToolError
from mcp_telegram.config import ConfigError, OutboundSettings, load_config
from mcp_telegram.errors import (
    OutboundPolicyError,
    OutboundRefusalReason,
    _OUTBOUND_HINTS,
)
from mcp_telegram.middleware import guarded
from mcp_telegram.runtime import Runtime
from mcp_telegram.security.audit import CredentialScrubber
from mcp_telegram.security.outbound import check_outbound
from mcp_telegram.security.permissions import Operation

from ..conftest import install_runtime, make_config
from ..fakes import FakeTelegram

API_HASH = "abcdef0123456789abcdef0123456789"
SESSION = "1" + "Ab_cD-ef=" * 39


@pytest.mark.parametrize("tool", ["send_message", "set_draft"])
@pytest.mark.parametrize("secret", [API_HASH, SESSION], ids=["api_hash", "session"])
async def test_credentials_refused_without_echo(
    tool: str, secret: str, runtime: Runtime, fake_tg: FakeTelegram
) -> None:
    with pytest.raises(OutboundPolicyError) as caught:
        await getattr(server, tool)(entity="@alice", message=f"secret: {secret}")
    assert not fake_tg.calls
    assert secret not in str(caught.value)
    assert caught.value.payload["reason"] == "credentials"
    assert caught.value.payload["retryable"] is False
    assert "server's outbound content policy" in str(caught.value)
    assert "not a Telegram failure" in str(caught.value)
    assert isinstance(caught.value, ToolError)


@pytest.mark.parametrize("reason", get_args(OutboundRefusalReason))
def test_every_refusal_reason_carries_a_distinct_hint(
    reason: OutboundRefusalReason,
) -> None:
    """Every reason shares one sentence of prose, so the code alone must not carry it.

    Without a hint, "you nearly sent your API hash" and "that was a lot of
    quoted text" reach the model as identical text plus an opaque token, and
    the user is told only that the server refused something.
    """
    error = OutboundPolicyError(reason=reason)
    hint = error.payload["hint"]
    assert hint == _OUTBOUND_HINTS[reason]
    assert hint in str(error)
    assert sum(other == hint for other in _OUTBOUND_HINTS.values()) == 1


@pytest.mark.parametrize(
    ("reason", "setting"),
    [
        ("credentials", "block_credentials"),
        ("max_length", "max_message_chars"),
        ("bulk_quotes", "block_bulk_quotes"),
    ],
)
def test_recoverable_refusals_name_the_setting_that_relaxes_them(
    reason: OutboundRefusalReason, setting: str
) -> None:
    """These three fire on legitimate messages, so the way out must be discoverable.

    The heuristics cannot prove intent — a checksum reads like an API hash, a
    genuine forwarded thread reads like bulk relaying. An operator who hits a
    false positive should not have to read the source to find the switch.
    """
    hint = _OUTBOUND_HINTS[reason]
    assert setting in hint
    assert "[security.outbound]" in hint


@pytest.mark.parametrize("reason", get_args(OutboundRefusalReason))
def test_hints_are_fixed_strings_that_cannot_carry_rejected_text(
    reason: OutboundRefusalReason,
) -> None:
    """The hint is the one part of the payload written by hand; keep it inert."""
    assert OutboundPolicyError(reason=reason).payload["hint"] is _OUTBOUND_HINTS[reason]


@pytest.mark.parametrize("tool", ["send_message", "set_draft"])
@pytest.mark.parametrize("message", ["", "Hello 🌍\n**unchanged**", "> short quote"])
async def test_normal_message_passes_untouched(
    tool: str, message: str, runtime: Runtime, fake_tg: FakeTelegram
) -> None:
    await getattr(server, tool)("@alice", message)
    assert fake_tg.calls[-1][0] == tool
    assert fake_tg.calls[-1][1][1] == message


@pytest.mark.parametrize("tool", ["send_message", "set_draft"])
async def test_max_length_refuses_before_telegram(
    tool: str, runtime: Runtime, fake_tg: FakeTelegram
) -> None:
    runtime.config.outbound.max_message_chars = 10
    with pytest.raises(OutboundPolicyError, match="max_length"):
        await getattr(server, tool)(entity="@alice", message="x" * 11)
    assert not fake_tg.calls
    await getattr(server, tool)(entity="@alice", message="x" * 10)
    assert fake_tg.calls[-1][1][1] == "x" * 10


@pytest.mark.parametrize("tool", ["send_message", "set_draft"])
async def test_toml_can_disable_all_checks(
    tool: str, tmp_path: Path, fake_tg: FakeTelegram, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "outbound.toml"
    path.write_text(
        "[security.outbound]\nenabled = false\nmax_message_chars = 1\n"
        "[rate_limit]\nenabled = false\n[security.logging]\nenabled = false\n"
    )
    install_runtime(load_config(path, environ={}), tmp_path)

    def fail(*args: Any) -> None:
        raise AssertionError("Disabled policy must not invoke the checker")

    monkeypatch.setattr(middleware, "check_outbound", fail)
    text = "> " + API_HASH + SESSION + "quoted " * 1000
    await getattr(server, tool)(entity="@alice", message=text)
    assert fake_tg.calls[-1][1][1] == text


@pytest.mark.parametrize("tool", ["send_message", "set_draft"])
async def test_checker_failure_refuses_without_leaking(
    tool: str,
    runtime: Runtime,
    fake_tg: FakeTelegram,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def fail(*args: Any) -> None:
        raise RuntimeError(API_HASH)

    monkeypatch.setattr(middleware, "check_outbound", fail)
    with pytest.raises(OutboundPolicyError, match="check_failed") as caught:
        await getattr(server, tool)(entity="@alice", message="normal")
    assert not fake_tg.calls
    assert API_HASH not in str(caught.value)
    assert API_HASH not in caplog.text
    assert caught.value.__suppress_context__


async def test_scrubber_failure_is_also_fail_safe(
    runtime: Runtime, fake_tg: FakeTelegram, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(text: str) -> bool:
        raise ValueError(text)

    monkeypatch.setattr(runtime.audit.scrubber, "contains_credentials", fail)
    with pytest.raises(OutboundPolicyError, match="check_failed"):
        await server.send_message(entity="@alice", message=API_HASH)
    assert not fake_tg.calls


@pytest.mark.parametrize("secret", ["unique-secret-value", "[redacted]"])
async def test_env_literals_share_scrubber_detection(
    secret: str, runtime: Runtime, fake_tg: FakeTelegram
) -> None:
    runtime.audit.scrubber = CredentialScrubber({"PRIVATE_TOKEN": secret})
    with pytest.raises(OutboundPolicyError, match="credentials"):
        await server.send_message(entity="@alice", message=secret)
    assert not fake_tg.calls


@pytest.mark.parametrize("prefix", ["> ", "Forwarded from Alice: "])
async def test_bulk_quotes_refused(
    prefix: str, runtime: Runtime, fake_tg: FakeTelegram
) -> None:
    with pytest.raises(OutboundPolicyError, match="bulk_quotes"):
        await server.send_message(
            entity="@alice", message=(prefix + "word " * 20 + "\n") * 25
        )
    assert not fake_tg.calls


def test_quote_threshold_ratio_and_individual_switches() -> None:
    scrubber = CredentialScrubber({})
    settings = OutboundSettings(
        max_message_chars=0, bulk_quote_min_chars=100, bulk_quote_ratio=0.9
    )
    text = ">" + "q" * 79 + "\n" + "prose" * 4
    check_outbound(text, settings, scrubber)  # 80% quoted is below 90%.
    settings.bulk_quote_ratio = 0.8
    with pytest.raises(OutboundPolicyError, match="bulk_quotes"):
        check_outbound(text, settings, scrubber)
    settings.bulk_quote_min_chars = len(text)
    check_outbound(text, settings, scrubber)  # Strictly above the length threshold.
    settings.bulk_quote_min_chars = 1
    settings.block_bulk_quotes = False
    check_outbound(text, settings, scrubber)
    settings.block_credentials = False
    check_outbound(API_HASH, settings, scrubber)


@pytest.mark.parametrize(
    "text", ["normal prose " * 250, "Forwarded from Alice:\n" + "normal prose " * 250]
)
def test_long_prose_and_lone_forward_header_are_not_bulk_quotes(text: str) -> None:
    check_outbound(text, OutboundSettings(), CredentialScrubber({}))


async def test_default_message_guard_cannot_be_forgotten(runtime: Runtime) -> None:
    @guarded(Operation.SEND_MESSAGES, entity_arg="entity", mutates=True)
    async def future_tool(entity: str, message: str) -> None:
        pytest.fail("Unchecked text reached tool body")

    with pytest.raises(OutboundPolicyError, match="credentials"):
        await future_tool("@alice", API_HASH)


async def test_declared_alternate_argument_is_checked(runtime: Runtime) -> None:
    @guarded(Operation.SEND_MESSAGES, outbound_text_arg="caption", mutates=True)
    async def future_tool(caption: str) -> None:
        pytest.fail("Unchecked caption reached tool body")

    with pytest.raises(OutboundPolicyError, match="credentials"):
        await future_tool(API_HASH)


async def test_refusal_precedes_chat_resolution(
    tmp_path: Path, fake_tg: FakeTelegram
) -> None:
    install_runtime(make_config(permissions={"allowed_chats": ["@alice"]}), tmp_path)
    with pytest.raises(OutboundPolicyError):
        await server.send_message(entity="@alice", message=API_HASH)
    assert not fake_tg.calls


async def test_edit_message_gets_automatic_protection(
    runtime: Runtime, fake_tg: FakeTelegram
) -> None:
    runtime.config.permissions.allow_edit = True
    with pytest.raises(OutboundPolicyError, match="credentials"):
        await server.edit_message(entity="@alice", message_id=1, message=API_HASH)
    assert not fake_tg.calls


async def test_structured_refusal_survives_mcp_sdk(
    runtime: Runtime, fake_tg: FakeTelegram
) -> None:
    try:
        result = await server.mcp.call_tool(
            "send_message", {"entity": "@alice", "message": API_HASH}
        )
    except ToolError as exc:
        # Direct SDK calls may raise; the transport turns this into an error
        # result. Its text must survive the SDK's deliberate-error wrapper.
        text = str(exc)
    else:
        if hasattr(result, "content"):
            assert result.is_error
            content = result.content
        elif isinstance(result, tuple):
            content = result[0]
        else:
            content = result
        text = " ".join(item.text for item in content)
    assert "outbound_policy_denied" in text
    assert '"retryable": false' in text
    assert API_HASH not in text
    assert not fake_tg.calls


@pytest.mark.parametrize(
    "setting",
    [
        "max_message_chars = -1",
        "bulk_quote_min_chars = 0",
        "bulk_quote_ratio = 0",
        "bulk_quote_ratio = 1.1",
        "bulk_quote_ratio = nan",
        "unknown = true",
    ],
)
def test_invalid_outbound_config_fails_closed(tmp_path: Path, setting: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text("[security.outbound]\n" + setting)
    with pytest.raises(ConfigError):
        load_config(path, environ={})


def test_every_outbound_setting_loads_and_is_documented(tmp_path: Path) -> None:
    values = {
        "enabled": False,
        "block_credentials": False,
        "max_message_chars": 1234,
        "block_bulk_quotes": False,
        "bulk_quote_min_chars": 500,
        "bulk_quote_ratio": 0.75,
    }
    path = tmp_path / "config.toml"
    path.write_text(
        "[security.outbound]\n"
        + "\n".join(f"{key} = {str(value).lower()}" for key, value in values.items())
    )
    assert load_config(path, environ={}).outbound.model_dump() == values
    section = (
        Path("docs/CONFIGURATION.md")
        .read_text()
        .split("## `[security.outbound]`", 1)[1]
        .split("\n## ", 1)[0]
    )
    for key in OutboundSettings.model_fields:
        assert f"`{key}`" in section
