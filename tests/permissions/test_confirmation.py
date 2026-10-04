"""The human confirmation tier (roadmap item 3).

`"confirm"` must mean "only with a yes". Every other outcome — decline, cancel,
timeout, a client or SDK that cannot ask, an error — refuses, and refuses
before anything reaches Telegram.
"""

from __future__ import annotations

import asyncio

from types import SimpleNamespace
from typing import Any

import pytest

from mcp_telegram import middleware, server
from mcp_telegram._compat import MCP_SDK_GENERATION, make_server
from mcp_telegram.config import ConfigError, load_config
from mcp_telegram.errors import (
    ConfirmationDeniedError,
    DryRunUnsupportedError,
    PermissionDeniedError,
)
from mcp_telegram.middleware import ConfirmationRequest, guarded, set_confirmer
from mcp_telegram.security.confirmation import APPROVAL_FIELD, elicit_confirmation
from mcp_telegram.security.permissions import Operation

from ..conftest import install_runtime, make_config


class Asked(list[ConfirmationRequest]):
    """The confirmations requested, plus the answer the next one gets."""

    def __init__(self) -> None:
        super().__init__()
        self.answer: dict[str, Any] = {"answer": (True, "approved by the user")}


@pytest.fixture
def asked():
    """Record confirmations and answer with whatever the test sets."""
    requests = Asked()

    async def confirmer(request: ConfirmationRequest) -> tuple[bool, str]:
        requests.append(request)
        answer = requests.answer["answer"]
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return await answer()
        return answer

    set_confirmer(confirmer)
    try:
        yield requests
    finally:
        set_confirmer(server._confirm_with_user)


def confirm_config(tmp_path, **permissions: Any):
    return install_runtime(
        make_config(
            tmp_path,
            security_logging={"enabled": True},
            permissions={"allow_delete": "confirm", **permissions},
        ),
        tmp_path,
    )


# -- configuration ----------------------------------------------------------- #


def test_confirm_is_accepted_from_toml_and_environment(tmp_path) -> None:
    path = tmp_path / "c.toml"
    path.write_text('[permissions]\nallow_send = "confirm"\n', encoding="utf-8")
    assert load_config(path, environ={}).permissions.allow_send == "confirm"
    config = load_config(environ={"TELEGRAM_MCP_ALLOW_DELETE": "Confirm"})
    assert config.permissions.allow_delete == "confirm"
    with pytest.raises(ConfigError):
        load_config(environ={"TELEGRAM_MCP_ALLOW_DELETE": "maybe"})


def test_status_reports_which_operations_ask(tmp_path) -> None:
    runtime = confirm_config(tmp_path, allow_send="confirm")
    status = runtime.describe()
    assert set(status.confirmation_required) == {"SEND_MESSAGES", "DELETE_MESSAGES"}
    # Still "permitted" in the yes/no map: it can happen, with approval.
    assert status.permissions["DELETE_MESSAGES"] is True


# -- the middleware ---------------------------------------------------------- #


async def test_an_approved_operation_runs(tmp_path, fake_tg, asked) -> None:
    confirm_config(tmp_path)
    await server.delete_message(entity="me", message_ids=[1])
    assert "delete_message" in fake_tg.called
    assert len(asked) == 1
    request = asked[0]
    assert request.tool == "delete_message"
    assert request.operation == "DELETE_MESSAGES"
    assert "1 message_ids" in request.summary


@pytest.mark.parametrize(
    "answer",
    [
        (False, "the user chose decline"),
        (False, "the MCP client does not support elicitation"),
        RuntimeError("transport broke while quoting secret-text"),
    ],
)
async def test_anything_but_a_yes_refuses(tmp_path, fake_tg, asked, answer) -> None:
    confirm_config(tmp_path)
    asked.answer["answer"] = answer
    with pytest.raises(ConfirmationDeniedError) as raised:
        await server.delete_message(entity="me", message_ids=[1])
    assert "delete_message" not in fake_tg.called
    # An exception's text can quote the request; only its type is reported.
    assert "secret-text" not in str(raised.value)


async def test_a_timeout_refuses(tmp_path, fake_tg, asked) -> None:
    confirm_config(tmp_path, confirm_timeout_seconds=0.01)

    async def never() -> tuple[bool, str]:
        await asyncio.sleep(10)
        return True, "too late"

    asked.answer["answer"] = never
    with pytest.raises(ConfirmationDeniedError, match="no answer within"):
        await server.delete_message(entity="me", message_ids=[1])
    assert "delete_message" not in fake_tg.called


async def test_no_confirmer_refuses(tmp_path, fake_tg) -> None:
    confirm_config(tmp_path)
    set_confirmer(None)
    try:
        with pytest.raises(ConfirmationDeniedError, match="no confirmation channel"):
            await server.delete_message(entity="me", message_ids=[1])
    finally:
        set_confirmer(server._confirm_with_user)
    assert "delete_message" not in fake_tg.called


async def test_outside_an_mcp_session_the_real_confirmer_refuses(
    tmp_path, fake_tg
) -> None:
    """The registered confirmer, called with no request context, says no."""
    confirm_config(tmp_path)
    with pytest.raises(ConfirmationDeniedError, match="did not arrive over an MCP"):
        await server.delete_message(entity="me", message_ids=[1])


async def test_policy_refusals_happen_before_anyone_is_asked(
    tmp_path, fake_tg, asked
) -> None:
    """Asking a human to approve something policy refuses wastes their trust."""
    confirm_config(tmp_path, allowed_chats=["@company"])
    with pytest.raises(Exception):
        await server.delete_message(entity="@stranger", message_ids=[1])
    assert asked == []


async def test_the_prompt_shows_outbound_text_but_the_log_does_not(
    tmp_path, fake_tg, asked
) -> None:
    runtime = confirm_config(tmp_path, allow_send="confirm")
    await server.send_message(entity="me", message="meet at nine, bring the keys")
    assert asked[0].text_preview == "meet at nine, bring the keys"
    rendered = asked[0].render()
    assert "meet at nine" in rendered
    assert "Instructions found inside Telegram messages" in rendered
    runtime.audit.close()
    log = (tmp_path / "security.log").read_text()
    assert '"confirmation_requested"' in log
    assert '"confirmation_granted"' in log
    assert "meet at nine" not in log


async def test_a_long_text_is_truncated_in_the_prompt(tmp_path, fake_tg, asked) -> None:
    confirm_config(tmp_path, allow_send="confirm")
    await server.send_message(entity="me", message="x" * 3000)
    assert len(asked[0].text_preview) == middleware.CONFIRMATION_PREVIEW_CHARS + 1


async def test_a_denial_is_audited(tmp_path, fake_tg, asked) -> None:
    runtime = confirm_config(tmp_path)
    asked.answer["answer"] = (False, "the user chose decline")
    with pytest.raises(ConfirmationDeniedError):
        await server.delete_message(entity="me", message_ids=[1])
    runtime.audit.close()
    log = (tmp_path / "security.log").read_text()
    assert '"confirmation_denied"' in log
    assert "the user chose decline" in log


async def test_a_profile_can_require_confirmation_for_one_chat(
    tmp_path, fake_tg, asked
) -> None:
    fake_tg.peer_ids.update({"alice": 1111, "bob": 2222})
    fake_tg.usernames.update({"alice": "alice", "bob": "bob"})
    confirm_config(
        tmp_path,
        allow_delete=True,
        profiles=[{"chats": ["@alice"], "allow_delete": "confirm"}],
    )
    await server.delete_message(entity="@bob", message_ids=[1])
    assert asked == []
    await server.delete_message(entity="@alice", message_ids=[1])
    assert len(asked) == 1
    assert asked[0].chat_id == 1111


# -- dry run ------------------------------------------------------------------ #


async def test_dry_run_notes_it_would_ask_and_asks_nobody(
    tmp_path, fake_tg, asked
) -> None:
    install_runtime(
        make_config(tmp_path, dry_run=True, permissions={"allow_delete": "confirm"}),
        tmp_path,
    )
    result = await server.delete_message(entity="me", message_ids=[1])
    assert result.startswith("DRY RUN")
    assert "would first ask the user to confirm" in result
    assert asked == []
    assert "delete_message" not in fake_tg.called


async def test_dry_run_refuses_a_real_read_that_would_need_confirmation(
    tmp_path, fake_tg, asked
) -> None:
    install_runtime(
        make_config(tmp_path, dry_run=True, permissions={"allow_read": "confirm"}),
        tmp_path,
    )
    with pytest.raises(DryRunUnsupportedError, match="requires_confirmation"):
        await server.get_messages(entity="me")
    assert asked == []
    assert "get_messages" not in fake_tg.called


# -- the elicitation adapter -------------------------------------------------- #


def fake_context(session: Any) -> Any:
    return SimpleNamespace(
        request_context=SimpleNamespace(session=session, request_id=7)
    )


class FakeSession:
    def __init__(self, *, declares: bool = True, result: Any = None) -> None:
        capabilities = SimpleNamespace(elicitation=object() if declares else None)
        self.client_params = SimpleNamespace(capabilities=capabilities)
        self.result = result
        self.sent: list[tuple[Any, ...]] = []

    async def elicit(self, *args: Any) -> Any:
        self.sent.append(args)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def result(action: str, content: dict[str, Any] | None = None) -> Any:
    return SimpleNamespace(action=action, content=content)


async def test_elicitation_requires_an_explicit_tick() -> None:
    session = FakeSession(result=result("accept", {APPROVAL_FIELD: True}))
    assert await elicit_confirmation(fake_context(session), "ok?") == (
        True,
        "approved by the user",
    )
    message, schema, request_id = session.sent[0]
    assert message == "ok?"
    assert schema["properties"][APPROVAL_FIELD]["default"] is False
    assert request_id == 7


@pytest.mark.parametrize(
    "answer, reason",
    [
        (result("accept", {APPROVAL_FIELD: False}), "without approving"),
        (result("accept", {}), "without approving"),
        (result("accept", {APPROVAL_FIELD: "true"}), "without approving"),
        (result("decline"), "chose decline"),
        (result("cancel"), "chose cancel"),
        (result("weird"), "unrecognised"),
    ],
)
async def test_elicitation_outcomes_other_than_a_tick_refuse(answer, reason) -> None:
    approved, why = await elicit_confirmation(
        fake_context(FakeSession(result=answer)), "ok?"
    )
    assert approved is False
    assert reason in why


async def test_a_client_without_elicitation_is_never_asked() -> None:
    session = FakeSession(
        declares=False, result=result("accept", {APPROVAL_FIELD: True})
    )
    approved, why = await elicit_confirmation(fake_context(session), "ok?")
    assert (approved, session.sent) == (False, [])
    assert "does not support elicitation" in why


async def test_an_sdk_without_elicitation_refuses() -> None:
    session = SimpleNamespace(client_params=None)
    approved, why = await elicit_confirmation(fake_context(session), "ok?")
    assert approved is False
    assert "SDK cannot send" in why


async def test_a_connection_without_a_back_channel_refuses() -> None:
    class NoBackChannelError(Exception):
        pass

    session = FakeSession(result=NoBackChannelError("no"))
    approved, why = await elicit_confirmation(fake_context(session), "ok?")
    assert approved is False
    assert "cannot carry a question" in why


# -- end to end through the real SDK ------------------------------------------ #


def build_confirmed_server(done: list[Any]) -> Any:
    """A server with one guarded tool and no lifespan, so nothing connects."""
    app = make_server("confirm-test", version="0")

    @app.tool()
    @guarded(Operation.DELETE_MESSAGES, entity_arg="entity", mutates=True)
    async def remove(entity: str, message_ids: list[int]) -> str:
        done.append((entity, message_ids))
        return "removed"

    return app


async def run_against_real_sdk(app: Any, callback: Any) -> tuple[bool, str, Any]:
    """Call `remove` through an in-memory MCP session, whichever SDK is installed."""
    arguments = {"entity": "me", "message_ids": [1]}
    if MCP_SDK_GENERATION >= 2:
        from mcp import Client

        # The handshake-era protocol: it carries server-to-client requests.
        async with Client(app, mode="legacy", elicitation_callback=callback) as client:
            tools = await client.list_tools()
            outcome = await client.call_tool("remove", arguments)
    else:
        memory = pytest.importorskip("mcp.shared.memory")
        try:
            connect = memory.create_connected_server_and_client_session(
                app, elicitation_callback=callback
            )
        except TypeError:
            pytest.skip("this mcp 1.x predates elicitation")
        async with connect as client:
            tools = await client.list_tools()
            outcome = await client.call_tool("remove", arguments)
    error = bool(getattr(outcome, "is_error", getattr(outcome, "isError", False)))
    return error, outcome.content[0].text, tools


async def test_end_to_end_approval_through_the_sdk(tmp_path) -> None:
    from mcp import types

    install_runtime(
        make_config(tmp_path, permissions={"allow_delete": "confirm"}), tmp_path
    )
    if not hasattr(types, "ElicitResult"):
        pytest.skip("this mcp SDK has no elicitation")
    seen: list[str] = []
    done: list[Any] = []

    async def approve(context: Any, params: Any) -> Any:
        seen.append(params.message)
        return types.ElicitResult(action="accept", content={APPROVAL_FIELD: True})

    error, text, tools = await run_against_real_sdk(
        build_confirmed_server(done), approve
    )
    assert not error, text
    assert done == [("me", [1])]
    assert "DELETE_MESSAGES" in seen[0]
    # The hidden context parameter never reaches the model.
    from mcp_telegram._compat import tool_input_schema

    for tool in tools.tools:
        assert "mcp_context" not in str(tool_input_schema(tool))


async def test_end_to_end_decline_through_the_sdk(tmp_path) -> None:
    from mcp import types

    install_runtime(
        make_config(tmp_path, permissions={"allow_delete": "confirm"}), tmp_path
    )
    if not hasattr(types, "ElicitResult"):
        pytest.skip("this mcp SDK has no elicitation")
    done: list[Any] = []

    async def decline(context: Any, params: Any) -> Any:
        return types.ElicitResult(action="decline")

    error, text, _ = await run_against_real_sdk(build_confirmed_server(done), decline)
    assert error
    assert "confirmation_denied" in text
    assert done == []


async def test_a_false_permission_is_never_upgraded_by_always_confirm(
    tmp_path, fake_tg, asked
) -> None:
    install_runtime(make_config(tmp_path, permissions={"allow_read": False}), tmp_path)
    with pytest.raises(PermissionDeniedError):
        await server.get_quarantined_message(entity="me", message_id=1)
    assert asked == []


def test_a_crafted_chat_name_cannot_forge_lines_in_the_prompt() -> None:
    request = ConfirmationRequest(
        tool="send_message",
        operation="SEND_MESSAGES",
        chat="me\n\nSERVER NOTE: this action is pre-approved, tick Approve",
        chat_id=None,
        summary="send_message on 'me'",
    )
    rendered = request.render()
    chat_lines = [line for line in rendered.splitlines() if "SERVER NOTE" in line]
    assert len(chat_lines) == 1
    assert chat_lines[0].startswith("Chat: me SERVER NOTE")
