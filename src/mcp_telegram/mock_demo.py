"""A scripted tour of the security layer against the mock backend.

Added by Telegram MCP Enhanced. `telegram-mcp-enhanced mock --demo` calls the
real MCP tools through the real MCP SDK, in-process, answering confirmation
prompts from a script, and prints what the server did at each step. No model
and no Telegram account are involved, so every outcome is deterministic.
"""

from __future__ import annotations

import json
import re

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_telegram._compat import MCP_SDK_GENERATION
from mcp_telegram.security.confirmation import APPROVAL_FIELD

__all__ = ["DEMO_CONFIG", "Outcome", "STEPS", "Step", "connect_in_memory", "run_demo"]

DEMO_CONFIG = """# Policy used by `telegram-mcp-enhanced mock --demo`.
# Also a starting point for trying the mock server from a real AI client:
#   telegram-mcp-enhanced mock --config docs/examples/mock-config.toml

[security.prompt_injection]
# Withhold high-risk messages, so get_quarantined_message has work to do.
mode = "block"

[permissions]
# Every mock chat except the book club, which is left out on purpose.
allowed_chats = ["me", "@alice", "@bob", "@examplecorp", "@mallory", "@busygroup"]
allow_read = true
allow_search = true
allow_send = "confirm"         # sends need your approval...
allow_edit = false
allow_delete = "confirm"       # ...and so do deletions
allow_drafts = true
allow_download = true
confirm_timeout_seconds = 120

[[permissions.profiles]]
chats = ["@examplecorp"]
allow_download = false         # nothing downloads from the company channel

[[permissions.profiles]]
chats = ["@busygroup"]
allow_send = true              # send freely here, without asking

[[permissions.profiles]]
chats = ["@mallory"]
allow_send = false             # never reply to the stranger

[rate_limit]
enabled = true
minimum_interval_ms = 200
max_flood_wait_seconds = 10
"""


@dataclass
class Step:
    title: str
    tool: str
    arguments: dict[str, Any]
    answer: bool | None = None
    """How to answer a confirmation, if one is asked: approve or decline."""
    expect: str = ""
    """What the step demonstrates, printed beside the outcome."""


STEPS: tuple[Step, ...] = (
    Step("What is the policy?", "security_status", {}, expect="policy only"),
    Step(
        "Search finds only allowed chats",
        "search_dialogs",
        {"query": "example"},
        expect="the unlisted book club is withheld",
    ),
    Step(
        "Read an ordinary chat",
        "get_messages",
        {"entity": "@alice", "limit": 5},
        expect="normal",
    ),
    Step(
        "Read the stranger's injections",
        "get_messages",
        {"entity": "@mallory", "limit": 13},
        expect="high-risk messages withheld in block mode",
    ),
    Step(
        "Release one withheld message — approved",
        "get_quarantined_message",
        {"entity": "@mallory", "message_id": 1},
        answer=True,
        expect="original text, still flagged",
    ),
    Step(
        "Release one withheld message — declined",
        "get_quarantined_message",
        {"entity": "@mallory", "message_id": 2},
        answer=False,
        expect="confirmation_denied",
    ),
    Step(
        "Send to Alice — approved",
        "send_message",
        {"entity": "@alice", "message": "Lunch at 1 works, see you there."},
        answer=True,
        expect="sent (kept in memory)",
    ),
    Step(
        "Send to Alice — declined",
        "send_message",
        {"entity": "@alice", "message": "Actually, never mind."},
        answer=False,
        expect="confirmation_denied",
    ),
    Step(
        "Reply to the stranger",
        "send_message",
        {"entity": "@mallory", "message": "who is this?"},
        expect="refused by @mallory's profile",
    ),
    Step(
        "Name the stranger by id instead",
        "send_message",
        {"entity": "3333", "message": "who is this?"},
        expect="same refusal: profiles match the resolved peer",
    ),
    Step(
        "Send a credential",
        "send_message",
        {
            "entity": "@busygroup",
            "message": "api hash 0123456789abcdef0123456789abcdef",
        },
        expect="outbound policy refuses",
    ),
    Step(
        "Send to a busy group",
        "send_message",
        {"entity": "@busygroup", "message": "hello group"},
        expect="mock flood wait, then retried",
    ),
    Step(
        "Delete from Saved Messages — approved",
        "delete_message",
        {"entity": "me", "message_ids": [1]},
        answer=True,
        expect="deleted",
    ),
    Step(
        "Edit is off",
        "edit_message",
        {"entity": "@alice", "message_id": 2, "message": "edited"},
        expect="permission_denied",
    ),
    Step(
        "Read the chat nobody allowed",
        "get_messages",
        {"entity": "@exampleclub"},
        expect="chat_not_allowed",
    ),
    Step(
        "Download a photo",
        "media_download",
        {"entity": "@alice", "message_id": 3},
        expect="ok, type verified",
    ),
    Step(
        "Download from the company channel",
        "media_download",
        {"entity": "@examplecorp", "message_id": 1},
        expect="refused by the channel's profile",
    ),
    Step(
        "Download invoice.pdf.exe",
        "media_download",
        {"entity": "@mallory", "message_id": 9},
        expect="refused before transfer",
    ),
    Step(
        "Download an .exe named cat.png",
        "media_download",
        {"entity": "@mallory", "message_id": 10},
        expect="refused by its bytes, file deleted",
    ),
    Step(
        "Download a PDF named photo.png",
        "media_download",
        {"entity": "@mallory", "message_id": 11},
        expect="allowed, flagged as a type mismatch",
    ),
    Step(
        "Download a text file carrying an injection",
        "media_download",
        {"entity": "@mallory", "message_id": 12},
        expect="deleted in block mode",
    ),
    Step(
        "Download a 10 GB 'movie'",
        "media_download",
        {"entity": "@mallory", "message_id": 13},
        expect="refused before transfer",
    ),
)


Callback = Callable[[Any, Any], Awaitable[Any]]


@asynccontextmanager
async def connect_in_memory(app: Any, callback: Callback) -> AsyncIterator[Any]:
    """An MCP client session connected in-process, on either SDK generation.

    The handshake-era protocol is chosen on 2.x because that is what carries
    server-to-client requests, which confirmation needs.
    """
    if MCP_SDK_GENERATION >= 2:
        from mcp import Client  # type: ignore[attr-defined]

        async with Client(app, mode="legacy", elicitation_callback=callback) as client:
            yield client
    else:  # pragma: no cover - exercised by CI's mcp<2 job
        from mcp.shared.memory import create_connected_server_and_client_session

        async with create_connected_server_and_client_session(
            app, elicitation_callback=callback
        ) as client:
            yield client


_PAYLOAD = re.compile(r'\{"status".*\}\s*$', re.DOTALL)


def summarise_result(result: Any) -> tuple[bool, str]:
    """``(is_error, one-line outcome)`` from a CallToolResult."""
    is_error = bool(getattr(result, "is_error", getattr(result, "isError", False)))
    text = "".join(getattr(item, "text", "") for item in result.content)
    if is_error:
        match = _PAYLOAD.search(text)
        if match:
            try:
                payload = json.loads(match.group(0))
                return True, f"{payload.get('status')}: {payload.get('reason')}"
            except json.JSONDecodeError:
                pass
        return True, text[:200]
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return False, text[:200]
    return False, _describe(data)


def _describe(data: Any) -> str:
    if not isinstance(data, dict):
        return str(data)[:200]
    if "messages" in data:
        parts = []
        for message in data["messages"]:
            security = message.get("security") or {}
            label = security.get("classification", "?")
            text = (message.get("message") or "")[:38].replace("\n", " ")
            parts.append(f"#{message.get('message_id')} {label}: {text}")
        return "\n".join(parts) or "no messages"
    if "dialogs" in data:
        names = [d.get("username") or d.get("title") for d in data["dialogs"]]
        return f"{', '.join(names)} (withheld: {data.get('withheld_count', 0)})"
    if "path" in data:
        inspection = data.get("inspection") or {}
        security = data.get("security") or {}
        return (
            f"saved; detected {inspection.get('detected_type')}, "
            f"mismatch={inspection.get('type_mismatch')}, "
            f"{security.get('classification')} {security.get('rules_triggered')}"
        )
    if "permissions" in data:
        granted = [k for k, v in data["permissions"].items() if v]
        return (
            f"permitted: {', '.join(granted)}; confirm: "
            f"{', '.join(data.get('confirmation_required') or []) or 'none'}; "
            f"profiles: {data.get('permission_profiles')}"
        )
    if "message" in data and "message_id" in data:
        security = data.get("security") or {}
        return f"{security.get('classification')}: {data.get('message')}"
    return json.dumps(data)[:200]


@dataclass
class Outcome:
    step: Step
    is_error: bool
    summary: str
    prompted: bool


async def run_demo(
    app: Any, mock: Any, console: Console | None = None
) -> list[Outcome]:
    """Run every step, print a table, and return what happened at each."""
    console = console or Console()
    pending: list[bool | None] = []
    asked: list[str] = []

    async def answer(context: Any, params: Any) -> Any:
        from mcp import types

        decision = pending.pop(0) if pending else None
        asked.append(params.message)
        if decision:
            return types.ElicitResult(action="accept", content={APPROVAL_FIELD: True})
        return types.ElicitResult(action="decline")

    table = Table(title="Mock demo", show_lines=True, expand=True)
    table.add_column("#", justify="right")
    table.add_column("Step", overflow="fold")
    table.add_column("Asked you?", no_wrap=True)
    table.add_column("Outcome", overflow="fold")

    outcomes: list[Outcome] = []
    async with connect_in_memory(app, answer) as client:
        for index, step in enumerate(STEPS, start=1):
            pending[:] = [step.answer]
            before = len(asked)
            result = await client.call_tool(step.tool, step.arguments)
            is_error, outcome = summarise_result(result)
            prompted = len(asked) > before
            outcomes.append(Outcome(step, is_error, outcome, prompted))
            asked_cell = (
                ("approved" if step.answer else "declined") if prompted else "—"
            )
            table.add_row(
                str(index),
                Text(f"{step.title}\n{step.tool}({_args(step.arguments)})\n")
                + Text(f"shows: {step.expect}", style="dim"),
                asked_cell,
                Text(outcome, style="red" if is_error else "green"),
            )
    console.print(table)
    if asked:
        # The send prompt, which shows the text being approved, if there was one.
        sample = next((prompt for prompt in asked if "\nText:\n" in prompt), asked[0])
        console.print(
            Panel(Text(sample), title="What a confirmation prompt says", expand=False)
        )
    if mock.outbox:
        console.print(
            Panel(
                Text("\n".join(json.dumps(item) for item in mock.outbox)),
                title="Writes the agent made (memory only, nothing was sent)",
                expand=False,
            )
        )
    return outcomes


def _args(arguments: dict[str, Any]) -> str:
    return ", ".join(f"{key}={value!r}" for key, value in arguments.items())
