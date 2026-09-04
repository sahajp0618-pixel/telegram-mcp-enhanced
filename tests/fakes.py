"""Test doubles: a Telegram wrapper that never touches the network."""

from __future__ import annotations

import asyncio

from datetime import datetime, timezone
from typing import Any

from mcp_telegram.security.permissions import ResolvedChat
from mcp_telegram.types import (
    Dialog,
    DialogType,
    DownloadedMedia,
    Media,
    Message,
    Messages,
)

__all__ = ["FakeClock", "FakeTelegram", "make_dialog", "make_message"]


def make_message(
    message_id: int = 1,
    text: str | None = "hello",
    *,
    chat_id: int | None = -1001111111111,
    outgoing: bool = False,
    file_name: str | None = None,
) -> Message:
    media = (
        Media(media_id=99, mime_type="image/png", file_name=file_name, file_size=10)
        if file_name is not None
        else None
    )
    return Message(
        chat_id=chat_id,
        message_id=message_id,
        sender_id=4242,
        message=text,
        outgoing=outgoing,
        date=datetime(2026, 1, 1, tzinfo=timezone.utc),
        media=media,
    )


def make_dialog(
    dialog_id: int = -1001111111111,
    title: str = "Project chat",
    username: str | None = "projectchat",
) -> Dialog:
    return Dialog(
        id=dialog_id,
        title=title,
        username=username,
        type=DialogType.GROUP,
        unread_messages_count=0,
        can_send_message=True,
    )


class FakeClock:
    """Virtual time: sleeping advances the clock instead of blocking."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += max(0.0, seconds)
        await asyncio.sleep(0)

    @property
    def total_slept(self) -> float:
        return sum(self.slept)


class FakeTelegram:
    """Stands in for `mcp_telegram.telegram.Telegram` in tool-level tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.messages: list[Message] = [make_message()]
        self.dialogs: list[Dialog] = [make_dialog()]
        self.draft_text: str = ""
        self.peer_ids: dict[str, int] = {}
        self.usernames: dict[str, str] = {}
        """Maps an identifier or peer id to the username Telegram reports."""
        self.raise_on: dict[str, Exception] = {}
        self.is_connected = False

    # -- helpers ------------------------------------------------------------ #

    def _record(self, name: str, *args: Any, **kwargs: Any) -> None:
        self.calls.append((name, args, kwargs))
        error = self.raise_on.pop(name, None)
        if error is not None:
            raise error

    @property
    def called(self) -> list[str]:
        return [name for name, _, _ in self.calls]

    # -- the surface the MCP tools use -------------------------------------- #

    async def resolve_chat_identity(self, entity: str | int) -> ResolvedChat:
        self._record("resolve_chat_identity", entity)
        key = str(entity).lstrip("@").lower()
        if key in self.peer_ids:
            return ResolvedChat(
                peer_id=self.peer_ids[key], username=self.usernames.get(key)
            )
        if str(entity).lstrip("-").isdigit():
            peer_id = int(entity)
            return ResolvedChat(
                peer_id=peer_id, username=self.usernames.get(str(peer_id))
            )
        raise ValueError(f"Cannot find any entity corresponding to {entity!r}")

    async def send_message(
        self,
        entity: str | int,
        message: str = "",
        file_path: list[str] | None = None,
        reply_to: int | None = None,
    ) -> None:
        self._record(
            "send_message", entity, message, file_path=file_path, reply_to=reply_to
        )

    async def edit_message(
        self, entity: str | int, message_id: int, message: str
    ) -> None:
        self._record("edit_message", entity, message_id, message)

    async def delete_message(self, entity: str | int, message_ids: list[int]) -> None:
        self._record("delete_message", entity, message_ids)

    async def get_draft(self, entity: str | int) -> str:
        self._record("get_draft", entity)
        return self.draft_text

    async def set_draft(self, entity: str | int, message: str) -> None:
        self._record("set_draft", entity, message)
        self.draft_text = message

    async def get_messages(
        self, entity: str | int, *args: Any, **kwargs: Any
    ) -> Messages:
        self._record("get_messages", entity, *args, **kwargs)
        return Messages(
            messages=[message.model_copy(deep=True) for message in self.messages],
            dialog=self.dialogs[0].model_copy(deep=True) if self.dialogs else None,
        )

    async def download_media(
        self, entity: str | int, message_id: int, path: str | None = None
    ) -> DownloadedMedia:
        self._record("download_media", entity, message_id, path)
        return DownloadedMedia(
            path=f"{path or '/tmp'}/file.png",
            media=Media(
                media_id=7, mime_type="image/png", file_name="holiday.png", file_size=12
            ),
        )

    async def message_from_link(self, link: str) -> Message:
        self._record("message_from_link", link)
        return self.messages[0].model_copy(deep=True)

    async def search_dialogs(
        self, query: str, limit: int, global_search: bool = False
    ) -> list[Dialog]:
        self._record("search_dialogs", query, limit, global_search)
        return [dialog.model_copy(deep=True) for dialog in self.dialogs]
