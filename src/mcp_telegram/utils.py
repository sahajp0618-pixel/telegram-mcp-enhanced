"""Utility functions for the MCP Telegram module."""

import re
import uuid

from pathlib import Path

from telethon.tl import patched  # type: ignore


def parse_entity(entity: str) -> int | str:
    """
    Parse a string entity identifier as an integer ID.

    If the string represents a valid integer (potentially negative), it's
    returned as an `int`. Otherwise, the original string (assumed to be
    a username or phone number) is returned.

    Args:
        entity (`str`): The entity (ID, username, phone number, or "me").

    Returns:
        `int | str`: The parsed integer ID or the original string identifier.
    """
    return int(entity) if entity.lstrip("-").isdigit() else entity


SAFE_SUFFIX = re.compile(r"^\.[A-Za-z0-9]{1,10}$")


def get_unique_filename(message: patched.Message) -> str:
    """Generate a unique local filename for a message's media.

    Enhanced by Telegram MCP Enhanced: the name is built from server-controlled
    values only. Upstream used the sender's filename stem, which put text chosen
    by a stranger into a path that is written to disk *and* returned to the
    model — so a file called "ignore all previous instructions.png" reached the
    model through a field no security mode could rewrite, because the path has
    to keep naming the real file. The original name is still reported, safely,
    as `media.file_name`.

    Args:
        message (`patched.Message`): The message to generate a filename for.

    Returns:
        `str`: The unique filename.
    """
    return f"download_{message.id}_{uuid.uuid4()}{_safe_suffix(message)}"


def _safe_suffix(message: patched.Message) -> str:
    """A file extension that cannot carry a payload, or none at all."""
    if message.file and isinstance(message.file.name, str):
        suffix = Path(message.file.name).suffix
        if SAFE_SUFFIX.match(suffix):
            return suffix.lower()

    if message.file and isinstance(message.file.mime_type, str):
        parts = message.file.mime_type.split("/")
        if len(parts) == 2 and parts[1].isalnum() and len(parts[1]) <= 10:
            return f".{parts[1].lower()}"

    return ""


def parse_telegram_url(url: str) -> tuple[str | int, int] | None:
    """Parse a Telegram message URL to extract the entity and message ID.

    Handles common formats like:
    - `https://t.me/username/123`
    - `t.me/username/123`
    - `https://telegram.me/username/123`
    - `telegram.me/username/123`
    - `https://t.me/c/1234567890/123`

    Args:
        url (`str`): The Telegram URL to parse.

    Returns:
        `tuple[str | int, int] | None`:
            A tuple containing the entity (username or channel_id) and the
            message ID, or None if the URL format is not recognized.
    """
    # Regex to capture the entity (username or channel_id) and message ID
    pattern = r"^(?:https?://)?t(?:elegram)?\.me/(?:(?P<username>[A-Za-z0-9_]+)/(?P<message_id>\d+)|c/(?P<chat_id>\d+)/(?P<chat_message_id>\d+))/?$"

    match = re.match(pattern, url)

    if match:
        captured = match.groupdict()
        entity = captured.get("username") or captured.get("chat_id")
        message_id = captured.get("message_id") or captured.get("chat_message_id")

        if entity and message_id:
            return parse_entity(entity), int(message_id)

    return None
