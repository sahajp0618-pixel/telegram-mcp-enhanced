"""Utility functions for the MCP Telegram module."""

import importlib.metadata
import re
import uuid

from pathlib import Path

from telethon.tl import patched  # type: ignore

DISTRIBUTION_NAMES = ("telegram-mcp-enhanced", "mcp-telegram")
"""Both names this package may be installed under, newest first.

The distribution was renamed downstream while the import package kept upstream's
name, so a lookup has to try both: an install from this repository answers to the
first, an older install from upstream to the second.
"""


def installed_version() -> str:
    """The installed distribution version.

    Lives here rather than in the CLI because the server reports it too, and the
    CLI imports the server -- so the server cannot import the CLI back.
    """
    for name in DISTRIBUTION_NAMES:
        try:
            return importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
    raise importlib.metadata.PackageNotFoundError(DISTRIBUTION_NAMES[0])


PLAIN_INTEGER = re.compile(r"-?\d+")
"""What counts as a bare Telegram peer id.

The single source of truth for "is this identifier a number?". The security
layer matches policy against the same pattern, so a spelling can never be a chat
id to one layer and something else to the other — the mismatch that made
whitespace- and zero-padded ids bypass chat rules. A leading `+` is excluded on
purpose: Telethon reads `+15551234567` as a phone number, not as peer 15551234567.
"""


def parse_entity(entity: str | int) -> int | str:
    """
    Parse a string entity identifier as an integer ID.

    If the string represents a valid integer (potentially negative), it's
    returned as an `int`. Otherwise, the original string (assumed to be
    a username or phone number) is returned.

    Accepts an `int` and returns it unchanged, so the parser is idempotent:
    `parse_telegram_url` already yields an int for a private-chat link, and the
    authorization path parses identifiers a second time to make sure it judges
    exactly what execution will use.

    Surrounding whitespace is stripped for the same reason. `" -1001234567890 "`
    is a chat id to the policy layer, but left unstripped it stays a string, and
    Telethon reads a numeric string as a *phone number* — so authorization and
    execution would name different peers.

    Args:
        entity (`str | int`): The entity (ID, username, phone number, or "me").

    Returns:
        `int | str`: The parsed integer ID or the original string identifier.
    """
    if isinstance(entity, int):
        return entity
    entity = entity.strip()
    return int(entity) if PLAIN_INTEGER.fullmatch(entity) else entity


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
