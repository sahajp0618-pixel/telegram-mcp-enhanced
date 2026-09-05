"""Server-side permission enforcement.

Added by Telegram MCP Enhanced.

Nothing here consults the model. Even if hostile Telegram content convinces the
LLM to attempt an operation, the request still has to satisfy these checks
before it reaches Telethon.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from mcp_telegram.config import ChatPolicy, PermissionSettings
from mcp_telegram.errors import ChatAccessDeniedError, PermissionDeniedError
from mcp_telegram.types import Dialog

__all__ = [
    "OPERATION_CLASS",
    "resolved_tokens",
    "ChatDecision",
    "Operation",
    "OperationClass",
    "PermissionEnforcer",
    "ResolvedChat",
    "chat_tokens",
]

WILDCARD = "*"


class Operation(str, Enum):
    """Permission categories enforced by the server."""

    READ_MESSAGES = "READ_MESSAGES"
    SEARCH_MESSAGES = "SEARCH_MESSAGES"
    SEND_MESSAGES = "SEND_MESSAGES"
    EDIT_MESSAGES = "EDIT_MESSAGES"
    DELETE_MESSAGES = "DELETE_MESSAGES"
    DOWNLOAD_MEDIA = "DOWNLOAD_MEDIA"
    MANAGE_DRAFTS = "MANAGE_DRAFTS"
    ADMINISTRATIVE_ACTIONS = "ADMINISTRATIVE_ACTIONS"
    RESOLVE_ENTITY = "RESOLVE_ENTITY"
    """Internal: resolving an identifier to a peer id on Telegram's servers."""


class OperationClass(str, Enum):
    """Rate-limiting classes. Different traffic shapes deserve different limits."""

    READ = "read"
    SEARCH = "search"
    WRITE = "write"
    MEDIA = "media"
    ADMIN = "admin"


OPERATION_CLASS: dict[Operation, OperationClass] = {
    Operation.READ_MESSAGES: OperationClass.READ,
    Operation.SEARCH_MESSAGES: OperationClass.SEARCH,
    Operation.SEND_MESSAGES: OperationClass.WRITE,
    Operation.EDIT_MESSAGES: OperationClass.WRITE,
    Operation.DELETE_MESSAGES: OperationClass.WRITE,
    Operation.DOWNLOAD_MEDIA: OperationClass.MEDIA,
    Operation.MANAGE_DRAFTS: OperationClass.WRITE,
    Operation.ADMINISTRATIVE_ACTIONS: OperationClass.ADMIN,
    Operation.RESOLVE_ENTITY: OperationClass.READ,
}

_PERMISSION_ATTR: dict[Operation, str] = {
    Operation.READ_MESSAGES: "allow_read",
    Operation.SEARCH_MESSAGES: "allow_search",
    Operation.SEND_MESSAGES: "allow_send",
    Operation.EDIT_MESSAGES: "allow_edit",
    Operation.DELETE_MESSAGES: "allow_delete",
    Operation.DOWNLOAD_MEDIA: "allow_download",
    Operation.MANAGE_DRAFTS: "allow_drafts",
    Operation.ADMINISTRATIVE_ACTIONS: "allow_admin",
    Operation.RESOLVE_ENTITY: "allow_read",
}

_CONFIG_KEY = {
    "allow_read": "allow_read",
    "allow_search": "allow_search",
    "allow_send": "allow_send",
    "allow_edit": "allow_edit",
    "allow_delete": "allow_delete",
    "allow_download": "allow_download",
    "allow_drafts": "allow_drafts",
    "allow_admin": "allow_admin",
}


class ChatDecision(Enum):
    """Outcome of a chat-level access check."""

    ALLOW = "allow"
    DENY = "deny"
    NEEDS_RESOLUTION = "needs_resolution"
    """Cannot be decided from the identifier alone; ask Telegram for the peer id."""


def normalize_token(value: object) -> str:
    """Reduce a chat identifier to a comparable form."""
    token = str(value).strip().lower()
    for prefix in ("https://t.me/", "http://t.me/", "t.me/", "@"):
        if token.startswith(prefix):
            token = token[len(prefix) :]
            break
    return token.rstrip("/")


def chat_tokens(value: object) -> set[str]:
    """Every spelling of ``value`` that compares equal *without* resolution.

    Deliberately exact: a bare number is not expanded into other peer forms.
    `1234567890` is a user and `-1001234567890` is a channel, and treating one
    as an alias of the other would let a channel allowlist entry authorise an
    unrelated user. The `-100` prefix is reconciled after resolution, where the
    peer type is actually known.
    """
    return {normalize_token(value)}


def resolved_tokens(resolved: ResolvedChat) -> set[str]:
    """Every spelling of a peer Telegram has identified.

    Only here is the unmarked channel id safe to accept: the canonical id says
    the peer really is a channel, so `-100…` and the bare id name the same chat.
    """
    tokens = {normalize_token(resolved.peer_id)}
    digits = str(abs(resolved.peer_id))
    if resolved.peer_id < 0 and digits.startswith("100") and len(digits) > 3:
        tokens.add(digits[3:])
    if resolved.username:
        tokens.add(normalize_token(resolved.username))
    return tokens


@dataclass(frozen=True)
class _ChatResult:
    decision: ChatDecision
    reason: str


@dataclass(frozen=True)
class ResolvedChat:
    """What Telegram says an identifier refers to."""

    peer_id: int
    username: str | None = None


class PermissionEnforcer:
    """Applies operation permissions and chat-level access control."""

    def __init__(self, settings: PermissionSettings) -> None:
        self.settings = settings
        self._allowed: set[str] = set()
        self._denied: set[str] = set()
        for entry in settings.allowed_chats:
            self._allowed |= chat_tokens(entry)
        for entry in settings.denied_chats:
            self._denied |= chat_tokens(entry)

    # -- operation permissions --------------------------------------------- #

    def is_operation_allowed(self, operation: Operation) -> bool:
        return bool(getattr(self.settings, _PERMISSION_ATTR[operation]))

    def check_operation(self, operation: Operation) -> None:
        """Raise unless this server is configured to perform ``operation``."""
        attribute = _PERMISSION_ATTR[operation]
        if getattr(self.settings, attribute):
            return
        raise PermissionDeniedError(
            operation=operation.value,
            reason=f"{attribute} is disabled in this server's configuration",
            hint=(
                f"An operator can enable it by setting {_CONFIG_KEY[attribute]} = true "
                "under [permissions] in the config file. The model cannot change this."
            ),
        )

    def allowed_operations(self) -> dict[str, bool]:
        """Operation permissions, for the `security_status` tool and the CLI."""
        return {
            operation.value: self.is_operation_allowed(operation)
            for operation in Operation
            if operation is not Operation.RESOLVE_ENTITY
        }

    # -- chat-level access controls ---------------------------------------- #

    @property
    def chat_filtering_active(self) -> bool:
        return self.settings.chat_filtering_active

    def decide_chat(self, entity: object) -> _ChatResult:
        """Decide access from the identifier alone, without touching Telegram.

        Returns NEEDS_RESOLUTION whenever asking Telegram could change the
        answer *in either direction*. Resolution is not only how a username
        earns an allowance — it is also how a denial is enforced against a chat
        the caller named some other way.
        """
        tokens = chat_tokens(entity)

        if WILDCARD in self._denied:
            return _ChatResult(ChatDecision.DENY, "all chats are denied by policy")
        if tokens & self._denied:
            return _ChatResult(ChatDecision.DENY, "chat is in denied_chats")

        allowed_now = WILDCARD in self._allowed or bool(tokens & self._allowed)

        if self._resolution_could_reveal_more(tokens):
            if self._denied:
                # A denied chat can be reached under another spelling, so a
                # denylist is unenforceable until the identifier is canonical.
                return _ChatResult(
                    ChatDecision.NEEDS_RESOLUTION,
                    "identifier must be resolved before denied_chats can be applied",
                )
            if self._allowed and not allowed_now:
                return _ChatResult(
                    ChatDecision.NEEDS_RESOLUTION, "identifier must be resolved first"
                )

        if allowed_now:
            return _ChatResult(ChatDecision.ALLOW, "chat is in allowed_chats")
        if self.settings.effective_default_policy == ChatPolicy.ALLOW:
            return _ChatResult(ChatDecision.ALLOW, "default_policy is allow")
        return _ChatResult(
            ChatDecision.DENY, "chat is not in allowed_chats and default_policy is deny"
        )

    def _resolution_could_reveal_more(self, tokens: set[str]) -> bool:
        """Whether asking Telegram could produce an identifier we have not checked.

        Precise on purpose: a round trip that cannot change the answer is both a
        wasted Telegram request and a way for a caller to probe which chats
        exist, so it is only taken when a match is genuinely still possible.
        """
        entries = {
            entry for entry in (self._allowed | self._denied) if entry != WILDCARD
        }
        if not entries:
            return False

        token = next(iter(tokens))
        if not token.lstrip("-").isdigit():
            return True  # a username or phone number resolves to a peer id

        if any(not entry.lstrip("-").isdigit() for entry in entries):
            return True  # the peer's username may be the listed one

        # Both sides are numeric, so the only spelling still in play is the
        # `-100` channel prefix, which resolution settles by revealing the type.
        digits = token.lstrip("-")
        if not token.startswith("-"):
            return f"-100{digits}" in entries
        if digits.startswith("100") and len(digits) > 3:
            return digits[3:] in entries
        return False

    def decide_resolved(self, resolved: ResolvedChat) -> _ChatResult:
        """Decide access for an identifier Telegram has now identified."""
        tokens = resolved_tokens(resolved)
        if WILDCARD in self._denied or tokens & self._denied:
            return _ChatResult(ChatDecision.DENY, "chat is in denied_chats")
        if WILDCARD in self._allowed or tokens & self._allowed:
            return _ChatResult(ChatDecision.ALLOW, "chat is in allowed_chats")
        if self.settings.effective_default_policy == ChatPolicy.ALLOW:
            return _ChatResult(ChatDecision.ALLOW, "default_policy is allow")
        return _ChatResult(
            ChatDecision.DENY, "chat is not in allowed_chats and default_policy is deny"
        )

    def is_chat_allowed(self, entity: object) -> bool:
        """Best-effort check with no resolution step (used to filter results)."""
        return self.decide_chat(entity).decision is ChatDecision.ALLOW

    def is_dialog_allowed(self, dialog: Dialog) -> bool:
        """Access check for a search result.

        A dialog carries both an id and a username, so it can be matched against
        an allowlist written either way without asking Telegram anything.
        """
        tokens = resolved_tokens(
            ResolvedChat(peer_id=dialog.id, username=dialog.username)
        )
        if WILDCARD in self._denied or tokens & self._denied:
            return False
        if WILDCARD in self._allowed or tokens & self._allowed:
            return True
        return self.settings.effective_default_policy == ChatPolicy.ALLOW

    def deny_chat(self, entity: object, reason: str) -> ChatAccessDeniedError:
        return ChatAccessDeniedError(
            entity=str(entity),
            reason=reason,
            hint=(
                "An operator can grant access by adding this chat to allowed_chats "
                "under [permissions] in the config file. The model cannot change this."
            ),
        )

    def filter_dialogs(self, dialogs: list[Dialog]) -> tuple[list[Dialog], int]:
        """Drop search results the server may not access.

        Without this, a deny-by-default allowlist would still let an agent
        enumerate every chat on the account through search.
        """
        if not self.chat_filtering_active:
            return dialogs, 0
        kept = [dialog for dialog in dialogs if self.is_dialog_allowed(dialog)]
        return kept, len(dialogs) - len(kept)
