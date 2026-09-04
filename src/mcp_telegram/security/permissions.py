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
    "ChatDecision",
    "Operation",
    "OperationClass",
    "PermissionEnforcer",
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


def _id_variants(value: int) -> set[str]:
    """Marked and unmarked spellings of the same channel id.

    Telegram reports supergroups and channels as ``-100`` + the raw id, and
    operators copy whichever form their client shows. A sign flip is *not*
    treated as equivalent: ``123`` (a user) and ``-123`` (a basic group) are
    genuinely different chats.
    """
    variants = {str(value)}
    digits = str(abs(value))
    if value < 0 and digits.startswith("100") and len(digits) > 3:
        variants.add(digits[3:])
    elif value > 0:
        variants.add(f"-100{digits}")
    return variants


def chat_tokens(value: object) -> set[str]:
    """Every spelling of ``value`` that should compare equal."""
    token = normalize_token(value)
    tokens = {token}
    if token.lstrip("-").isdigit():
        tokens |= _id_variants(int(token))
    return tokens


@dataclass(frozen=True)
class _ChatResult:
    decision: ChatDecision
    reason: str


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
        """Decide access from the identifier alone, without touching Telegram."""
        tokens = chat_tokens(entity)

        if WILDCARD in self._denied:
            return _ChatResult(ChatDecision.DENY, "all chats are denied by policy")
        if tokens & self._denied:
            return _ChatResult(ChatDecision.DENY, "chat is in denied_chats")
        if WILDCARD in self._allowed or tokens & self._allowed:
            return _ChatResult(ChatDecision.ALLOW, "chat is in allowed_chats")
        if self.settings.effective_default_policy == ChatPolicy.ALLOW:
            return _ChatResult(ChatDecision.ALLOW, "default_policy is allow")

        token = next(iter(tokens))
        if self._allowed and not token.lstrip("-").isdigit():
            # A username or phone number may still resolve to an allowed peer id.
            return _ChatResult(
                ChatDecision.NEEDS_RESOLUTION, "identifier must be resolved first"
            )
        return _ChatResult(
            ChatDecision.DENY, "chat is not in allowed_chats and default_policy is deny"
        )

    def decide_resolved_id(self, peer_id: int) -> _ChatResult:
        """Decide access for an identifier already resolved to a peer id."""
        tokens = chat_tokens(peer_id)
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
        kept = [dialog for dialog in dialogs if self.is_chat_allowed(dialog.id)]
        return kept, len(dialogs) - len(kept)
