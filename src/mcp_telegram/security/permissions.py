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
from mcp_telegram.utils import parse_entity

__all__ = [
    "ID_PREFIX",
    "NAME_PREFIX",
    "OPERATION_CLASS",
    "SELF_ALIASES",
    "name_token",
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


ID_PREFIX = "id:"
NAME_PREFIX = "name:"


def normalize_token(value: object) -> str:
    """Reduce a chat identifier to a comparable, *typed* form.

    The type tag is the point. Whether an identifier is a peer id is decided by
    :func:`mcp_telegram.utils.parse_entity` — the same call execution makes —
    and only identifiers it does not turn into an integer have their `@`, URL
    and trailing-slash decorations stripped. Deciding "is this a number?" after
    stripping decorations was a bypass: `123/` became the token `123`, matching
    an allowlist entry for peer 123, while Telethon kept the string and resolved
    it by cached title to an entirely different chat.

    Tagging also keeps the two namespaces apart, so a chat *named* `123` can
    never satisfy a rule about the chat *with id* 123.
    """
    parsed = parse_entity(value) if isinstance(value, (str, int)) else str(value)
    if isinstance(parsed, int):
        return f"{ID_PREFIX}{parsed}"

    token = parsed.strip().lower()
    for prefix in ("https://t.me/", "http://t.me/", "t.me/", "@"):
        if token.startswith(prefix):
            token = token[len(prefix) :]
            break
    return f"{NAME_PREFIX}{token.rstrip('/')}"


SELF_ALIASES = frozenset({"me", "self"})
"""Identifiers Telethon resolves to the account itself and nothing else.

They cannot be redirected to another peer, so a rule naming one does not need
confirming with Telegram the way an ordinary username does.
"""


def name_token(value: str) -> str:
    """Tag a username Telegram itself reported.

    Only case is normalised. A resolved username is already canonical, so
    stripping decorations from it would undo the check it exists to support: a
    peer whose name is `alice/` must not satisfy a rule about `@alice`.
    """
    return f"{NAME_PREFIX}{value.strip().lower()}"


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
    tokens = {f"{ID_PREFIX}{resolved.peer_id}"}
    digits = str(abs(resolved.peer_id))
    if resolved.peer_id < 0 and digits.startswith("100") and len(digits) > 3:
        tokens.add(f"{ID_PREFIX}{digits[3:]}")
    if resolved.username:
        tokens.add(name_token(resolved.username))
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
        self._allow_all = WILDCARD in {e.strip() for e in settings.allowed_chats}
        self._deny_all = WILDCARD in {e.strip() for e in settings.denied_chats}
        self._allowed: set[str] = set()
        self._denied: set[str] = set()
        for entry in settings.allowed_chats:
            if entry.strip() != WILDCARD:
                self._allowed |= chat_tokens(entry)
        for entry in settings.denied_chats:
            if entry.strip() != WILDCARD:
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

        if self._deny_all:
            return _ChatResult(ChatDecision.DENY, "all chats are denied by policy")
        if tokens & self._denied:
            return _ChatResult(ChatDecision.DENY, "chat is in denied_chats")

        allowed_now = self._allow_all or bool(tokens & self._allowed)
        is_peer_id = next(iter(tokens)).startswith(ID_PREFIX)

        is_self = next(iter(tokens)) in {
            f"{NAME_PREFIX}{alias}" for alias in SELF_ALIASES
        }

        if allowed_now and not self._allow_all and not is_peer_id and not is_self:
            # A name matched textually, which is not the same as naming the same
            # chat. Telethon can resolve a decorated or malformed name through
            # its cached display-name fallback, so `alice/` matching an entry
            # for `@alice` could still execute against an unrelated peer. Ask
            # Telegram which peer it really is, check that peer's own username,
            # and execute against the id that comes back.
            return _ChatResult(
                ChatDecision.NEEDS_RESOLUTION,
                "a name must be confirmed with Telegram before it grants access",
            )

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
        entries = self._allowed | self._denied
        if not entries:
            return False

        token = next(iter(tokens))
        if not token.startswith(ID_PREFIX):
            # Anything execution will not turn into a peer id — a username, a
            # phone number, a decorated form, or a malformed number Telethon
            # still reads as a phone — has to be resolved before it can be
            # judged. The tag comes from the parser execution itself uses, so
            # the two layers cannot disagree about what the identifier is.
            return True

        if any(not entry.startswith(ID_PREFIX) for entry in entries):
            return True  # the peer's username may be the listed one

        # Both sides are peer ids, so the only spelling still in play is the
        # `-100` channel prefix, which resolution settles by revealing the type.
        number = token[len(ID_PREFIX) :]
        digits = number.lstrip("-")
        if not number.startswith("-"):
            return f"{ID_PREFIX}-100{digits}" in entries
        if digits.startswith("100") and len(digits) > 3:
            return f"{ID_PREFIX}{digits[3:]}" in entries
        return False

    def decide_resolved(self, resolved: ResolvedChat) -> _ChatResult:
        """Decide access for an identifier Telegram has now identified."""
        tokens = resolved_tokens(resolved)
        if self._deny_all or tokens & self._denied:
            return _ChatResult(ChatDecision.DENY, "chat is in denied_chats")
        if self._allow_all or tokens & self._allowed:
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
        if self._deny_all or tokens & self._denied:
            return False
        if self._allow_all or tokens & self._allowed:
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
