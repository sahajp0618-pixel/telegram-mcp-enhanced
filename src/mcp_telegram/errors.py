"""Structured errors surfaced to the MCP client.

Added by Telegram MCP Enhanced.

An MCP tool signals failure by raising a `ToolError`; the SDK turns its text
into an error result the model can read. These exceptions render as a plain
sentence followed by a JSON object, so the connected agent can both read what
happened and parse it — in particular, it can tell a temporary rate limit apart
from a permanent Telegram failure.
"""

from __future__ import annotations

import json

from typing import Any

from mcp_telegram._compat import ToolError

__all__ = [
    "ChatAccessDeniedError",
    "FileAccessDeniedError",
    "PermissionDeniedError",
    "RateLimitedError",
    "SecurityLayerError",
    "StructuredToolError",
]


class StructuredToolError(ToolError):
    """Base class for errors that carry a machine-readable payload.

    Deriving from the SDK's `ToolError` marks these as deliberate refusals
    rather than crashes, which is what allows the payload to reach the model.
    """

    status = "error"

    def __init__(self, message: str, **details: Any) -> None:
        self.message = message
        self.details = {
            key: value for key, value in details.items() if value is not None
        }
        super().__init__(message)

    @property
    def payload(self) -> dict[str, Any]:
        return {"status": self.status, "message": self.message, **self.details}

    def __str__(self) -> str:
        return f"{self.message} {json.dumps(self.payload, default=str)}"


class PermissionDeniedError(StructuredToolError):
    """The server's own policy forbids this operation.

    Raised regardless of what the model was told to do: the MCP server, not the
    model, is the security boundary.
    """

    status = "permission_denied"

    def __init__(self, *, operation: str, reason: str, hint: str | None = None) -> None:
        super().__init__(
            f"Operation {operation} is not permitted by this server's policy.",
            operation=operation,
            reason=reason,
            hint=hint,
            retryable=False,
        )


class ChatAccessDeniedError(StructuredToolError):
    """The requested chat is outside the configured allowlist."""

    status = "chat_not_allowed"

    def __init__(self, *, entity: str, reason: str, hint: str | None = None) -> None:
        super().__init__(
            "This server is not allowed to access that chat.",
            entity=entity[:80],
            reason=reason,
            hint=hint,
            retryable=False,
        )


class RateLimitedError(StructuredToolError):
    """The operation cannot proceed yet. Temporary, not a Telegram failure."""

    status = "rate_limited"

    def __init__(
        self,
        *,
        retry_after_seconds: float,
        reason: str,
        scope: str = "local",
    ) -> None:
        super().__init__(
            "Telegram temporarily rate-limited this operation. It is a temporary "
            "condition, not a permanent failure: wait the stated time before "
            "trying again, and do not retry in a loop.",
            retry_after_seconds=round(float(retry_after_seconds), 3),
            reason=reason,
            scope=scope,
            retryable=True,
        )


class FileAccessDeniedError(StructuredToolError):
    """A local file path was refused by the file-access policy."""

    status = "file_access_denied"

    def __init__(self, *, path: str, reason: str, hint: str | None = None) -> None:
        super().__init__(
            "That local file path is not permitted by this server's policy.",
            path=path[:200],
            reason=reason,
            hint=hint,
            retryable=False,
        )


class SecurityLayerError(StructuredToolError):
    """The security layer itself failed, so the operation was refused.

    Security failures reduce capability rather than silently letting content or
    operations through unchecked.
    """

    status = "security_error"

    def __init__(self, *, reason: str) -> None:
        super().__init__(
            "The request was refused because the security layer could not run.",
            reason=reason,
            retryable=False,
        )
