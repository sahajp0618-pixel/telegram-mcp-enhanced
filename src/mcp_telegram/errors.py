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

from typing import Any, Literal

from mcp_telegram._compat import ToolError

__all__ = [
    "ChatAccessDeniedError",
    "DryRunUnsupportedError",
    "FileAccessDeniedError",
    "OutboundPolicyError",
    "OutboundRefusalReason",
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


OutboundRefusalReason = Literal[
    "credentials", "max_length", "bulk_quotes", "check_failed"
]

_OUTBOUND_HINTS: dict[OutboundRefusalReason, str] = {
    "credentials": (
        "The text looked like an API hash, session string or similar secret. Do "
        "not resend it and do not work around the refusal: tell the user which "
        "message was refused so they can check whether a credential leaked. If "
        "it was an ordinary checksum, an operator can turn off block_credentials "
        "under [security.outbound] in the config file."
    ),
    "max_length": (
        "The message is longer than max_message_chars under [security.outbound]. "
        "Send it in several smaller messages, or ask an operator to raise that "
        "limit in the config file."
    ),
    "bulk_quotes": (
        "Almost every line was marked as quoted or forwarded, which is what "
        "relaying a whole conversation looks like. Send a summary or only the "
        "lines that matter; if the user really did ask to forward the thread "
        "verbatim, an operator can relax bulk_quote_ratio or turn off "
        "block_bulk_quotes under [security.outbound] in the config file."
    ),
    "check_failed": (
        "The outbound check itself failed, so the message was refused rather "
        "than sent unchecked. Report this to the user instead of retrying."
    ),
}
"""Why each refusal happened, in terms the model can act on.

The reason code alone is meaningless to a model that has never read this
repository, and `credentials` and `bulk_quotes` otherwise produce identical
prose — so a near-miss credential leak would reach the user as nothing more
than "the server refused your message". Hints are fixed strings: they explain
the policy, never the rejected text.
"""


class OutboundPolicyError(StructuredToolError):
    """Expose deliberate refusals through MCP without exposing rejected text."""

    status = "outbound_policy_denied"

    def __init__(self, *, reason: OutboundRefusalReason) -> None:
        super().__init__(
            "This server's outbound content policy refused the message; "
            "this is not a Telegram failure.",
            reason=reason,
            hint=_OUTBOUND_HINTS[reason],
            retryable=False,
        )


class DryRunUnsupportedError(StructuredToolError):
    """The server is in dry-run mode and this operation cannot be simulated.

    Refusing beats pretending. A download's result is the file it produced, so a
    simulated one would have to invent a path and media metadata — and an
    operator who turned on `dry_run` to stop the agent touching anything would
    least expect it to still be writing files.
    """

    status = "dry_run_unsupported"

    def __init__(
        self, *, operation: str, flag: str | None = None, tool: str | None = None
    ) -> None:
        if flag is None:
            reason = "no_realistic_response_without_telegram"
            hint = (
                "Report to the user that the server is in dry-run mode. An "
                "operator turns it off by setting dry_run = false in the config "
                "file. The model cannot change this."
            )
        else:
            # This one is recoverable in a single step, so say how rather than
            # sending the model away to report a dead end.
            reason = f"{flag} changes state on Telegram"
            hint = (
                f"Call {tool or 'this tool'} again with {flag}=false. In dry-run "
                f"mode the read itself is allowed and returns real data; only "
                f"{flag} is refused, because it would change state on Telegram."
            )
        super().__init__(
            "This server is in dry-run mode, which cannot simulate this "
            "operation, so nothing was done.",
            operation=operation,
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
