"""Human confirmation through MCP elicitation.

Added by Telegram MCP Enhanced.

An operation whose permission is `"confirm"` runs only after the person at the
MCP client approves it. The question travels as an MCP `elicitation/create`
request on the session that made the tool call, so it reaches whoever is driving
that client — not the model, and not anything written in a Telegram message.

Everything that is not an explicit approval is a refusal. That includes a
client that never declared elicitation support, an SDK too old to send the
request (mcp < 1.9), a decline, a cancel, and any error on the way.
"""

from __future__ import annotations

from typing import Any

__all__ = ["APPROVAL_FIELD", "APPROVAL_SCHEMA", "elicit_confirmation"]

APPROVAL_FIELD = "approve"

APPROVAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        APPROVAL_FIELD: {
            "type": "boolean",
            "title": "Approve this action",
            "description": "Tick to let the agent perform the action described.",
            "default": False,
        }
    },
    "required": [APPROVAL_FIELD],
}
"""A single explicit checkbox.

Accepting the form is not enough on its own: a client that auto-submits
defaults would otherwise approve everything, so the field defaults to false and
must come back true.
"""


def client_supports_elicitation(session: Any) -> bool:
    """Whether the client declared elicitation in its `initialize` request.

    Read from the declared capabilities directly rather than through the SDK's
    `check_client_capability`, whose semantics for sub-capabilities differ
    between generations. A declaration of any kind counts; the spec makes form
    mode the default.
    """
    params = getattr(session, "client_params", None)
    capabilities = getattr(params, "capabilities", None)
    return getattr(capabilities, "elicitation", None) is not None


async def elicit_confirmation(request_context: Any, message: str) -> tuple[bool, str]:
    """Ask the human behind ``request_context`` to approve ``message``.

    Args:
        request_context: the SDK's per-call `Context` object, or None when the
            tool was called outside MCP.
        message: the full question, built by the server.

    Returns:
        Whether it was approved, and a short reason suitable for the audit log.
    """
    if request_context is None:
        return False, "the call did not arrive over an MCP session"
    try:
        lowlevel = request_context.request_context
        session = lowlevel.session
        request_id = lowlevel.request_id
    except Exception:
        return False, "the call did not arrive over an MCP session"

    # `elicit_form` on 2.x, where `elicit` is its deprecated alias; `elicit` on
    # 1.9 and later; neither before that.
    elicit = getattr(session, "elicit_form", None) or getattr(session, "elicit", None)
    if elicit is None:
        return False, "the installed MCP SDK cannot send elicitation requests"
    if not client_supports_elicitation(session):
        return False, "the MCP client does not support elicitation"

    try:
        # Positional on purpose: the schema argument is `requestedSchema` on
        # 1.x and `requested_schema` on 2.x.
        result = await elicit(message, APPROVAL_SCHEMA, request_id)
    except Exception as exc:
        if type(exc).__name__ == "NoBackChannelError":
            # Protocol 2026-07-28 connections carry no server-initiated
            # requests; elicitation there rides a retried tool call instead,
            # which this server does not implement yet.
            return False, (
                "this connection cannot carry a question to the user "
                "(MCP protocol without a server-to-client channel)"
            )
        raise
    action = getattr(result, "action", None)
    content = getattr(result, "content", None) or {}
    if action == "accept" and content.get(APPROVAL_FIELD) is True:
        return True, "approved by the user"
    if action == "accept":
        return False, "the user submitted the form without approving"
    if action in ("decline", "cancel"):
        return False, f"the user chose {action}"
    return False, "the client returned an unrecognised answer"
