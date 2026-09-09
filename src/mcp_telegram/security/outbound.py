"""Stop model-composed exfiltration before Telegram sees the request.

Added by Telegram MCP Enhanced. Incoming-content detection cannot inspect text
the model composes itself, so outbound text needs an independent refusal policy.
"""

from __future__ import annotations

from mcp_telegram.config import OutboundSettings
from mcp_telegram.errors import OutboundPolicyError
from mcp_telegram.security.audit import CredentialScrubber


def check_outbound(
    text: str, settings: OutboundSettings, scrubber: CredentialScrubber
) -> None:
    """Refuse the whole request rather than silently change the user's message."""
    if not settings.enabled:
        return
    if settings.max_message_chars and len(text) > settings.max_message_chars:
        raise OutboundPolicyError(reason="max_length")
    if settings.block_credentials and scrubber.contains_credentials(text):
        raise OutboundPolicyError(reason="credentials")
    if (
        settings.block_bulk_quotes
        and len(text) > settings.bulk_quote_min_chars
        and _quoted_ratio(text) >= settings.bulk_quote_ratio
    ):
        raise OutboundPolicyError(reason="bulk_quotes")


def _quoted_ratio(text: str) -> float:
    """Require explicit line markers to avoid guessing the provenance of prose.

    A forward header alone does not make all subsequent text a quotation. Only
    marked lines count, and whitespace is excluded so padding cannot dominate
    the ratio. This deliberately misses unmarked transcripts and paraphrases.
    """
    total = 0
    quoted = 0
    for line in text.splitlines():
        stripped = line.strip()
        weight = len(stripped)
        total += weight
        if stripped.startswith(">") or stripped.lower().startswith(
            ("forwarded from ", "forwarded message:")
        ):
            quoted += weight
    return quoted / total if total else 0.0
