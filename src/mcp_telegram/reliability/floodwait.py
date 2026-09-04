"""FloodWait interception and bounded retries.

Added by Telegram MCP Enhanced.

Telegram answers an over-eager client with a flood-wait error carrying the
number of seconds to wait. Upstream lets that exception propagate. Here it is
caught, converted into a scheduler-wide cooldown, retried a bounded number of
times, and — if the wait is longer than the operator allows — reported to the
agent as a structured, explicitly temporary condition.
"""

from __future__ import annotations

import logging

from collections.abc import Awaitable, Callable
from typing import TypeVar

from telethon import errors  # type: ignore

from mcp_telegram.config import RateLimitSettings
from mcp_telegram.errors import RateLimitedError
from mcp_telegram.reliability.scheduler import RequestScheduler
from mcp_telegram.security.audit import SecurityAuditLog

__all__ = ["flood_wait_seconds", "run_with_flood_protection"]

logger = logging.getLogger(__name__)

T = TypeVar("T")


def flood_wait_seconds(exc: BaseException) -> float | None:
    """Return the wait Telegram asked for, or None if this is not a flood error."""
    if not isinstance(exc, errors.FloodError):
        return None
    seconds = getattr(exc, "seconds", None)
    if seconds is None:
        return 0.0
    try:
        return float(seconds)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return 0.0


async def run_with_flood_protection(
    operation: Callable[[], Awaitable[T]],
    *,
    scheduler: RequestScheduler,
    operation_class: str,
    settings: RateLimitSettings,
    audit: SecurityAuditLog,
    tool: str,
) -> T:
    """Run ``operation`` under the scheduler, absorbing Telegram flood waits.

    Raises:
        RateLimitedError: when the wait exceeds ``max_flood_wait_seconds`` or the
            retry budget is exhausted. The server stays up either way.
    """
    attempt = 0
    while True:
        try:
            async with scheduler.slot(operation_class, tool=tool):
                return await operation()
        except Exception as exc:
            seconds = flood_wait_seconds(exc)
            if seconds is None:
                raise

            # Hold back every other queued operation too, so parallel MCP
            # requests cannot turn one flood wait into a retry storm.
            scheduler.note_flood_wait(seconds)

            if seconds > settings.max_flood_wait_seconds:
                audit.flood_wait(
                    tool=tool, seconds=seconds, attempt=attempt, action_taken="reported"
                )
                raise RateLimitedError(
                    retry_after_seconds=seconds,
                    reason=(
                        f"Telegram asked for a {seconds:g}s wait, longer than the "
                        f"configured max_flood_wait_seconds "
                        f"({settings.max_flood_wait_seconds:g}s)"
                    ),
                    scope="telegram",
                ) from exc

            if attempt >= settings.max_retries:
                audit.flood_wait(
                    tool=tool,
                    seconds=seconds,
                    attempt=attempt,
                    action_taken="retries_exhausted",
                )
                raise RateLimitedError(
                    retry_after_seconds=seconds,
                    reason=(
                        f"Telegram rate-limited this operation and the retry budget "
                        f"(max_retries={settings.max_retries}) is exhausted"
                    ),
                    scope="telegram",
                ) from exc

            attempt += 1
            audit.flood_wait(
                tool=tool, seconds=seconds, attempt=attempt, action_taken="retrying"
            )
            logger.warning(
                "Telegram flood wait of %.0fs on %s; retry %d/%d",
                seconds,
                tool,
                attempt,
                settings.max_retries,
            )
            # The retry re-enters the scheduler, which serves the cooldown and
            # then the rate limiter and pacing interval before dispatching again.
