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

__all__ = ["longest_flood_wait", "flood_wait_seconds", "run_with_flood_protection"]

logger = logging.getLogger(__name__)

T = TypeVar("T")


def _plain_flood_seconds(exc: BaseException) -> float | None:
    """The wait carried by a single Telethon flood error, if it is one."""
    if not isinstance(exc, errors.FloodError):
        return None
    seconds = getattr(exc, "seconds", None)
    if seconds is None:
        return 0.0
    try:
        return float(seconds)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return 0.0


def longest_flood_wait(exc: BaseException) -> float | None:
    """The longest wait anywhere in ``exc``, for publishing a cooldown.

    Holding other operations back is safe even when replaying this one is not,
    so this looks inside a MultiError unconditionally. The longest wins:
    satisfying the shortest would walk straight into the next.
    """
    if isinstance(exc, errors.MultiError):
        waits = [
            wait
            for wait in (
                longest_flood_wait(inner)
                for inner in exc.exceptions
                if inner is not None
            )
            if wait is not None
        ]
        return max(waits) if waits else None
    return _plain_flood_seconds(exc)


def flood_wait_seconds(exc: BaseException) -> float | None:
    """The wait to honour before *replaying* the operation, or None to give up.

    Telethon wraps the failures of any list-form call in MultiError, and
    `delete_messages` chunks its ids, so deleting more than a hundred messages
    is a genuine multi-request batch. Replaying such a batch is only safe when
    nothing in it succeeded and every failure is a flood wait:

    * a partly-successful batch must not be replayed. `delete_message`
      revalidates every id it was given, so after some messages were already
      deleted the retry reports an authorization failure — an alarming and
      wrong description of an irreversible partial deletion.
    * a group mixing a flood wait with a permanent failure must not be replayed
      either, or the permanent failure is retried until the budget runs out and
      is then reported as a rate limit.

    Publishing the cooldown is handled separately by :func:`longest_flood_wait`,
    which has no such restriction.
    """
    if isinstance(exc, errors.MultiError):
        failures = [inner for inner in exc.exceptions if inner is not None]
        if not failures or any(result is not None for result in exc.results):
            return None
        waits = [flood_wait_seconds(inner) for inner in failures]
        if any(wait is None for wait in waits):
            return None
        return max(wait for wait in waits if wait is not None)
    return _plain_flood_seconds(exc)


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
            # Publish first, and decide whether to replay second. A batch that
            # cannot be safely replayed still discovered a real flood wait, and
            # every other queued operation should hold back for it.
            published = longest_flood_wait(exc)
            if published is not None:
                scheduler.note_flood_wait(published)

            seconds = flood_wait_seconds(exc)
            if seconds is None:
                raise

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
            # The retry re-enters tool admission. Its next RPC serves the
            # cooldown, token bucket and pacing gate at the client boundary.
