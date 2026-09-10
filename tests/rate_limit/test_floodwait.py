"""FloodWait interception and bounded retries (PRD sections 27-29, 44)."""

from __future__ import annotations

import asyncio

import pytest

from telethon import errors  # type: ignore

from mcp_telegram.config import RateLimitSettings, SecurityLoggingSettings
from mcp_telegram.errors import RateLimitedError
from mcp_telegram.reliability.floodwait import (
    flood_wait_seconds,
    run_with_flood_protection,
)
from mcp_telegram.reliability.rate_limiter import MultiClassRateLimiter
from mcp_telegram.reliability.scheduler import RequestScheduler
from mcp_telegram.security.audit import SecurityAuditLog

from ..fakes import FakeClock


def flood(seconds: int) -> errors.FloodWaitError:
    error = errors.FloodWaitError(request=None)
    error.seconds = seconds
    return error


def harness(**settings: object):
    clock = FakeClock()
    resolved = RateLimitSettings(minimum_interval_ms=0, **settings)  # type: ignore[arg-type]
    limiter = MultiClassRateLimiter(resolved.buckets, clock=clock, sleep=clock.sleep)
    scheduler = RequestScheduler(resolved, limiter, clock=clock, sleep=clock.sleep)
    audit = SecurityAuditLog(SecurityLoggingSettings(enabled=False))
    return scheduler, resolved, audit, clock


async def run(operation, scheduler, settings, audit, tool="get_messages"):
    async def rpc_operation():
        await scheduler.meter_rpc()
        return await operation()

    return await run_with_flood_protection(
        rpc_operation,
        scheduler=scheduler,
        operation_class="read",
        settings=settings,
        audit=audit,
        tool=tool,
    )


def test_flood_errors_are_recognised_and_others_are_not() -> None:
    assert flood_wait_seconds(flood(30)) == 30.0
    assert flood_wait_seconds(ValueError("nope")) is None


async def test_a_short_flood_wait_is_absorbed_and_the_call_succeeds() -> None:
    scheduler, settings, audit, clock = harness(
        max_retries=2, max_flood_wait_seconds=60
    )
    attempts = 0

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise flood(20)
        return "ok"

    assert await run(operation, scheduler, settings, audit) == "ok"
    assert attempts == 2
    assert clock.total_slept == pytest.approx(20.0), "it waited exactly what was asked"


async def test_retries_are_bounded_by_configuration() -> None:
    scheduler, settings, audit, _ = harness(max_retries=2, max_flood_wait_seconds=60)
    attempts = 0

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        raise flood(5)

    with pytest.raises(RateLimitedError) as excinfo:
        await run(operation, scheduler, settings, audit)
    assert attempts == 3, "the original attempt plus max_retries"
    assert "max_retries=2" in excinfo.value.payload["reason"]


async def test_zero_retries_reports_immediately() -> None:
    scheduler, settings, audit, clock = harness(max_retries=0)
    attempts = 0

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        raise flood(5)

    with pytest.raises(RateLimitedError):
        await run(operation, scheduler, settings, audit)
    assert attempts == 1
    assert clock.total_slept == 0.0


async def test_an_excessive_wait_is_reported_instead_of_waited_out() -> None:
    scheduler, settings, audit, clock = harness(
        max_retries=5, max_flood_wait_seconds=60
    )

    async def operation() -> str:
        raise flood(3600)

    with pytest.raises(RateLimitedError) as excinfo:
        await run(operation, scheduler, settings, audit)
    payload = excinfo.value.payload
    assert payload["status"] == "rate_limited"
    assert payload["retry_after_seconds"] == 3600
    assert payload["retryable"] is True
    assert "longer than the configured max_flood_wait_seconds" in payload["reason"]
    assert clock.total_slept == 0.0, "the server must not block for an hour"


async def test_the_structured_response_says_it_is_temporary() -> None:
    scheduler, settings, audit, _ = harness(max_retries=0)

    async def operation() -> str:
        raise flood(37)

    with pytest.raises(RateLimitedError) as excinfo:
        await run(operation, scheduler, settings, audit)
    rendered = str(excinfo.value)
    assert "temporary" in rendered
    assert '"retry_after_seconds": 37' in rendered
    assert '"status": "rate_limited"' in rendered


async def test_slow_mode_waits_are_handled_too() -> None:
    scheduler, settings, audit, clock = harness(
        max_retries=1, max_flood_wait_seconds=60
    )
    attempts = 0

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            error = errors.SlowModeWaitError(request=None)
            error.seconds = 8
            raise error
        return "sent"

    assert await run(operation, scheduler, settings, audit) == "sent"
    assert clock.total_slept == pytest.approx(8.0)


async def test_other_telegram_errors_are_not_swallowed() -> None:
    scheduler, settings, audit, _ = harness()

    async def operation() -> str:
        raise ValueError("entity not found")

    with pytest.raises(ValueError, match="entity not found"):
        await run(operation, scheduler, settings, audit)


async def test_parallel_calls_do_not_create_a_retry_storm() -> None:
    """One flood wait must hold back every queued request, not just its own."""
    scheduler, settings, audit, clock = harness(
        max_retries=1, max_flood_wait_seconds=60, max_concurrent=4
    )
    attempts = 0

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise flood(30)
        return "ok"

    results = await asyncio.gather(
        *(run(operation, scheduler, settings, audit) for _ in range(4))
    )
    assert results == ["ok"] * 4
    assert attempts == 5, "one flood wait, then one attempt each"
    assert clock.total_slept == pytest.approx(30.0, abs=1.0), (
        "the cooldown is shared, not paid once per request"
    )


async def test_the_server_survives_a_flood_wait_and_keeps_serving() -> None:
    scheduler, settings, audit, _ = harness(max_retries=1, max_flood_wait_seconds=60)
    state = {"first": True}

    async def flaky() -> str:
        if state["first"]:
            state["first"] = False
            raise flood(1)
        return "ok"

    async def healthy() -> str:
        return "fine"

    first = await run(flaky, scheduler, settings, audit)
    second = await run(healthy, scheduler, settings, audit)
    assert (first, second) == ("ok", "fine")


async def test_flood_events_are_audited(tmp_path) -> None:
    scheduler, settings, _, _ = harness(max_retries=0)
    audit = SecurityAuditLog(
        SecurityLoggingSettings(enabled=True, path=str(tmp_path / "s.log"))
    )

    async def operation() -> str:
        raise flood(9)

    with pytest.raises(RateLimitedError):
        await run(operation, scheduler, settings, audit)
    audit.close()
    contents = (tmp_path / "s.log").read_text()
    assert "flood_wait" in contents
    assert "retries_exhausted" in contents


def _multi(exceptions, results):
    from telethon import errors
    from telethon.tl.functions.updates import GetStateRequest

    return errors.MultiError(
        exceptions, results, [GetStateRequest() for _ in exceptions]
    )


def test_a_wholly_flooded_batch_is_replayable() -> None:
    """`delete_messages` chunks its ids, so a big deletion is a real batch.

    Telethon wraps a list-form call's failures in MultiError. When every member
    flooded and none succeeded, replaying the whole thing is safe and correct.
    """
    from telethon import errors

    from mcp_telegram.reliability.floodwait import flood_wait_seconds

    wrapped = _multi(
        [
            errors.FloodWaitError(request=None, capture=5),
            errors.FloodWaitError(request=None, capture=90),
        ],
        [None, None],
    )
    # The longest wins: satisfying the shortest walks into the next.
    assert flood_wait_seconds(wrapped) == 90.0


def test_a_partly_successful_batch_is_never_replayed() -> None:
    """This is the deletion case, and replaying it is actively harmful.

    `delete_message` revalidates every id before deleting. If one chunk
    succeeded, those messages no longer exist, so the retry reports
    ChatAccessDeniedError — an authorization failure describing an
    irreversible partial deletion.
    """
    from telethon import errors

    from mcp_telegram.reliability.floodwait import flood_wait_seconds

    wrapped = _multi(
        [errors.FloodWaitError(request=None, capture=42), None], [None, "deleted"]
    )
    assert flood_wait_seconds(wrapped) is None


def test_a_batch_mixing_flood_and_permanent_failure_is_not_replayed() -> None:
    """Otherwise the permanent failure is retried, then reported as a rate limit."""
    from telethon import errors

    from mcp_telegram.reliability.floodwait import flood_wait_seconds

    wrapped = _multi(
        [
            errors.FloodWaitError(request=None, capture=42),
            errors.RPCError(request=None, message="boom"),
        ],
        [None, None],
    )
    assert flood_wait_seconds(wrapped) is None


def test_a_cooldown_is_still_published_for_a_batch_that_cannot_be_replayed() -> None:
    """Holding others back is safe even when replaying this one is not."""
    from telethon import errors

    from mcp_telegram.reliability.floodwait import (
        flood_wait_seconds,
        longest_flood_wait,
    )

    wrapped = _multi(
        [errors.FloodWaitError(request=None, capture=42), None], [None, "deleted"]
    )
    assert flood_wait_seconds(wrapped) is None, "must not replay"
    assert longest_flood_wait(wrapped) == 42.0, "but must still hold others back"


def test_a_multierror_without_a_flood_wait_is_not_one() -> None:
    """Otherwise any list-call failure would be treated as retryable."""
    from telethon import errors

    from mcp_telegram.reliability.floodwait import flood_wait_seconds

    wrapped = _multi(
        [errors.RPCError(request=None, message="boom"), None], [None, "ok"]
    )
    assert flood_wait_seconds(wrapped) is None
