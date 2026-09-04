"""Request scheduling, pacing and concurrency protection (PRD sections 25-31, 43)."""

from __future__ import annotations

import asyncio
import time

import pytest

from mcp_telegram.config import RateLimitSettings
from mcp_telegram.errors import RateLimitedError
from mcp_telegram.reliability.rate_limiter import MultiClassRateLimiter
from mcp_telegram.reliability.scheduler import RequestScheduler

from ..fakes import FakeClock


def scheduler(**settings: object) -> tuple[RequestScheduler, FakeClock]:
    clock = FakeClock()
    resolved = RateLimitSettings(**settings)  # type: ignore[arg-type]
    limiter = MultiClassRateLimiter(resolved.buckets, clock=clock, sleep=clock.sleep)
    return (
        RequestScheduler(resolved, limiter, clock=clock, sleep=clock.sleep),
        clock,
    )


async def test_requests_are_spaced_by_the_minimum_interval() -> None:
    sched, clock = scheduler(minimum_interval_ms=500)
    start = clock.now
    for _ in range(3):
        async with sched.slot("read", tool="get_messages"):
            pass
    assert clock.now - start == pytest.approx(1.0), "two gaps of 500 ms"


async def test_the_interval_is_configurable() -> None:
    sched, clock = scheduler(minimum_interval_ms=2000)
    for _ in range(2):
        async with sched.slot("read", tool="get_messages"):
            pass
    assert clock.total_slept == pytest.approx(2.0)


async def test_spacing_can_be_switched_off() -> None:
    sched, clock = scheduler(minimum_interval_ms=0)
    for _ in range(5):
        async with sched.slot("read", tool="get_messages"):
            pass
    assert clock.total_slept == 0.0


async def test_parallel_requests_cannot_bypass_pacing() -> None:
    sched, clock = scheduler(minimum_interval_ms=500, max_concurrent=4)

    async def call() -> None:
        async with sched.slot("read", tool="get_messages"):
            pass

    await asyncio.gather(*(call() for _ in range(4)))
    assert clock.now >= 1000.0 + 1.5, "four calls need three 500 ms gaps"


async def test_concurrency_is_capped() -> None:
    sched, _ = scheduler(minimum_interval_ms=0, max_concurrent=2)
    live = 0
    peak = 0

    async def call() -> None:
        nonlocal live, peak
        async with sched.slot("read", tool="get_messages"):
            live += 1
            peak = max(peak, live)
            await asyncio.sleep(0.01)
            live -= 1

    await asyncio.gather(*(call() for _ in range(6)))
    assert peak <= 2


async def test_a_full_queue_reports_a_temporary_rate_limit() -> None:
    sched, _ = scheduler(
        minimum_interval_ms=0, max_concurrent=1, queue_timeout_seconds=0.05
    )

    async def hold() -> None:
        async with sched.slot("read", tool="get_messages"):
            await asyncio.sleep(0.3)

    holder = asyncio.create_task(hold())
    await asyncio.sleep(0.01)
    with pytest.raises(RateLimitedError) as excinfo:
        async with sched.slot("read", tool="get_messages"):
            pass
    assert excinfo.value.payload["retryable"] is True
    assert excinfo.value.payload["scope"] == "scheduler"
    await holder


async def test_a_cancelled_request_releases_its_slot() -> None:
    sched, _ = scheduler(minimum_interval_ms=0, max_concurrent=1)

    async def call() -> None:
        async with sched.slot("read", tool="get_messages"):
            await asyncio.sleep(5)

    task = asyncio.create_task(call())
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    async with sched.slot("read", tool="get_messages"):
        pass  # the slot is available again
    assert sched.stats().in_flight == 0


async def test_disabling_rate_limiting_removes_all_waiting() -> None:
    sched, clock = scheduler(enabled=False, minimum_interval_ms=5000)
    for _ in range(10):
        async with sched.slot("write", tool="send_message"):
            pass
    assert clock.total_slept == 0.0


async def test_a_flood_wait_holds_back_every_queued_operation() -> None:
    sched, clock = scheduler(minimum_interval_ms=0, max_flood_wait_seconds=60)
    sched.note_flood_wait(30)
    async with sched.slot("read", tool="get_messages"):
        pass
    assert clock.total_slept == pytest.approx(30.0)


async def test_a_cooldown_longer_than_allowed_fails_fast() -> None:
    sched, clock = scheduler(minimum_interval_ms=0, max_flood_wait_seconds=10)
    sched.note_flood_wait(300)
    with pytest.raises(RateLimitedError) as excinfo:
        async with sched.slot("read", tool="get_messages"):
            pass
    assert excinfo.value.payload["scope"] == "telegram"
    assert excinfo.value.payload["retry_after_seconds"] == pytest.approx(300, abs=1)
    assert clock.total_slept == 0.0, "it reports instead of blocking"


async def test_the_longest_cooldown_wins() -> None:
    sched, _ = scheduler()
    sched.note_flood_wait(30)
    sched.note_flood_wait(5)
    assert sched.cooldown_remaining == pytest.approx(30, abs=0.01)


async def test_statistics_are_reported_for_observability() -> None:
    sched, _ = scheduler(minimum_interval_ms=0)
    async with sched.slot("read", tool="get_messages"):
        pass
    stats = sched.stats()
    assert stats.dispatched == 1
    assert stats.in_flight == 0
    assert "read" in stats.tokens_available


async def test_the_event_loop_stays_responsive_while_throttled() -> None:
    """Waiting must never block the loop: no time.sleep anywhere."""
    settings = RateLimitSettings(minimum_interval_ms=120, max_concurrent=1)
    sched = RequestScheduler(settings, MultiClassRateLimiter(settings.buckets))
    ticks = 0

    async def heartbeat() -> None:
        nonlocal ticks
        for _ in range(20):
            await asyncio.sleep(0.01)
            ticks += 1

    async def throttled() -> None:
        for _ in range(3):
            async with sched.slot("read", tool="get_messages"):
                pass

    started = time.monotonic()
    await asyncio.gather(heartbeat(), throttled())
    assert time.monotonic() - started >= 0.24
    assert ticks == 20, "the heartbeat kept running while requests were paced"
