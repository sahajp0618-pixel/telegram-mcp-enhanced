"""Token-bucket behaviour (PRD sections 23, 43)."""

from __future__ import annotations

import asyncio

import pytest

from mcp_telegram.config import BucketSettings
from mcp_telegram.reliability.rate_limiter import MultiClassRateLimiter, TokenBucket

from ..fakes import FakeClock


def bucket(capacity=3, refill_per_minute=60) -> tuple[TokenBucket, FakeClock]:
    clock = FakeClock()
    return (
        TokenBucket(capacity, refill_per_minute, clock=clock, sleep=clock.sleep),
        clock,
    )


async def test_a_burst_up_to_capacity_does_not_wait() -> None:
    limiter, clock = bucket(capacity=3)
    for _ in range(3):
        assert await limiter.acquire() == 0.0
    assert clock.total_slept == 0.0


async def test_the_next_request_waits_for_a_refill() -> None:
    limiter, clock = bucket(capacity=3, refill_per_minute=60)  # one token per second
    for _ in range(3):
        await limiter.acquire()
    waited = await limiter.acquire()
    assert waited == pytest.approx(1.0)
    assert clock.total_slept == pytest.approx(1.0)


async def test_tokens_replenish_over_time() -> None:
    limiter, clock = bucket(capacity=5, refill_per_minute=60)
    for _ in range(5):
        await limiter.acquire()
    assert limiter.available == pytest.approx(0.0)
    clock.now += 3
    assert limiter.available == pytest.approx(3.0)


def test_refill_never_exceeds_capacity() -> None:
    limiter, clock = bucket(capacity=2, refill_per_minute=600)
    clock.now += 3600
    assert limiter.available == 2.0


async def test_rapid_sequential_requests_are_paced_not_dropped() -> None:
    limiter, clock = bucket(capacity=2, refill_per_minute=60)
    for _ in range(6):
        await limiter.acquire()
    # 2 free, then 4 more at one per second
    assert clock.total_slept == pytest.approx(4.0)


async def test_parallel_requests_cannot_exceed_the_budget() -> None:
    limiter, clock = bucket(capacity=2, refill_per_minute=60)
    await asyncio.gather(*(limiter.acquire() for _ in range(5)))
    assert clock.total_slept == pytest.approx(3.0)


async def test_waiters_are_served_in_order() -> None:
    limiter, clock = bucket(capacity=1, refill_per_minute=60)
    order: list[int] = []

    async def take(index: int) -> None:
        await limiter.acquire()
        order.append(index)

    await asyncio.gather(*(take(index) for index in range(4)))
    assert order == [0, 1, 2, 3]


async def test_cancelling_a_waiter_frees_the_bucket() -> None:
    limiter, _ = bucket(capacity=1, refill_per_minute=1)
    await limiter.acquire()
    waiter = asyncio.create_task(limiter.acquire())
    await asyncio.sleep(0)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert not limiter._lock.locked()


async def test_asking_for_more_than_capacity_is_a_programming_error() -> None:
    limiter, _ = bucket(capacity=2)
    with pytest.raises(ValueError, match="capacity"):
        await limiter.acquire(5)


def test_invalid_bucket_settings_are_rejected() -> None:
    with pytest.raises(ValueError):
        TokenBucket(0, 60)
    with pytest.raises(ValueError):
        TokenBucket(1, 0)


async def test_each_operation_class_has_its_own_budget() -> None:
    clock = FakeClock()
    limiter = MultiClassRateLimiter(
        {
            "read": BucketSettings(capacity=2, refill_per_minute=60),
            "write": BucketSettings(capacity=1, refill_per_minute=60),
        },
        clock=clock,
        sleep=clock.sleep,
    )
    await limiter.acquire("read")
    await limiter.acquire("read")
    assert await limiter.acquire("write") == 0.0, "write budget is independent of read"
    assert limiter.snapshot()["read"] == pytest.approx(0.0)


async def test_an_unknown_class_is_not_limited() -> None:
    limiter = MultiClassRateLimiter({})
    assert await limiter.acquire("nonexistent") == 0.0
