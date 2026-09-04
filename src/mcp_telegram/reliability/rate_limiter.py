"""Asynchronous token-bucket rate limiting.

Added by Telegram MCP Enhanced.

An LLM can issue Telegram requests far faster, and far more repetitively, than
a human client ever would. Every Telegram operation started through MCP passes
through one of these buckets first, so an autonomous loop degrades into a queue
instead of a flood.

The clock and sleep function are injectable so tests can be deterministic and
fast.
"""

from __future__ import annotations

import asyncio
import time

from collections.abc import Awaitable, Callable

from mcp_telegram.config import BucketSettings

__all__ = ["MultiClassRateLimiter", "TokenBucket"]

Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]


class TokenBucket:
    """A single asyncio-friendly token bucket.

    Waiters hold the internal lock while sleeping, which makes them FIFO and
    stops a thundering herd from all waking to find the bucket empty again.
    """

    def __init__(
        self,
        capacity: float,
        refill_per_minute: float,
        *,
        clock: Clock = time.monotonic,
        sleep: Sleeper = asyncio.sleep,
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_per_minute <= 0:
            raise ValueError("refill_per_minute must be positive")
        self.capacity = float(capacity)
        self.refill_per_second = float(refill_per_minute) / 60.0
        self._clock = clock
        self._sleep = sleep
        self._tokens = float(capacity)
        self._updated = clock()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(
                self.capacity, self._tokens + elapsed * self.refill_per_second
            )
            self._updated = now

    @property
    def available(self) -> float:
        self._refill()
        return self._tokens

    async def acquire(self, tokens: float = 1.0) -> float:
        """Take ``tokens`` from the bucket, waiting if necessary.

        Returns the number of seconds spent waiting.
        """
        if tokens > self.capacity:
            raise ValueError(
                f"cannot acquire {tokens} tokens from a bucket of capacity "
                f"{self.capacity}"
            )
        waited = 0.0
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return waited
                delay = (tokens - self._tokens) / self.refill_per_second
                waited += delay
                await self._sleep(delay)


class MultiClassRateLimiter:
    """One bucket per operation class (read, search, write, media, admin)."""

    def __init__(
        self,
        buckets: dict[str, BucketSettings],
        *,
        clock: Clock = time.monotonic,
        sleep: Sleeper = asyncio.sleep,
    ) -> None:
        self._buckets = {
            name: TokenBucket(
                settings.capacity,
                settings.refill_per_minute,
                clock=clock,
                sleep=sleep,
            )
            for name, settings in buckets.items()
        }

    def bucket(self, name: str) -> TokenBucket | None:
        return self._buckets.get(name)

    async def acquire(self, name: str, tokens: float = 1.0) -> float:
        bucket = self._buckets.get(name)
        if bucket is None:
            return 0.0
        return await bucket.acquire(tokens)

    def snapshot(self) -> dict[str, float]:
        return {
            name: round(bucket.available, 2) for name, bucket in self._buckets.items()
        }
