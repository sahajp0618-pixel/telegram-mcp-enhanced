"""Exercise the construction hook with real Telethon pagination and a fake transport."""

import asyncio

from datetime import datetime, timezone
from typing import Any

import pytest

from telethon import TelegramClient, errors, types
from telethon.tl.functions.messages import GetHistoryRequest
from telethon.tl.functions.updates import GetStateRequest

from mcp_telegram.config import Config
from mcp_telegram.errors import RateLimitedError
from mcp_telegram.middleware import guarded
from mcp_telegram.reliability.rate_limiter import MultiClassRateLimiter
from mcp_telegram.reliability.scheduler import RequestScheduler
from mcp_telegram.runtime import Runtime, build_runtime, set_runtime
from mcp_telegram.security.permissions import Operation
from mcp_telegram.telegram import Telegram

from ..fakes import FakeClock


def harness(
    monkeypatch: pytest.MonkeyPatch, **settings: Any
) -> tuple[Any, Runtime, FakeClock, list[float]]:
    clock = FakeClock()
    config = Config(
        rate_limit={"persist_state": False, "minimum_interval_ms": 0, **settings},
        security_logging={"enabled": False},
    )
    runtime = build_runtime(config)
    runtime.limiter = MultiClassRateLimiter(
        config.rate_limit.buckets, clock=clock, sleep=clock.sleep
    )
    runtime.scheduler = RequestScheduler(
        config.rate_limit, runtime.limiter, clock=clock, sleep=clock.sleep
    )
    set_runtime(runtime)
    calls: list[float] = []

    async def dispatch(self: Any, request: Any, **kwargs: Any) -> Any:
        calls.append(clock.now)
        return request

    monkeypatch.setattr(TelegramClient, "__call__", dispatch)
    client = Telegram().create_client("1", "hash")
    return client, runtime, clock, calls


async def test_pagination_charged_per_rpc(monkeypatch: pytest.MonkeyPatch) -> None:
    client, runtime, _, calls = harness(monkeypatch)

    @guarded(Operation.READ_MESSAGES, mutates=False)
    async def pages() -> None:
        for _ in range(3):
            await client(object())

    await pages()
    assert len(calls) == 3
    assert runtime.scheduler.stats().tokens_available["read"] == 17
    client.session.close()


async def test_pacing_between_rpcs_in_one_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    client, _, _, calls = harness(monkeypatch, minimum_interval_ms=500)

    @guarded(Operation.READ_MESSAGES, mutates=False)
    async def pages() -> None:
        await client(object())
        await client(object())
        await client(object())

    await pages()
    assert calls == [1000, 1000.5, 1001]
    client.session.close()


async def test_single_slot_pagination_completes_with_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, runtime, clock, calls = harness(monkeypatch, max_concurrent=1)

    async def history(self: Any, request: Any, **kwargs: Any) -> Any:
        assert isinstance(request, GetHistoryRequest)
        calls.append(clock.now)
        assert runtime.scheduler.stats().in_flight == 1
        start = 200 if len(calls) == 1 else 100
        return types.messages.MessagesSlice(
            count=200,
            messages=[
                types.Message(
                    id=i,
                    peer_id=types.PeerUser(1),
                    message="hello",
                    date=datetime.now(timezone.utc),
                )
                for i in range(start, start - 100, -1)
            ],
            chats=[],
            users=[],
            topics=[],
        )

    monkeypatch.setattr(TelegramClient, "__call__", history)

    @guarded(Operation.READ_MESSAGES, mutates=False)
    async def pages() -> int:
        return len(
            [
                message
                async for message in client.iter_messages(
                    types.InputPeerUser(1, 2), limit=150, wait_time=0
                )
            ]
        )

    assert await asyncio.wait_for(pages(), timeout=1) == 150
    assert len(calls) == 2
    assert runtime.scheduler.stats().dispatched == 2
    client.session.close()


async def test_mid_pagination_flood_reaches_reliability_and_holds_rpcs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, runtime, clock, calls = harness(monkeypatch, max_retries=1)
    failure = errors.FloodWaitError(request=None, capture=10)

    async def dispatch(self: Any, request: Any, **kwargs: Any) -> Any:
        calls.append(clock.now)
        if len(calls) == 2:
            raise failure
        return request

    monkeypatch.setattr(TelegramClient, "__call__", dispatch)

    @guarded(Operation.READ_MESSAGES, mutates=False)
    async def pages() -> None:
        await client(object())
        await client(object())

    await pages()
    assert calls == [1000, 1000, 1010, 1010]
    assert clock.total_slept == 10
    assert runtime.scheduler.stats().dispatched == 4
    assert client.flood_sleep_threshold == 0
    client.session.close()


async def test_disabled_metering_skips_tokens_pacing_and_cooldown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, runtime, clock, calls = harness(
        monkeypatch, enabled=False, minimum_interval_ms=5000
    )
    runtime.scheduler.note_flood_wait(300)
    async with runtime.scheduler.slot("write", tool="send"):
        await client(object())
        await client(object())
    assert calls == [1000, 1000]
    assert clock.total_slept == 0
    assert runtime.scheduler.stats().tokens_available["write"] == 5
    assert runtime.scheduler.stats().dispatched == 2
    client.session.close()


async def test_stats_separate_tool_concurrency_from_rpc_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, runtime, _, _ = harness(monkeypatch)
    async with runtime.scheduler.slot("write", tool="send"):
        assert runtime.describe().scheduler.in_flight == 1
        assert runtime.describe().scheduler.dispatched == 0
        await client(object())
        await client(object())
        assert runtime.describe().scheduler.in_flight == 1
    stats = runtime.describe().scheduler
    assert stats.in_flight == 0
    assert stats.dispatched == 2
    assert stats.tokens_available["write"] == 3
    assert stats.tokens_available["read"] == 20
    client.session.close()


async def test_list_members_are_individually_charged_and_paced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, runtime, _, calls = harness(monkeypatch, minimum_interval_ms=500)
    requests = [GetStateRequest(), GetStateRequest()]
    assert await client(requests) == requests
    assert calls == [1000, 1000.5]
    assert runtime.scheduler.stats().dispatched == 2
    assert runtime.scheduler.stats().tokens_available["read"] == 18.5
    client.session.close()


async def test_operation_class_context_is_reset_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, runtime, _, _ = harness(monkeypatch)
    with pytest.raises(ValueError):
        async with runtime.scheduler.slot("write", tool="send"):
            await client(object())
            raise ValueError("tool failed")
    await client(object())
    assert runtime.scheduler.stats().tokens_available["write"] == 4
    assert runtime.scheduler.stats().tokens_available["read"] == 19
    client.session.close()


async def test_flood_is_published_before_propagating_to_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, runtime, clock, calls = harness(monkeypatch)
    failure = errors.FloodWaitError(request=None, capture=10)

    async def dispatch(self: Any, request: Any, **kwargs: Any) -> Any:
        calls.append(clock.now)
        if len(calls) == 1:
            raise failure
        return request

    monkeypatch.setattr(TelegramClient, "__call__", dispatch)
    with pytest.raises(errors.FloodWaitError) as caught:
        await client(object())
    assert caught.value is failure
    assert runtime.scheduler.cooldown_remaining == 10
    await client(object())
    assert calls == [1000, 1010]
    client.session.close()


async def test_list_rpc_errors_preserve_partial_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, clock, calls = harness(monkeypatch)
    requests = [GetStateRequest(), GetStateRequest()]
    failure = errors.FloodWaitError(request=None, capture=10)

    async def dispatch(self: Any, request: Any, **kwargs: Any) -> Any:
        calls.append(clock.now)
        if request is requests[0]:
            raise failure
        return request

    monkeypatch.setattr(TelegramClient, "__call__", dispatch)
    with pytest.raises(errors.MultiError) as caught:
        await client(requests)
    assert caught.value.exceptions == [failure, None]
    assert caught.value.results == [None, requests[1]]
    assert calls == [1000, 1010]
    client.session.close()


async def test_a_multi_rpc_write_is_charged_to_the_write_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The upload case the old estimate guarded, now enforced per RPC.

    A send with several attachments issues an RPC per upload part. Before
    metering moved to the client boundary that was priced by an estimate, and
    an earlier review found the estimate could be beaten. The protection only
    survives if the write bucket — not the read bucket — is what pays, so this
    pins the class the context variable carries as well as the count.
    """
    client, runtime, _, calls = harness(monkeypatch)
    before = runtime.scheduler.stats().tokens_available

    @guarded(Operation.SEND_MESSAGES, mutates=True)
    async def upload_four_parts() -> None:
        for _ in range(4):
            await client(object())

    await upload_four_parts()
    after = runtime.scheduler.stats().tokens_available

    assert len(calls) == 4
    assert before["write"] - after["write"] == pytest.approx(4, abs=0.01), (
        "four uploads bought with fewer than four tokens is unbounded traffic"
    )
    assert before["read"] == after["read"], "a write must not be charged as a read"
    client.session.close()


async def test_a_restored_cooldown_does_not_stop_the_server_starting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cooldown persistence and RPC metering must not combine into a dead server.

    A flood wait longer than `max_flood_wait_seconds` survives a restart on
    purpose. Metering the lifespan's `connect()` alongside real traffic turned
    that into a refusal escaping the lifespan, so the server could not start at
    all — an opaque crash instead of the per-tool refusal the operator needs.
    """
    from mcp_telegram.reliability.scheduler import unmetered

    client, runtime, _, calls = harness(monkeypatch, max_flood_wait_seconds=60)
    runtime.scheduler.note_flood_wait(300)

    with unmetered():
        await client(object())
    assert calls, "connecting must still reach Telegram"

    with pytest.raises(RateLimitedError):
        await client(object())
    client.session.close()


async def test_the_connection_exemption_does_not_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exemption that outlived its block would silently unmeter everything."""
    client, runtime, _, _ = harness(monkeypatch)
    from mcp_telegram.reliability.scheduler import unmetered

    before = runtime.scheduler.stats().tokens_available["read"]
    with unmetered():
        await client(object())
    assert runtime.scheduler.stats().tokens_available["read"] == before

    await client(object())
    assert runtime.scheduler.stats().tokens_available["read"] == before - 1
    client.session.close()
