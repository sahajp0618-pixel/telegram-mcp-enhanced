"""Restarts must preserve enforcement without persisting request context."""

from pathlib import Path

import pytest

from mcp_telegram.config import RateLimitSettings, state_dir
from mcp_telegram.errors import RateLimitedError
from mcp_telegram.reliability.rate_limiter import MultiClassRateLimiter
from mcp_telegram.reliability.scheduler import RequestScheduler
from mcp_telegram.reliability.state import ReliabilityState, STATE_FILE

from ..fakes import FakeClock


def restart(
    wall: FakeClock, *, persist: bool = True
) -> tuple[RequestScheduler, FakeClock]:
    """Use a new monotonic epoch so accidentally persisted monotonic time fails."""
    clock = FakeClock()
    clock.now = 17
    settings = RateLimitSettings(persist_state=persist, minimum_interval_ms=0)
    limiter = MultiClassRateLimiter(settings.buckets, clock=clock, sleep=clock.sleep)
    return RequestScheduler(
        settings,
        limiter,
        clock=clock,
        sleep=clock.sleep,
        wall_clock=wall,
    ), clock


async def charge(scheduler: RequestScheduler, cost: float = 1) -> None:
    async with scheduler.slot("read", tool="get_messages", cost=cost):
        pass


async def test_state_survives_restart() -> None:
    wall = FakeClock()
    first, _ = restart(wall)
    await charge(first, 20)
    second, clock = restart(wall)
    assert second.limiter.snapshot()["read"] == 0
    await charge(second)
    assert clock.total_slept == pytest.approx(1)


@pytest.mark.parametrize("elapsed, expected", [(3, 3), (1000, 20), (-10, 0)])
async def test_refill_across_restart(elapsed: float, expected: float) -> None:
    wall = FakeClock()
    first, _ = restart(wall)
    await charge(first, 20)
    wall.now += elapsed
    second, _ = restart(wall)
    assert second.limiter.snapshot()["read"] == expected


async def test_future_cooldown_is_honoured() -> None:
    wall = FakeClock()
    first, _ = restart(wall)
    first.note_flood_wait(300)
    wall.now += 250
    second, clock = restart(wall)
    await charge(second)
    assert clock.total_slept == pytest.approx(50)


async def test_long_cooldown_still_refuses_after_restart() -> None:
    wall = FakeClock()
    first, _ = restart(wall)
    first.note_flood_wait(300)
    second, clock = restart(wall)
    with pytest.raises(RateLimitedError):
        await charge(second)
    assert clock.total_slept == 0


async def test_expired_cooldown_is_discarded() -> None:
    wall = FakeClock()
    first, _ = restart(wall)
    first.note_flood_wait(300)
    wall.now += 301
    second, clock = restart(wall)
    assert second.cooldown_remaining == 0
    await charge(second)
    assert clock.total_slept == 0


@pytest.mark.parametrize(
    "contents",
    [
        "",
        "garbage",
        '{"version":1',
        "{}",
        '{"version":2,"saved_at":1000,"buckets":{},"cooldown_until":null}',
        '{"version":1,"saved_at":1000,"buckets":{"read":NaN},"cooldown_until":null}',
    ],
)
def test_invalid_state_starts_fresh(
    contents: str, caplog: pytest.LogCaptureFixture
) -> None:
    state_dir().mkdir(parents=True)
    (state_dir() / STATE_FILE).write_text(contents)
    scheduler, _ = restart(FakeClock())
    assert scheduler.limiter.snapshot()["read"] == 20
    assert scheduler.cooldown_remaining == 0
    assert "starting with fresh limits" in caplog.text


def test_unreadable_state_starts_fresh(caplog: pytest.LogCaptureFixture) -> None:
    (state_dir() / STATE_FILE).mkdir(parents=True)
    scheduler, _ = restart(FakeClock())
    assert scheduler.limiter.snapshot()["read"] == 20
    assert "starting with fresh limits" in caplog.text


async def test_disabled_persistence_neither_reads_nor_writes() -> None:
    wall = FakeClock()
    first, _ = restart(wall, persist=False)
    await charge(first)
    first.note_flood_wait(300)
    path = state_dir() / STATE_FILE
    assert not path.exists()
    enabled, _ = restart(wall)
    enabled.note_flood_wait(300)
    contents = path.read_bytes()
    disabled, _ = restart(wall, persist=False)
    assert disabled.cooldown_remaining == 0
    await charge(disabled)
    assert path.read_bytes() == contents


async def test_atomic_write_failure_preserves_previous_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    scheduler, _ = restart(FakeClock())
    await charge(scheduler)
    path = state_dir() / STATE_FILE
    previous = path.read_bytes()

    def fail_replace(source: Path, destination: Path) -> None:
        assert source.parent == destination.parent
        ReliabilityState.model_validate_json(source.read_bytes())
        raise OSError("simulated interrupted replacement")

    monkeypatch.setattr("mcp_telegram.reliability.state.os.replace", fail_replace)
    await charge(scheduler)
    assert path.read_bytes() == previous
    assert not list(state_dir().glob("*.tmp"))
    assert "restart protection unavailable" in caplog.text


async def test_snapshot_has_only_documented_fields() -> None:
    scheduler, _ = restart(FakeClock())
    await charge(scheduler)
    state = ReliabilityState.model_validate_json(
        (state_dir() / STATE_FILE).read_bytes()
    )
    assert set(state.model_dump()) == {
        "version",
        "saved_at",
        "buckets",
        "cooldown_until",
    }
    assert set(state.buckets) == {"read", "search", "write", "media", "admin"}
