"""Shared fixtures for the enhanced test suite.

The XDG state directory is redirected before anything imports the package, so
running the tests never touches a real Telegram session or writes to the
developer's state directory.
"""

from __future__ import annotations

import os
import tempfile

_TEST_STATE_HOME = tempfile.mkdtemp(prefix="mcp-telegram-tests-")
os.environ["XDG_STATE_HOME"] = _TEST_STATE_HOME
os.environ["XDG_CONFIG_HOME"] = os.path.join(_TEST_STATE_HOME, "config")
# Upstream reads these at client creation; tests never connect.
os.environ.setdefault("API_ID", "12345")
os.environ.setdefault("API_HASH", "0123456789abcdef0123456789abcdef")

from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

import pytest  # noqa: E402

from mcp_telegram.config import Config  # noqa: E402
from mcp_telegram.runtime import (  # noqa: E402
    Runtime,
    build_runtime,
    reset_runtime,
    set_runtime,
)

from .fakes import FakeTelegram  # noqa: E402

__all__ = ["FakeTelegram"]


def make_config(tmp_path: Path | None = None, **overrides: Any) -> Config:
    """Build a Config with test-friendly defaults.

    Rate limiting is off unless a test asks for it, so unrelated tests are not
    slowed down by the 500 ms pacing interval.
    """
    data: dict[str, Any] = {
        "rate_limit": {"enabled": False},
        "security_logging": {"enabled": False},
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(data.get(key), dict):
            data[key] = {**data[key], **value}
        else:
            data[key] = value
    if tmp_path is not None and data.get("security_logging", {}).get("enabled"):
        data["security_logging"].setdefault("path", str(tmp_path / "security.log"))
    return Config.model_validate(data)


def install_runtime(config: Config, tmp_path: Path | None = None) -> Runtime:
    """Make ``config`` the process-wide policy for the duration of a test.

    The simulated state directory is a *subdirectory* of ``tmp_path`` so tests
    can still use ``tmp_path`` itself for ordinary files: everything inside the
    state directory is off limits to uploads by design.
    """
    state_directory = None
    if tmp_path is not None:
        state_directory = tmp_path / "state"
        state_directory.mkdir(parents=True, exist_ok=True)
    runtime = build_runtime(config, state_directory=state_directory)
    set_runtime(runtime)
    return runtime


@pytest.fixture(autouse=True)
def _clean_runtime():
    """No test may leak its policy into the next one."""
    reset_runtime()
    yield
    reset_runtime()


@pytest.fixture
def runtime(tmp_path: Path) -> Runtime:
    """A permissive runtime: security layers on, rate limiting off."""
    return install_runtime(make_config(tmp_path), tmp_path)


@pytest.fixture
def fake_tg(monkeypatch: pytest.MonkeyPatch) -> FakeTelegram:
    """Replace the Telegram client wrapper used by the MCP tools."""
    from mcp_telegram import middleware, server

    fake = FakeTelegram()
    monkeypatch.setattr(server, "tg", fake)
    middleware.set_entity_resolver(fake.resolve_peer_id)
    yield fake
    middleware.set_entity_resolver(None)
