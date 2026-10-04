"""Session hardening (roadmap item 11).

Nothing here connects to Telegram. Sessions are built locally from a made-up
auth key, which is all a session file holds before a client uses it.
"""

from __future__ import annotations

import os
import stat
import sys
import types as pytypes

from pathlib import Path
from typing import Any

import pytest

from telethon.crypto import AuthKey
from telethon.sessions import SQLiteSession, StringSession
from typer.testing import CliRunner
from xdg_base_dirs import xdg_state_home

import mcp_telegram.telegram as telegram_module

from mcp_telegram.cli import app
from mcp_telegram.config import SessionSettings
from mcp_telegram.telegram import KeyringUnavailableError, Telegram

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def seeded(session: Any) -> Any:
    session.set_dc(2, "149.154.167.51", 443)
    session.auth_key = AuthKey(bytes(range(256)))
    return session


class FakeKeyring:
    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, value: str) -> None:
        self.store[(service, username)] = value

    def delete_password(self, service: str, username: str) -> None:
        del self.store[(service, username)]


@pytest.fixture
def keyring(monkeypatch) -> FakeKeyring:
    fake = FakeKeyring()
    module = pytypes.ModuleType("keyring")
    for name in ("get_password", "set_password", "delete_password"):
        setattr(module, name, getattr(fake, name))
    monkeypatch.setitem(sys.modules, "keyring", module)
    return fake


@pytest.fixture
def keyring_config(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "config.toml"
    path.write_text('[session]\nstorage = "keyring"\n', encoding="utf-8")
    monkeypatch.setenv("TELEGRAM_MCP_CONFIG", str(path))
    return path


# -- file permissions -------------------------------------------------------- #


@posix_only
def test_state_and_download_directories_are_owner_only() -> None:
    root = xdg_state_home() / "mcp-telegram"
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o755)
    Telegram(SessionSettings())
    assert mode(root) == 0o700
    assert mode(root / "downloads") == 0o700


@posix_only
def test_existing_session_files_are_tightened() -> None:
    telegram = Telegram(SessionSettings())
    primary = telegram.session_file.with_suffix(".session")
    journal = primary.with_name(primary.name + "-journal")
    for path in (primary, journal):
        path.write_bytes(b"x")
        path.chmod(0o644)
    telegram.harden_session_files()
    assert mode(primary) == 0o600
    assert mode(journal) == 0o600


@posix_only
async def test_a_new_client_leaves_its_session_owner_only(monkeypatch) -> None:
    monkeypatch.setattr(os, "umask", os.umask)  # restored by monkeypatch
    previous = os.umask(0o022)
    try:
        telegram = Telegram(SessionSettings())
        telegram.create_client()
        primary = telegram.session_file.with_suffix(".session")
        assert primary.exists()
        assert mode(primary) == 0o600
    finally:
        os.umask(previous)


def test_a_chmod_failure_is_logged_not_fatal(monkeypatch, caplog) -> None:
    telegram = Telegram(SessionSettings())
    primary = telegram.session_file.with_suffix(".session")
    primary.write_bytes(b"x")
    primary.chmod(0o644)

    def refuse(self, *args: Any, **kwargs: Any) -> None:
        raise PermissionError("read-only filesystem")

    monkeypatch.setattr(Path, "chmod", refuse)
    telegram.harden_session_files()
    assert "Could not restrict permissions" in caplog.text


# -- keyring storage --------------------------------------------------------- #


async def test_keyring_storage_loads_the_stored_session(keyring) -> None:
    value = seeded(StringSession()).save()
    keyring.store[("telegram-mcp-enhanced", "session")] = value
    telegram = Telegram(SessionSettings(storage="keyring"))
    client = telegram.create_client()
    assert isinstance(client.session, StringSession)
    assert client.session.save() == value
    # No SQLite file is created for a keyring session.
    assert telegram.session_files() == []


async def test_keyring_storage_writes_the_session_back(keyring) -> None:
    telegram = Telegram(
        SessionSettings(storage="keyring", keyring_service="svc", keyring_username="u")
    )
    client = telegram.create_client()
    seeded(client.session)
    telegram.persist_session()
    assert keyring.store[("svc", "u")] == client.session.save()


async def test_an_empty_session_is_not_written_to_the_keyring(keyring) -> None:
    telegram = Telegram(SessionSettings(storage="keyring"))
    telegram.create_client()
    telegram.persist_session()
    assert keyring.store == {}


async def test_keyring_storage_without_the_package_says_how_to_fix_it(
    monkeypatch,
) -> None:
    monkeypatch.setitem(sys.modules, "keyring", None)
    telegram = Telegram(SessionSettings(storage="keyring"))
    with pytest.raises(KeyringUnavailableError, match=r"\[keyring\]"):
        telegram.create_client()


async def test_a_keyring_write_failure_does_not_echo_the_session(
    keyring, caplog
) -> None:
    telegram = Telegram(SessionSettings(storage="keyring"))
    client = telegram.create_client()
    seeded(client.session)
    secret = client.session.save()

    def broken(service: str, username: str, value: str) -> None:
        raise RuntimeError(f"backend rejected {value}")

    sys.modules["keyring"].set_password = broken  # type: ignore[attr-defined]
    telegram.persist_session()
    assert "RuntimeError" in caplog.text
    assert secret not in caplog.text


# -- migration and clearing -------------------------------------------------- #


def make_file_session() -> tuple[Path, str]:
    telegram = Telegram(SessionSettings())
    sqlite = seeded(SQLiteSession(str(telegram.session_file)))
    sqlite.save()
    expected = StringSession.save(sqlite)
    sqlite.close()
    return telegram.session_file.with_suffix(".session"), expected


def test_migrate_session_copies_then_optionally_deletes(keyring, monkeypatch) -> None:
    monkeypatch.delenv("TELEGRAM_MCP_CONFIG", raising=False)
    primary, expected = make_file_session()
    result = CliRunner().invoke(app, ["migrate-session"])
    assert result.exit_code == 0, result.output
    assert keyring.store[("telegram-mcp-enhanced", "session")] == expected
    assert primary.exists()
    assert expected not in result.output

    result = CliRunner().invoke(app, ["migrate-session", "--delete-file"])
    assert result.exit_code == 0, result.output
    assert not primary.exists()


def test_migrate_session_without_a_login_changes_nothing(keyring) -> None:
    result = CliRunner().invoke(app, ["migrate-session", "--delete-file"])
    assert result.exit_code == 1
    assert keyring.store == {}


def test_migrate_session_keeps_the_file_if_the_keyring_fails(
    keyring, monkeypatch
) -> None:
    primary, expected = make_file_session()

    def broken(service: str, username: str, value: str) -> None:
        raise RuntimeError(f"denied {value}")

    sys.modules["keyring"].set_password = broken  # type: ignore[attr-defined]
    result = CliRunner().invoke(app, ["migrate-session", "--delete-file"])
    assert result.exit_code == 1
    assert primary.exists()
    assert expected not in result.output
    assert "RuntimeError" in result.output


def test_clear_session_removes_the_keyring_entry(keyring, keyring_config) -> None:
    keyring.store[("telegram-mcp-enhanced", "session")] = "1abc"
    result = CliRunner().invoke(app, ["clear-session"])
    assert result.exit_code == 0, result.output
    assert keyring.store == {}
    assert "keyring" in result.output


def test_the_session_is_written_back_on_shutdown(monkeypatch) -> None:
    """The lifespan saves before disconnecting, so auth changes survive."""
    import inspect

    from mcp_telegram import server

    source = inspect.getsource(server.app_lifespan)
    assert source.index("tg.persist_session()") < source.index("tg.client.disconnect()")
    assert "harden_session_files" in source
    assert telegram_module.PRIVATE_FILE_MODE == 0o600


def test_clear_session_still_deletes_the_file_when_config_is_broken(
    tmp_path, monkeypatch
) -> None:
    """A broken config must not leave the credential on disk."""
    broken = tmp_path / "broken.toml"
    broken.write_text("[permissions]\nallow_send = 'perhaps'\n", encoding="utf-8")
    monkeypatch.setenv("TELEGRAM_MCP_CONFIG", str(broken))
    telegram = Telegram(SessionSettings())
    primary = telegram.session_file.with_suffix(".session")
    primary.write_bytes(b"session")
    result = CliRunner().invoke(app, ["clear-session"])
    assert not primary.exists()
    # Not confirmed complete: a keyring entry may still exist.
    assert result.exit_code == 1
    assert "Keyring not checked" in result.output
