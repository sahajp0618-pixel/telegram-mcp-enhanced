"""Local file-access policy (added by Telegram MCP Enhanced)."""

from __future__ import annotations

import pytest

from mcp_telegram.errors import FileAccessDeniedError

from ..conftest import install_runtime, make_config


@pytest.fixture
def guard(tmp_path):
    runtime = install_runtime(make_config(tmp_path), tmp_path)
    return runtime.files


SENSITIVE_NAMES = [
    ".env",
    "id_rsa",
    "id_ed25519",
    "server.pem",
    "private.key",
    "credentials",
    ".netrc",
    ".git-credentials",
    "vault.kdbx",
    "account.session",
    ".bash_history",
]


@pytest.mark.parametrize("name", SENSITIVE_NAMES)
def test_sensitive_files_cannot_be_uploaded(guard, tmp_path, name: str) -> None:
    target = tmp_path / name
    target.write_text("secret")
    with pytest.raises(FileAccessDeniedError) as excinfo:
        guard.check_upload(str(target), tool="send_message")
    assert excinfo.value.details["reason"]


def test_files_in_sensitive_directories_cannot_be_uploaded(guard, tmp_path) -> None:
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    target = ssh / "config"
    target.write_text("Host *")
    with pytest.raises(FileAccessDeniedError, match="not permitted"):
        guard.check_upload(str(target), tool="send_message")


def test_a_symlink_is_judged_by_its_target(guard, tmp_path) -> None:
    """Renaming a secret must not get it past the policy."""
    secret = tmp_path / "id_rsa"
    secret.write_text("PRIVATE KEY")
    link = tmp_path / "holiday-photo.png"
    link.symlink_to(secret)
    with pytest.raises(FileAccessDeniedError):
        guard.check_upload(str(link), tool="send_message")


def test_the_session_directory_is_always_off_limits(tmp_path) -> None:
    runtime = install_runtime(make_config(tmp_path), tmp_path)
    session = tmp_path / "state" / "session.session"
    session.write_text("data")
    with pytest.raises(FileAccessDeniedError, match="not permitted") as excinfo:
        runtime.files.check_upload(str(session), tool="send_message")
    assert "session/state directory" in excinfo.value.details["reason"]


def test_an_upload_allowlist_cannot_re_expose_the_session_directory(tmp_path) -> None:
    """The state directory is denied even if an operator allows it."""
    state = tmp_path / "state"
    runtime = install_runtime(
        make_config(tmp_path, files={"allowed_upload_dirs": [str(state)]}), tmp_path
    )
    session = state / "session.session"
    session.write_text("data")
    with pytest.raises(FileAccessDeniedError):
        runtime.files.check_upload(str(session), tool="send_message")


def test_ordinary_files_are_allowed(guard, tmp_path) -> None:
    document = tmp_path / "report.pdf"
    document.write_text("report")
    assert guard.check_upload(str(document), tool="send_message").name == "report.pdf"


def test_upload_allowlist_replaces_the_default_checks(tmp_path) -> None:
    outbox = tmp_path / "outbox"
    outbox.mkdir()
    allowed = outbox / "invoice.pdf"
    allowed.write_text("x")
    elsewhere = tmp_path / "other.pdf"
    elsewhere.write_text("x")

    runtime = install_runtime(
        make_config(tmp_path, files={"allowed_upload_dirs": [str(outbox)]}), tmp_path
    )
    assert runtime.files.check_upload(str(allowed), tool="send_message")
    with pytest.raises(FileAccessDeniedError, match="not permitted"):
        runtime.files.check_upload(str(elsewhere), tool="send_message")


def test_extra_denied_patterns_are_applied(tmp_path) -> None:
    runtime = install_runtime(
        make_config(tmp_path, files={"extra_denied_patterns": ["*.docx"]}), tmp_path
    )
    document = tmp_path / "contract.docx"
    document.write_text("x")
    with pytest.raises(FileAccessDeniedError, match="not permitted"):
        runtime.files.check_upload(str(document), tool="send_message")


def test_protection_can_be_switched_off(tmp_path) -> None:
    runtime = install_runtime(
        make_config(tmp_path, files={"protect_sensitive_paths": False}), tmp_path
    )
    secret = tmp_path / ".env"
    secret.write_text("API_HASH=x")
    assert runtime.files.check_upload(str(secret), tool="send_message")


def test_download_targets_are_checked_too(tmp_path) -> None:
    runtime = install_runtime(
        make_config(tmp_path, files={"allowed_download_dirs": [str(tmp_path / "dl")]}),
        tmp_path,
    )
    (tmp_path / "dl").mkdir()
    assert runtime.files.check_download_target(
        str(tmp_path / "dl"), tool="media_download"
    )
    with pytest.raises(FileAccessDeniedError):
        runtime.files.check_download_target("/etc", tool="media_download")


def test_denials_are_written_to_the_security_log(tmp_path) -> None:
    runtime = install_runtime(
        make_config(tmp_path, security_logging={"enabled": True}), tmp_path
    )
    secret = tmp_path / "id_rsa"
    secret.write_text("x")
    with pytest.raises(FileAccessDeniedError):
        runtime.files.check_upload(str(secret), tool="send_message")
    runtime.audit.close()
    assert "file_access_denied" in runtime.audit.path.read_text()


def test_a_missing_file_is_reported_clearly(guard, tmp_path) -> None:
    with pytest.raises(FileAccessDeniedError) as excinfo:
        guard.check_upload(str(tmp_path / "nope.pdf"), tool="send_message")
    assert "does not exist" in excinfo.value.details["reason"]


def test_a_directory_cannot_be_uploaded(guard, tmp_path) -> None:
    folder = tmp_path / "folder"
    folder.mkdir()
    with pytest.raises(FileAccessDeniedError, match="not permitted"):
        guard.check_upload(str(folder), tool="send_message")


def test_a_download_target_need_not_exist_yet(guard, tmp_path) -> None:
    """Telethon creates the file; only the location is policed."""
    assert guard.check_download_target(str(tmp_path / "new"), tool="media_download")
