"""What must never reach the published repository.

Added by Telegram MCP Enhanced.

`.gitignore` is a default, not a guarantee: `git add -f` overrides it, a
rewritten rule can stop covering what it used to, and neither failure is
visible in a diff. These tests read the *tracked* file list -- what a clone
would actually receive -- and fail the build when something that belongs on the
laptop has crossed into it.

They are deliberately cheap and dependency-free, and skip themselves outside a
git checkout so an installed sdist does not fail on them.
"""

from __future__ import annotations

import re
import subprocess

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def tracked_files() -> list[str]:
    """Every path a fresh clone would receive."""
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("not a git checkout")
    return [line for line in result.stdout.splitlines() if line]


def test_the_local_directory_is_never_tracked() -> None:
    """`local/` is the private half of the working copy. See local/README.md."""
    leaked = [path for path in tracked_files() if path.startswith("local/")]
    assert not leaked, (
        f"files under local/ are tracked and would be published: {leaked}. "
        "Run `git rm --cached` on them; local/ is not for anything public."
    )


def test_the_specification_document_is_not_tracked() -> None:
    """It was purged from history before anything was pushed. Keep it out."""
    leaked = [path for path in tracked_files() if Path(path).name == "PRD.md"]
    assert not leaked, (
        f"PRD.md is tracked again at {leaked}. It was deliberately removed from "
        "history; publishing it should be a decision, not an accident."
    )


def test_no_environment_file_is_tracked() -> None:
    """A committed .env is the most common way a real credential ships."""
    leaked = [
        path
        for path in tracked_files()
        if Path(path).name == ".env" or Path(path).name.startswith(".env.")
    ]
    assert not leaked, f"environment files are tracked: {leaked}"


def test_no_telegram_session_is_tracked() -> None:
    """A session file is the account. It must never be in a repository."""
    leaked = [
        path
        for path in tracked_files()
        if path.endswith((".session", ".session-journal", ".session-wal"))
    ]
    assert not leaked, f"Telegram session files are tracked: {leaked}"


# A real api_hash is 32 hex characters. The corpus and the test suite use
# obvious placeholders, which this deliberately allows: the point is to catch a
# credential pasted in by accident, not to ban the shape outright.
_HEX32 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
_OBVIOUS_PLACEHOLDERS = {
    "0123456789abcdef0123456789abcdef",
    "abcdef0123456789abcdef0123456789",
    "fedcba9876543210fedcba9876543210",
    "deadbeefdeadbeefdeadbeefdeadbeef",
    "deadbeefcafebabefeedface12345678",
    "00000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff",
}
_SKIP_SUFFIXES = (".lock", ".png", ".jpg", ".gif", ".ico", ".woff", ".woff2")


def test_no_credential_shaped_string_is_tracked() -> None:
    """Sweep every tracked text file for something shaped like an api_hash.

    Placeholders used by the suite are allowed by name. Anything else with this
    shape is far more likely to be a pasted credential than a coincidence, and
    is worth a human look even when it turns out to be a checksum.
    """
    findings: list[str] = []
    for path in tracked_files():
        if path.endswith(_SKIP_SUFFIXES):
            continue
        full = REPO_ROOT / path
        if not full.is_file():
            continue
        try:
            text = full.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for match in _HEX32.finditer(text):
            value = match.group(0).lower()
            if value in _OBVIOUS_PLACEHOLDERS:
                continue
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"{path}:{line}: {value}")
    assert not findings, (
        "credential-shaped strings are tracked:\n  "
        + "\n  ".join(findings)
        + "\nIf one is a genuine placeholder, add it to _OBVIOUS_PLACEHOLDERS."
    )


def test_no_private_key_material_is_tracked() -> None:
    """PEM headers are unambiguous; there is no benign reason for one here."""
    markers = ("BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY")
    findings: list[str] = []
    for path in tracked_files():
        if path.endswith(_SKIP_SUFFIXES):
            continue
        full = REPO_ROOT / path
        if not full.is_file():
            continue
        try:
            text = full.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        # This file names the markers it looks for, so it would match itself.
        if full.resolve() == Path(__file__).resolve():
            continue
        for marker in markers:
            if marker in text:
                findings.append(f"{path}: {marker}")
    assert not findings, f"private key material is tracked: {findings}"
