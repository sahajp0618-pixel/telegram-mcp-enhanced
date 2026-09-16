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
    """Every path a fresh clone would receive.

    `-z` is not optional. Without it git *quotes* any path containing non-ASCII
    or control characters -- `local/notes\303\251.md` comes back wrapped in
    quotes and backslash-escaped. That form starts with `"`, so it fails a
    `local/` prefix test, and it names no file on disk, so a content scanner
    opens nothing and reports clean. A review reproduced exactly that bypass.
    """
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("not a git checkout")
    raw = result.stdout.decode("utf-8", errors="surrogateescape")
    return [entry for entry in raw.split("\0") if entry]


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


# Every PEM spelling of a private key, not just the two most familiar ones. A
# review generated a PKCS#8 Ed25519 key and walked it past the original check.
PRIVATE_KEY_MARKERS = (
    "BEGIN PRIVATE KEY",  # PKCS#8, covers Ed25519 and modern OpenSSL output
    "BEGIN ENCRYPTED PRIVATE KEY",  # PKCS#8, passphrase-protected
    "BEGIN RSA PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PGP PRIVATE KEY BLOCK",
)


def test_no_private_key_material_is_tracked() -> None:
    """PEM headers are unambiguous; there is no benign reason for one here."""
    markers = PRIVATE_KEY_MARKERS
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


def test_the_private_key_guard_covers_every_pem_spelling() -> None:
    """A guard that names only the familiar formats is worse than none.

    `BEGIN PRIVATE KEY` is what OpenSSL writes by default and what an Ed25519
    key looks like; omitting it meant the common case walked straight past.
    """
    for algorithm in (
        "PRIVATE",
        "ENCRYPTED PRIVATE",
        "RSA PRIVATE",
        "DSA PRIVATE",
        "EC PRIVATE",
        "OPENSSH PRIVATE",
    ):
        header = f"-----BEGIN {algorithm} KEY-----"
        assert any(marker in header for marker in PRIVATE_KEY_MARKERS), (
            f"{header} would not be detected"
        )


def test_tracked_paths_survive_a_quoted_filename() -> None:
    """The NUL-separated listing must return usable paths, not git's quoting.

    If this ever returns something starting with a quote, every prefix check
    below it is comparing against the wrong string.
    """
    paths = tracked_files()
    assert paths, "no tracked files; the guards would all pass vacuously"
    assert not any(path.startswith('"') for path in paths), (
        "paths came back in git's quoted form; -z was dropped somewhere"
    )
    # Sanity: the listing names real files, so content scanners can open them.
    assert (REPO_ROOT / paths[0]).exists()
