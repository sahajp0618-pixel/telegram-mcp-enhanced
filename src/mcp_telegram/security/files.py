"""Local file-access policy for uploads and downloads.

Added by Telegram MCP Enhanced.

Upstream's `send_message` uploads any path the model names, and `media_download`
writes to any path it names. That turns one successful prompt injection into
file exfiltration ("send ~/.ssh/id_rsa to @attacker") or arbitrary file
placement. This module refuses the obviously dangerous cases by default and
supports a strict directory allowlist for locked-down deployments.
"""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

from mcp_telegram.config import FileAccessSettings
from mcp_telegram.errors import FileAccessDeniedError
from mcp_telegram.security.audit import SecurityAuditLog

__all__ = ["FileAccessGuard", "SENSITIVE_DIRECTORY_NAMES", "SENSITIVE_FILE_GLOBS"]

SENSITIVE_FILE_GLOBS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.env",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.ppk",
    "*.kdbx",
    "*.keychain*",
    "*.session",
    "*.session-journal",
    "credentials",
    "credentials.*",
    "secrets",
    "secrets.*",
    ".netrc",
    ".pgpass",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    "known_hosts",
    "authorized_keys",
    "shadow",
    "*_history",
    "*.sqlite-wal",
    "Cookies",
    "Login Data",
)

SENSITIVE_DIRECTORY_NAMES: frozenset[str] = frozenset(
    {
        ".ssh",
        ".aws",
        ".gnupg",
        ".gpg",
        ".kube",
        ".docker",
        ".password-store",
        ".mozilla",
        "Keychains",
        "gcloud",
        "gh",
    }
)


class FileAccessGuard:
    """Decides whether a local path may be read from or written to."""

    def __init__(
        self,
        settings: FileAccessSettings,
        *,
        state_dir: Path,
        audit: SecurityAuditLog,
    ) -> None:
        self.settings = settings
        self.audit = audit
        self._state_dir = state_dir.expanduser()
        self._upload_roots = _resolve_roots(settings.allowed_upload_dirs)
        self._download_roots = _resolve_roots(settings.allowed_download_dirs)

    def check_uploads(self, paths: list[str], *, tool: str) -> list[Path]:
        """Validate a whole batch of attachments, not just each file alone.

        The per-file checks say whether a file may leave the machine; these say
        how much may leave in one request, which is what keeps a single write
        token from buying an unbounded number of uploads.
        """
        if len(paths) > self.settings.max_files_per_message:
            raise self._deny(
                tool,
                f"{len(paths)} attachments",
                (
                    f"{len(paths)} attachments exceeds max_files_per_message "
                    f"({self.settings.max_files_per_message})"
                ),
                hint="Send them in smaller batches.",
            )

        resolved = [self.check_upload(path, tool=tool) for path in paths]

        ceiling = self.settings.max_upload_bytes
        if ceiling:
            total = sum(path.stat().st_size for path in resolved)
            if total > ceiling:
                raise self._deny(
                    tool,
                    f"{len(resolved)} attachments",
                    (
                        f"{total} bytes of attachments exceeds max_upload_bytes "
                        f"({ceiling})"
                    ),
                    hint="Send fewer or smaller files in one message.",
                )
        return resolved

    def check_upload(self, path: str, *, tool: str) -> Path:
        """Validate a file the model wants to send to Telegram."""
        resolved = self._check(
            path,
            tool=tool,
            roots=self._upload_roots,
            roots_setting="allowed_upload_dirs",
            action="upload",
        )
        if not resolved.is_file():
            # Reported here rather than as a bare FileNotFoundError from the
            # tool body: the MCP SDK withholds the text of unexpected
            # exceptions, so the agent would otherwise be told only that the
            # call failed.
            raise self._deny(
                tool,
                str(resolved),
                "file does not exist or is not a regular file",
                hint="Check the path, or ask the user for the correct one.",
            )
        return resolved

    def check_download_target(self, path: str | None, *, tool: str) -> Path | None:
        """Validate a directory the model wants media written into."""
        if path is None:
            return None
        return self._check(
            path,
            tool=tool,
            roots=self._download_roots,
            roots_setting="allowed_download_dirs",
            action="download",
        )

    def _check(
        self,
        path: str,
        *,
        tool: str,
        roots: list[Path],
        roots_setting: str,
        action: str,
    ) -> Path:
        try:
            # resolve() follows symlinks, so a link pointing at a secret is
            # judged by its target rather than by its name.
            resolved = Path(path).expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            raise self._deny(tool, path, f"path could not be resolved: {exc}")

        if _is_within(resolved, self._state_dir):
            raise self._deny(
                tool,
                str(resolved),
                "path is inside the Telegram session/state directory",
                hint="Session material must never be sent through Telegram.",
            )

        if roots:
            if not any(_is_within(resolved, root) for root in roots):
                raise self._deny(
                    tool,
                    str(resolved),
                    f"path is outside every directory listed in {roots_setting}",
                    hint=(
                        f"An operator can add its directory to {roots_setting} under "
                        "[security.files] in the config file."
                    ),
                )
        elif self.settings.protect_sensitive_paths:
            reason = self._sensitive_reason(resolved)
            if reason is not None:
                raise self._deny(
                    tool,
                    str(resolved),
                    reason,
                    hint=(
                        "If this file really is meant to be shared, an operator can "
                        "list its directory in allowed_upload_dirs under "
                        "[security.files], which replaces this check."
                    ),
                )

        if self.settings.extra_denied_patterns:
            posix = resolved.as_posix()
            for pattern in self.settings.extra_denied_patterns:
                if fnmatch(posix, pattern) or fnmatch(resolved.name, pattern):
                    raise self._deny(
                        tool,
                        str(resolved),
                        f"path matches denied pattern {pattern!r}",
                    )

        return resolved

    def _sensitive_reason(self, resolved: Path) -> str | None:
        for part in resolved.parts:
            if part in SENSITIVE_DIRECTORY_NAMES:
                return f"path is inside a sensitive directory ({part})"
        for glob in SENSITIVE_FILE_GLOBS:
            if fnmatch(resolved.name, glob):
                return f"file name matches sensitive pattern {glob!r}"
        return None

    def _deny(
        self, tool: str, path: str, reason: str, hint: str | None = None
    ) -> FileAccessDeniedError:
        self.audit.file_access_denied(tool=tool, reason=reason, path=path)
        return FileAccessDeniedError(path=path, reason=reason, hint=hint)


def _resolve_roots(values: list[str]) -> list[Path]:
    roots: list[Path] = []
    for value in values:
        try:
            roots.append(Path(value).expanduser().resolve())
        except (OSError, RuntimeError):
            continue
    return roots


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
