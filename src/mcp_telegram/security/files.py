"""Local file-access policy for uploads and downloads.

Added by Telegram MCP Enhanced.

Upstream's `send_message` uploads any path the model names, and `media_download`
writes to any path it names. That turns one successful prompt injection into
file exfiltration ("send ~/.ssh/id_rsa to @attacker") or arbitrary file
placement. This module refuses the obviously dangerous cases by default and
supports a strict directory allowlist for locked-down deployments.
"""

from __future__ import annotations

import mimetypes

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import NoReturn

from mcp_telegram.config import FileAccessSettings
from mcp_telegram.errors import AttachmentRejectedError, FileAccessDeniedError
from mcp_telegram.security.audit import SecurityAuditLog
from mcp_telegram.types import AttachmentInspection, DownloadedMedia, Media

__all__ = [
    "EXECUTABLE_EXTENSIONS",
    "FileAccessGuard",
    "InspectedDownload",
    "SENSITIVE_DIRECTORY_NAMES",
    "SENSITIVE_FILE_GLOBS",
    "detect_type",
]

EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe", ".com", ".bat", ".cmd", ".scr", ".pif", ".msi", ".msp", ".dll",
        ".cpl", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".hta", ".jar", ".app", ".dmg", ".pkg", ".sh", ".bash", ".zsh",
        ".command", ".apk", ".deb", ".rpm", ".run", ".bin", ".lnk", ".reg",
        ".appimage", ".elf", ".so", ".dylib", ".gadget", ".msix", ".appx",
    }
)  # fmt: skip
"""Extensions an operating system will run, or hand to something that will."""

_EXECUTABLE_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "application/x-msdownload"),
    (b"\x7fELF", "application/x-elf"),
    (b"\xfe\xed\xfa\xce", "application/x-mach-binary"),
    (b"\xfe\xed\xfa\xcf", "application/x-mach-binary"),
    (b"\xce\xfa\xed\xfe", "application/x-mach-binary"),
    (b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
    # Also a Java class file; both are code, and both are refused.
    (b"\xca\xfe\xba\xbe", "application/x-mach-binary"),
    (b"#!", "text/x-shellscript"),
)

_MAGIC: tuple[tuple[int, bytes, str], ...] = (
    (0, b"\x89PNG\r\n\x1a\n", "image/png"),
    (0, b"\xff\xd8\xff", "image/jpeg"),
    (0, b"GIF87a", "image/gif"),
    (0, b"GIF89a", "image/gif"),
    (0, b"%PDF-", "application/pdf"),
    (0, b"PK\x03\x04", "application/zip"),
    (0, b"\x1f\x8b", "application/gzip"),
    (0, b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (0, b"Rar!\x1a\x07", "application/vnd.rar"),
    (0, b"OggS", "audio/ogg"),
    (0, b"\x1a\x45\xdf\xa3", "video/webm"),
    (0, b"ID3", "audio/mpeg"),
    (0, b"II*\x00", "image/tiff"),
    (0, b"MM\x00*", "image/tiff"),
    (0, b"fLaC", "audio/flac"),
    (4, b"ftyp", "video/mp4"),
)

_COMPATIBLE: dict[str, tuple[str, ...]] = {
    # Office documents, e-books, Android and Java packages are all zip files.
    "application/zip": (
        "zip", "openxml", "opendocument", "epub", "java-archive", "android",
        "x-tgsticker", "vnd.ms-",
    ),
    "application/gzip": ("gzip", "x-tgsticker", "tar"),
    "video/mp4": ("video/", "audio/", "image/heic", "image/heif", "image/avif"),
    "video/webm": ("video/", "audio/"),
    "audio/ogg": ("audio/", "video/", "application/ogg"),
    "audio/mpeg": ("audio/",),
    "audio/flac": ("audio/",),
}  # fmt: skip
"""Detected types whose container legitimately carries other declared types."""

_TEXT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/x-yaml",
    "application/yaml",
    "application/javascript",
    "application/x-sh",
    "image/svg+xml",
)

_SNIFF_BYTES = 4096


def detect_type(head: bytes) -> tuple[str | None, bool]:
    """Identify a file from its first bytes: ``(mime type, is executable)``.

    Deliberately small. It recognises the formats Telegram users actually send
    and every common executable header, and answers None for anything else —
    an unknown type is reported as unknown, never guessed.
    """
    for magic, mime in _EXECUTABLE_MAGIC:
        if head.startswith(magic):
            return mime, True
    if head[:4] == b"RIFF" and len(head) >= 12:
        kind = head[8:12]
        if kind == b"WEBP":
            return "image/webp", False
        if kind == b"WAVE":
            return "audio/wav", False
        if kind == b"AVI ":
            return "video/x-msvideo", False
    for offset, magic, mime in _MAGIC:
        if head[offset : offset + len(magic)] == magic:
            return mime, False
    return None, False


def _types_agree(detected: str, declared: str) -> bool:
    if detected == declared:
        return True
    allowed = _COMPATIBLE.get(detected)
    if allowed is not None:
        return any(token in declared for token in allowed)
    return detected.split("/")[0] == declared.split("/")[0]


def _is_text_type(declared: str | None) -> bool:
    return declared is not None and declared.startswith(_TEXT_TYPES)


def _looks_like_text(sample: bytes) -> bool:
    """UTF-8 without NUL bytes, tolerating a character cut at the boundary."""
    if b"\x00" in sample:
        return False
    decoded = sample.decode("utf-8", errors="replace")
    replacements = decoded.count("\ufffd")
    return replacements <= max(1, len(decoded) // 100)


@dataclass
class InspectedDownload:
    """What :meth:`FileAccessGuard.inspect_download` found.

    ``text`` is the readable body to scan, kept off the model-facing record:
    the model gets the verdict, not a second copy of the file.
    """

    inspection: AttachmentInspection
    text: str | None = None
    text_truncated: bool = False


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

    # -- downloaded attachments -------------------------------------------- #

    def _extension_problem(self, *names: str | None) -> str | None:
        suffixes = {Path(name).suffix.lower() for name in names if name}
        suffixes.discard("")
        if self.settings.block_executables:
            for suffix in sorted(suffixes):
                if suffix in EXECUTABLE_EXTENSIONS:
                    return f"{suffix} files are executable and block_executables is on"
        allowed = self.settings.allowed_download_extensions
        if allowed:
            if not suffixes:
                return (
                    "the file has no extension and allowed_download_extensions is set"
                )
            outside = sorted(s for s in suffixes if s not in allowed)
            if outside:
                return f"{outside[0]} is not in allowed_download_extensions"
        return None

    def check_attachment(self, media: Media, filename: str, *, tool: str) -> None:
        """Refuse an attachment before a single byte of it is transferred.

        Uses what Telegram reports — the sender's file name, the saved name and
        the declared size. All three are sender-influenced, which is why
        :meth:`inspect_download` checks the real bytes again afterwards; this
        step exists so an obviously refused file costs no bandwidth.
        """
        problem = self._extension_problem(media.file_name, filename)
        if problem is None:
            ceiling = self.settings.max_download_bytes
            size = media.file_size
            if ceiling and size is not None and size > ceiling:
                problem = (
                    f"the attachment is {size} bytes, over max_download_bytes "
                    f"({ceiling})"
                )
        if problem is not None:
            self.audit.record(
                "attachment_rejected", tool=tool, reason=problem, stage="before"
            )
            raise AttachmentRejectedError(reason=problem)

    def inspect_download(
        self, media: DownloadedMedia, *, tool: str
    ) -> InspectedDownload:
        """Look at what was actually written, and delete it if it is refused."""
        path = Path(media.path)
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                head = handle.read(_SNIFF_BYTES)
        except OSError as exc:
            self.reject(path, tool=tool, reason=f"the file could not be read: {exc}")

        ceiling = self.settings.max_download_bytes
        if ceiling and size > ceiling:
            self.reject(
                path,
                tool=tool,
                reason=f"{size} bytes were written, over max_download_bytes "
                f"({ceiling})",
            )
        problem = self._extension_problem(media.media.file_name, path.name)
        if problem is not None:
            self.reject(path, tool=tool, reason=problem)

        detected, executable = detect_type(head)
        if executable and self.settings.block_executables:
            self.reject(
                path,
                tool=tool,
                reason=f"the file's contents are executable ({detected}), whatever "
                "its name says",
            )

        declared = media.media.mime_type or mimetypes.guess_type(path.name)[0]
        mismatch = False
        if self.settings.verify_file_type:
            if detected is not None and declared is not None:
                mismatch = not _types_agree(detected, declared)
            elif detected is None and _is_text_type(declared):
                mismatch = not _looks_like_text(head)

        result = InspectedDownload(
            AttachmentInspection(
                size_bytes=size,
                declared_type=declared,
                detected_type=detected,
                type_mismatch=mismatch,
            )
        )
        if (
            self.settings.scan_text_attachments
            and detected is None
            and _looks_like_text(head)
        ):
            limit = self.settings.text_scan_max_bytes
            try:
                with path.open("rb") as handle:
                    body = handle.read(limit)
            except OSError as exc:
                self.reject(
                    path, tool=tool, reason=f"the file could not be read: {exc}"
                )
            result.text = body.decode("utf-8", errors="replace")
            result.text_truncated = size > limit
            result.inspection.text_scanned = True
        return result

    def reject(self, path: Path, *, tool: str, reason: str) -> NoReturn:
        """Delete a downloaded file and refuse the call."""
        removed = True
        try:
            path.unlink(missing_ok=True)
        except OSError:
            removed = False
        self.audit.record(
            "attachment_rejected",
            tool=tool,
            reason=reason,
            stage="after",
            removed=removed,
        )
        hint = None
        if not removed:
            hint = (
                f"The refused file could not be deleted and is still at {path}. "
                "Tell the user so they can remove it."
            )
        raise AttachmentRejectedError(reason=reason, hint=hint)

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
