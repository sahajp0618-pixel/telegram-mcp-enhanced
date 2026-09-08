"""Structured security-event logging.

Added by Telegram MCP Enhanced.

Two rules govern everything here:

* message content is never written unless the operator explicitly opts in, and
  even then it is truncated;
* credentials are scrubbed from every field on the way out, so a stray value
  cannot reach the log through an exception message.
"""

from __future__ import annotations

import json
import logging
import os
import re

from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from mcp_telegram.config import SecurityLoggingSettings

__all__ = ["CredentialScrubber", "SecurityAuditLog"]

logger = logging.getLogger(__name__)

REDACTED = "[redacted]"
_CONTENT_PREVIEW_CHARS = 200

_SECRET_NAME_HINTS = ("api_hash", "api_id", "token", "secret", "password", "session")
_SECRET_SHAPES: tuple[re.Pattern[str], ...] = (
    # Not `\b`: a word boundary needs a word/non-word transition, so a hash
    # butted against a letter — `hash0123…` — would not match. Anchoring on
    # "not more hex" catches it while still refusing to fire on part of a
    # longer hex run.
    re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", re.IGNORECASE),  # api_hash
    # Same reasoning as the hash above, and the same bug until it was fixed
    # here too: a leading `\b` meant a session butted against a letter never
    # matched at all, so `x` + session left all 353 characters in place. Anchor
    # on the session alphabet instead of a word boundary. Over-redacting a long
    # token in a log is the safe direction; leaking one grants the account.
    re.compile(r"1[A-Za-z0-9_\-=]{40,}(?![A-Za-z0-9_\-=])"),  # StringSession
    re.compile(r"\b[A-Za-z0-9_\-]{20,}\.session\b"),
)


class CredentialScrubber:
    """Removes credential material from anything about to be written."""

    def __init__(self, environ: dict[str, str] | None = None) -> None:
        env = os.environ if environ is None else environ
        self._literals: set[str] = set()
        for name, value in env.items():
            if not value or len(value) < 6:
                continue
            lowered = name.lower()
            if any(hint in lowered for hint in _SECRET_NAME_HINTS):
                self._literals.add(value)

    def scrub(self, value: Any) -> Any:
        """Return ``value`` with any credential-looking content replaced."""
        if isinstance(value, str):
            return self._scrub_text(value)
        if isinstance(value, dict):
            return {key: self.scrub(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.scrub(item) for item in value]
        return value

    def _scrub_text(self, text: str) -> str:
        """Redact every match in one pass over the original text.

        Substituting pattern by pattern lets an earlier replacement break a
        later match: inserting `[redacted]` inside a session string severs its
        alphabet, so the session pattern no longer sees it and the rest of the
        credential survives. Every match is therefore located against the
        untouched text, the spans are merged, and the replacement happens once.
        """
        spans: list[tuple[int, int]] = []

        for literal in self._literals:
            start = text.find(literal)
            while start != -1:
                spans.append((start, start + len(literal)))
                start = text.find(literal, start + len(literal))

        for shape in _SECRET_SHAPES:
            for match in shape.finditer(text):
                spans.append(match.span())

        if not spans:
            return text

        spans.sort()
        merged: list[tuple[int, int]] = [spans[0]]
        for start, end in spans[1:]:
            last_start, last_end = merged[-1]
            if start <= last_end:  # overlapping or touching
                merged[-1] = (last_start, max(last_end, end))
            else:
                merged.append((start, end))

        out = text
        for start, end in reversed(merged):
            out = f"{out[:start]}{REDACTED}{out[end:]}"
        return out


class SecurityAuditLog:
    """Append-only JSON-lines log of security-relevant events."""

    def __init__(
        self,
        settings: SecurityLoggingSettings,
        *,
        scrubber: CredentialScrubber | None = None,
    ) -> None:
        self.settings = settings
        self.scrubber = scrubber or CredentialScrubber()
        self._handler: RotatingFileHandler | None = None
        self._disabled = not settings.enabled
        self._path = settings.resolved_path()

    @property
    def path(self) -> Path:
        return self._path

    def _ensure_handler(self) -> RotatingFileHandler | None:
        if self._disabled:
            return None
        if self._handler is not None:
            return self._handler
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                self._path,
                maxBytes=self.settings.max_bytes or 0,
                backupCount=self.settings.backup_count,
                encoding="utf-8",
                delay=True,
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
        except OSError as exc:
            # Losing the audit trail must not take the server down; say so loudly
            # once and carry on with enforcement, which does not depend on it.
            logger.error(
                "Security audit log disabled, cannot open %s: %s", self._path, exc
            )
            self._disabled = True
            return None
        self._handler = handler
        return handler

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        """Write one event. Returns the record (useful in tests)."""
        record: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
        }
        for key, value in fields.items():
            if value is None:
                continue
            record[key] = self.scrubber.scrub(value)

        handler = self._ensure_handler()
        if handler is not None:
            try:
                handler.emit(
                    logging.LogRecord(
                        name="mcp_telegram.security",
                        level=logging.INFO,
                        pathname=__file__,
                        lineno=0,
                        msg=json.dumps(record, ensure_ascii=False, default=str),
                        args=(),
                        exc_info=None,
                    )
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("Failed to write security audit event: %s", exc)
        return record

    def preview(self, content: str | None) -> str | None:
        """Return a loggable excerpt of message content, or nothing.

        Scrubbing happens **before** truncation, and the order is the whole
        point. Truncating first can cut a credential in half, and a fragment
        matches neither the literal value nor the fixed-width shape patterns —
        so 31 characters of a 32-character API hash would survive into the log,
        leaving sixteen possibilities. Sanitise the whole string, then cut.
        """
        if not content or not self.settings.include_message_content:
            return None
        sanitized = self.scrubber.scrub(content)
        if not isinstance(sanitized, str):  # pragma: no cover - defensive
            sanitized = str(sanitized)
        excerpt = sanitized[:_CONTENT_PREVIEW_CHARS]
        if len(sanitized) > _CONTENT_PREVIEW_CHARS:
            excerpt += "…"
        return excerpt

    # -- convenience wrappers ---------------------------------------------- #

    def injection_detected(
        self,
        *,
        tool: str,
        chat_id: int | str | None,
        message_id: int | None,
        risk_level: str,
        classification: str,
        rules_triggered: list[str],
        action_taken: str,
        content: str | None = None,
    ) -> dict[str, Any]:
        return self.record(
            "injection_detected",
            tool=tool,
            chat_id=chat_id,
            message_id=message_id,
            risk_level=risk_level,
            classification=classification,
            rule_triggered=rules_triggered,
            action_taken=action_taken,
            content_preview=self.preview(content),
        )

    def permission_denied(
        self,
        *,
        tool: str,
        operation: str,
        reason: str,
        chat_id: int | str | None = None,
    ) -> dict[str, Any]:
        return self.record(
            "permission_denied",
            tool=tool,
            operation=operation,
            reason=reason,
            chat_id=chat_id,
            action_taken="denied",
        )

    def rate_limited(
        self,
        *,
        tool: str,
        operation_class: str,
        retry_after_seconds: float,
        reason: str,
    ) -> dict[str, Any]:
        return self.record(
            "rate_limited",
            tool=tool,
            operation_class=operation_class,
            retry_after_seconds=retry_after_seconds,
            reason=reason,
            action_taken="deferred",
        )

    def flood_wait(
        self, *, tool: str, seconds: float, attempt: int, action_taken: str
    ) -> dict[str, Any]:
        return self.record(
            "flood_wait",
            tool=tool,
            seconds=seconds,
            attempt=attempt,
            action_taken=action_taken,
        )

    def file_access_denied(
        self, *, tool: str, reason: str, path: str
    ) -> dict[str, Any]:
        return self.record(
            "file_access_denied",
            tool=tool,
            reason=reason,
            path=path,
            action_taken="denied",
        )

    def close(self) -> None:
        if self._handler is not None:
            self._handler.close()
            self._handler = None
