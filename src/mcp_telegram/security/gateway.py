"""The untrusted content gateway.

Added by Telegram MCP Enhanced.

Every piece of externally authored text — message bodies, chat titles,
usernames, sender-supplied file names — passes through here on its way to the
MCP client. The gateway classifies it, attaches safety metadata, applies the
configured security mode and wraps it in an envelope that keeps server-
generated facts distinguishable from third-party content.

Under the default `flag` mode the original text is returned byte-for-byte:
detection annotates, it does not rewrite.
"""

from __future__ import annotations

from mcp_telegram.config import PromptInjectionSettings
from mcp_telegram.security.audit import SecurityAuditLog
from mcp_telegram.security.injection import (
    InjectionDetector,
    RuleMatch,
)
from mcp_telegram.security.models import (
    BatchSecurity,
    Classification,
    ContentSecurity,
    RISK_FOR_CLASSIFICATION,
    SecurityAction,
    SecurityMode,
)
from mcp_telegram.types import (
    Dialog,
    Dialogs,
    DownloadedMedia,
    Media,
    Message,
    Messages,
)

__all__ = ["ContentGateway"]

INCOMPLETE_REDACTION_PLACEHOLDER = (
    "[WITHHELD by security policy: this content matched more times than can be "
    "redacted precisely ({rules}), so it was withheld rather than partially "
    "rewritten. Tell the user it was withheld and let them read it in Telegram "
    "if they want to.]"
)

BLOCKED_PLACEHOLDER = (
    "[BLOCKED by security policy: this message was classified as {classification} "
    "(rules: {rules}). Its text was withheld from you. Tell the user it was "
    "withheld and let them read it in Telegram if they want to.]"
)


class ContentGateway:
    """Single place where Telegram content becomes an MCP response."""

    def __init__(
        self,
        settings: PromptInjectionSettings,
        detector: InjectionDetector,
        audit: SecurityAuditLog,
    ) -> None:
        self.settings = settings
        self.detector = detector
        self.audit = audit

    # -- core --------------------------------------------------------------- #

    def assess(
        self,
        text: str | None,
        *,
        tool: str,
        chat_id: int | str | None = None,
        message_id: int | None = None,
    ) -> tuple[str | None, ContentSecurity]:
        """Classify one piece of external text and apply the security mode.

        Returns the text to hand to the model (unchanged under `flag`) and the
        metadata describing what was found.
        """
        result = self.detector.scan(text)
        if not result.scanned:
            return text, ContentSecurity(scanned=False)
        if result.clean:
            return text, ContentSecurity()

        classification = result.classification
        action = SecurityAction.FLAGGED
        output = text

        if self.settings.mode is SecurityMode.REDACT and text:
            if result.capped:
                # Redaction rewrites the spans that were recorded. If more
                # matched than fit the budget, a partial rewrite would leave
                # hostile text behind while the metadata claimed otherwise, so
                # the whole field is withheld instead.
                classification = Classification.BLOCKED
                action = SecurityAction.BLOCKED
                output = INCOMPLETE_REDACTION_PLACEHOLDER.format(
                    rules=", ".join(result.rule_ids) or "unspecified"
                )
            else:
                output = _redact(text, result.matches)
                if output != text:
                    action = SecurityAction.REDACTED
        elif self.settings.mode is SecurityMode.BLOCK and self._blocks(classification):
            classification = Classification.BLOCKED
            action = SecurityAction.BLOCKED
            output = BLOCKED_PLACEHOLDER.format(
                classification=result.classification.value,
                rules=", ".join(result.rule_ids) or "unspecified",
            )

        metadata = ContentSecurity(
            prompt_injection_risk=RISK_FOR_CLASSIFICATION[classification],
            classification=classification,
            action_taken=action,
            rules_triggered=result.rule_ids,
            scanned=True,
        )

        self.audit.injection_detected(
            tool=tool,
            chat_id=chat_id,
            message_id=message_id,
            risk_level=metadata.prompt_injection_risk.value,
            classification=classification.value,
            rules_triggered=metadata.rules_triggered,
            action_taken=action.value,
            content=text,
        )
        return output, metadata

    def _blocks(self, classification: Classification) -> bool:
        return classification.rank >= self.settings.block_risk_threshold.rank

    # -- typed helpers ------------------------------------------------------ #

    def process_message(
        self, message: Message, *, tool: str, chat_id: int | str | None = None
    ) -> Message:
        """Attach safety metadata to one message, in place."""
        effective_chat = message.chat_id if message.chat_id is not None else chat_id
        text, metadata = self.assess(
            message.message,
            tool=tool,
            chat_id=effective_chat,
            message_id=message.message_id,
        )
        message.message = text
        message.security = metadata
        if message.media is not None and self.settings.scan_media_filenames:
            message.security = _merge(
                metadata,
                self._scan_media(
                    message.media,
                    tool=tool,
                    chat_id=effective_chat,
                    message_id=message.message_id,
                ),
            )
        return message

    def _scan_media(
        self,
        media: Media,
        *,
        tool: str,
        chat_id: int | str | None = None,
        message_id: int | None = None,
    ) -> ContentSecurity:
        """Scan every sender-controlled string on an attachment.

        The file name is the obvious one, but the MIME type is stored per
        document and is equally attacker-chosen.
        """
        context = {"tool": tool, "chat_id": chat_id, "message_id": message_id}
        media.file_name, name_metadata = self.assess(media.file_name, **context)
        media.mime_type, mime_metadata = self.assess(media.mime_type, **context)
        return _merge(name_metadata, mime_metadata)

    def process_messages(
        self, messages: Messages, *, tool: str, chat_id: int | str | None = None
    ) -> Messages:
        """Attach per-message metadata and a batch summary."""
        summary = BatchSecurity()
        dialog_id = messages.dialog.id if messages.dialog else chat_id
        for message in messages.messages:
            self.process_message(message, tool=tool, chat_id=dialog_id)
            if message.security is not None:
                summary.absorb(message.security)
        if messages.dialog is not None:
            self.process_dialog(messages.dialog, tool=tool)
        messages.security = summary
        return messages

    def process_dialog(self, dialog: Dialog, *, tool: str) -> Dialog:
        """Scan a chat title and username, which the chat owner controls."""
        if not self.settings.scan_dialog_titles:
            dialog.security = ContentSecurity(scanned=False)
            return dialog
        title, title_metadata = self.assess(dialog.title, tool=tool, chat_id=dialog.id)
        dialog.title = title or ""
        username, username_metadata = self.assess(
            dialog.username, tool=tool, chat_id=dialog.id
        )
        dialog.username = username
        phone, phone_metadata = self.assess(
            dialog.phone_number, tool=tool, chat_id=dialog.id
        )
        dialog.phone_number = phone
        dialog.security = _merge(
            _merge(title_metadata, username_metadata), phone_metadata
        )
        return dialog

    def process_dialogs(
        self, dialogs: list[Dialog], *, tool: str, withheld_count: int = 0
    ) -> Dialogs:
        summary = BatchSecurity()
        for dialog in dialogs:
            self.process_dialog(dialog, tool=tool)
            if dialog.security is not None:
                summary.absorb(dialog.security)
        return Dialogs(dialogs=dialogs, security=summary, withheld_count=withheld_count)

    def process_downloaded_media(
        self, media: DownloadedMedia, *, tool: str, chat_id: int | str | None = None
    ) -> DownloadedMedia:
        if not self.settings.scan_media_filenames:
            media.security = ContentSecurity(scanned=False)
            return media
        metadata = self._scan_media(media.media, tool=tool, chat_id=chat_id)
        # The saved file name is derived from the sender's, so the path can carry
        # their text too. It names a real file on disk, so it is reported rather
        # than rewritten: the metadata says whether it should be trusted.
        _, path_metadata = self.assess(media.path, tool=tool, chat_id=chat_id)
        media.security = _merge(metadata, path_metadata)
        return media


def _merge(first: ContentSecurity, second: ContentSecurity) -> ContentSecurity:
    """Combine two assessments, keeping the more severe classification."""
    primary, other = (
        (first, second)
        if first.classification.rank >= second.classification.rank
        else (second, first)
    )
    rules = list(primary.rules_triggered)
    for rule in other.rules_triggered:
        if rule not in rules:
            rules.append(rule)
    return ContentSecurity(
        prompt_injection_risk=primary.prompt_injection_risk,
        classification=primary.classification,
        action_taken=primary.action_taken,
        rules_triggered=rules,
        scanned=primary.scanned or other.scanned,
    )


def _redact(text: str, matches: list[RuleMatch]) -> str:
    """Replace matched spans with markers, leaving the rest of the text intact."""
    spans = sorted(
        (
            (match.start, match.end, match.rule_id)
            for match in matches
            if match.end > match.start
        ),
        key=lambda span: (span[0], -span[1]),
    )
    if not spans:
        return text

    merged: list[tuple[int, int, str]] = []
    for start, end, rule_id in spans:
        if merged and start <= merged[-1][1]:
            previous_start, previous_end, previous_rule = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end), previous_rule)
        else:
            merged.append((start, end, rule_id))

    out = text
    for start, end, rule_id in reversed(merged):
        out = f"{out[:start]}[REDACTED:{rule_id}]{out[end:]}"
    return out
