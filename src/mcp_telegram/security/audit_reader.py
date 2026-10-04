"""Reading the security audit log back.

Added by Telegram MCP Enhanced. The log is JSON lines written through a
`RotatingFileHandler`, so its history is spread across `security.log` and the
backups `security.log.1` (newest) to `security.log.N` (oldest). This module
reads them in chronological order, filters and summarises, for the `log`
command. It only reads: nothing here writes, rotates or truncates the log.
"""

from __future__ import annotations

import json
import re

from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

__all__ = [
    "AuditSummary",
    "ReadStats",
    "log_files",
    "parse_since",
    "read_events",
    "summarise",
]

_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdw])\s*$", re.IGNORECASE)
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_since(value: str, *, now: datetime | None = None) -> datetime:
    """Turn `90s`, `15m`, `1h`, `2d`, `1w` or an ISO 8601 time into a cut-off.

    A timestamp without a zone is taken as UTC, which is what the log writes.

    Raises:
        ValueError: if ``value`` is neither form.
    """
    now = now or datetime.now(timezone.utc)
    match = _DURATION.match(value)
    if match:
        amount, unit = float(match.group(1)), match.group(2).lower()
        return now - timedelta(seconds=amount * _UNITS[unit])
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(
            f"--since expects a duration such as 30m, 6h or 2d, or an ISO 8601 "
            f"time; got {value!r}"
        ) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def log_files(path: Path) -> list[Path]:
    """The log and its rotated backups, oldest first.

    Only `name.<digits>` counts as a backup, so an unrelated `security.log.bak`
    beside it is not read as audit history.
    """
    backups: list[tuple[int, Path]] = []
    for candidate in path.parent.glob(path.name + ".*"):
        suffix = candidate.name[len(path.name) + 1 :]
        if suffix.isdigit() and candidate.is_file():
            backups.append((int(suffix), candidate))
    ordered = [backup for _, backup in sorted(backups, reverse=True)]
    if path.is_file():
        ordered.append(path)
    return ordered


@dataclass
class ReadStats:
    files: int = 0
    malformed: int = 0


def _timestamp(record: dict[str, Any]) -> datetime | None:
    raw = record.get("timestamp")
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def read_events(
    path: Path,
    *,
    since: datetime | None = None,
    events: Iterable[str] = (),
    stats: ReadStats | None = None,
) -> Iterator[dict[str, Any]]:
    """Every matching record across the log and its backups, oldest first.

    A line that is not a JSON object is counted in ``stats`` and skipped: an
    interrupted write leaves a torn last line, and one bad line must not hide
    the rest of the trail.
    """
    wanted = {event.strip() for event in events if event.strip()}
    stats = stats if stats is not None else ReadStats()
    for file in log_files(path):
        stats.files += 1
        with file.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    stats.malformed += 1
                    continue
                if not isinstance(record, dict):
                    stats.malformed += 1
                    continue
                if wanted and record.get("event") not in wanted:
                    continue
                if since is not None:
                    stamp = _timestamp(record)
                    if stamp is None or stamp < since:
                        continue
                yield record


@dataclass
class AuditSummary:
    total: int = 0
    first: str | None = None
    last: str | None = None
    by_event: Counter[str] = field(default_factory=Counter)
    by_tool: Counter[str] = field(default_factory=Counter)
    by_rule: Counter[str] = field(default_factory=Counter)
    by_action: Counter[str] = field(default_factory=Counter)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "first": self.first,
            "last": self.last,
            "by_event": dict(self.by_event.most_common()),
            "by_tool": dict(self.by_tool.most_common()),
            "by_rule": dict(self.by_rule.most_common()),
            "by_action": dict(self.by_action.most_common()),
        }


def summarise(records: Iterable[dict[str, Any]]) -> AuditSummary:
    summary = AuditSummary()
    for record in records:
        summary.total += 1
        stamp = record.get("timestamp")
        if isinstance(stamp, str):
            summary.first = summary.first or stamp
            summary.last = stamp
        summary.by_event[str(record.get("event", "unknown"))] += 1
        if isinstance(record.get("tool"), str):
            summary.by_tool[record["tool"]] += 1
        if isinstance(record.get("action_taken"), str):
            summary.by_action[record["action_taken"]] += 1
        rules = record.get("rule_triggered")
        if isinstance(rules, list):
            for rule in rules:
                summary.by_rule[str(rule)] += 1
    return summary
