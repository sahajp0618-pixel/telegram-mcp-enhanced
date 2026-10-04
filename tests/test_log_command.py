"""The `log` command (roadmap item 17)."""

from __future__ import annotations

import json

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from typer.testing import CliRunner

from mcp_telegram.cli import app
from mcp_telegram.security.audit_reader import (
    ReadStats,
    log_files,
    parse_since,
    read_events,
    summarise,
)

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)


def stamp(minutes_ago: float) -> str:
    return (NOW - timedelta(minutes=minutes_ago)).isoformat()


def record(minutes_ago: float, event: str, **fields) -> str:
    return json.dumps({"timestamp": stamp(minutes_ago), "event": event, **fields})


@pytest.fixture
def log_dir(tmp_path: Path) -> Path:
    """A log rotated twice, written the way RotatingFileHandler leaves it."""
    base = tmp_path / "security.log"
    (tmp_path / "security.log.2").write_text(
        record(300, "server_start") + "\n" + record(290, "flood_wait", tool="a") + "\n"
    )
    (tmp_path / "security.log.1").write_text(
        record(120, "injection_detected", tool="get_messages",
               rule_triggered=["instruction_override", "authority_claim"],
               action_taken="flagged") + "\n"
        + "{torn line\n"
    )  # fmt: skip
    base.write_text(
        record(30, "permission_denied", tool="send_message", action_taken="denied")
        + "\n"
        + record(5, "injection_detected", tool="get_messages",
                 rule_triggered=["instruction_override"], action_taken="flagged")
        + "\n"
    )  # fmt: skip
    (tmp_path / "security.log.bak").write_text(record(1, "should_not_be_read") + "\n")
    return tmp_path


def test_files_are_read_oldest_first(log_dir: Path) -> None:
    names = [p.name for p in log_files(log_dir / "security.log")]
    assert names == ["security.log.2", "security.log.1", "security.log"]


def test_every_backup_is_read_in_order_and_torn_lines_are_counted(
    log_dir: Path,
) -> None:
    stats = ReadStats()
    events = [r["event"] for r in read_events(log_dir / "security.log", stats=stats)]
    assert events == [
        "server_start",
        "flood_wait",
        "injection_detected",
        "permission_denied",
        "injection_detected",
    ]
    assert stats.malformed == 1
    assert stats.files == 3


def test_filters_by_time_and_event(log_dir: Path) -> None:
    path = log_dir / "security.log"
    since = parse_since("1h", now=NOW)
    assert [r["event"] for r in read_events(path, since=since)] == [
        "permission_denied",
        "injection_detected",
    ]
    hits = list(read_events(path, events=["injection_detected", "flood_wait"]))
    assert len(hits) == 3


@pytest.mark.parametrize(
    "value, expected",
    [
        ("90s", NOW - timedelta(seconds=90)),
        ("15m", NOW - timedelta(minutes=15)),
        ("2h", NOW - timedelta(hours=2)),
        ("1d", NOW - timedelta(days=1)),
        ("1w", NOW - timedelta(weeks=1)),
        ("2026-10-01", datetime(2026, 10, 1, tzinfo=timezone.utc)),
        ("2026-10-01T05:00:00Z", datetime(2026, 10, 1, 5, tzinfo=timezone.utc)),
    ],
)
def test_since_formats(value: str, expected: datetime) -> None:
    assert parse_since(value, now=NOW) == expected


def test_a_bad_since_is_an_error() -> None:
    with pytest.raises(ValueError, match="duration"):
        parse_since("yesterday")


def test_summary_counts(log_dir: Path) -> None:
    summary = summarise(read_events(log_dir / "security.log"))
    assert summary.total == 5
    assert summary.by_event["injection_detected"] == 2
    assert summary.by_rule["instruction_override"] == 2
    assert summary.by_tool["get_messages"] == 2
    assert summary.by_action["denied"] == 1


def invoke(log_dir: Path, *args: str):
    return CliRunner().invoke(
        app,
        ["log", *args],
        env={
            "TELEGRAM_MCP_SECURITY_LOG_PATH": str(log_dir / "security.log"),
            "COLUMNS": "250",
        },
    )


def test_json_output_is_one_record_per_line(log_dir: Path) -> None:
    result = invoke(log_dir, "--json", "--limit", "0", "--event", "injection_detected")
    assert result.exit_code == 0, result.output
    lines = [
        json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")
    ]
    assert [line["event"] for line in lines] == ["injection_detected"] * 2


def test_limit_keeps_the_most_recent(log_dir: Path) -> None:
    result = invoke(log_dir, "--json", "--limit", "1")
    lines = [l for l in result.stdout.splitlines() if l.startswith("{")]  # noqa: E741
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "injection_detected"


def test_summary_json(log_dir: Path) -> None:
    result = invoke(log_dir, "--summary", "--json")
    assert result.exit_code == 0, result.output
    summary = json.loads(result.stdout.splitlines()[0])
    assert summary["total"] == 5
    assert summary["by_rule"]["instruction_override"] == 2


def test_table_output_does_not_interpret_markup(log_dir: Path) -> None:
    """The log holds sender-chosen strings; rich markup in them stays literal."""
    path = log_dir / "security.log"
    path.write_text(
        path.read_text() + record(1, "file_access_denied", path="[bold]x[/bold]") + "\n"
    )
    result = invoke(log_dir)
    assert result.exit_code == 0, result.output
    assert "[bold]x[/bold]" in result.stdout


def test_a_missing_log_is_not_an_error(tmp_path: Path) -> None:
    result = invoke(tmp_path)
    assert result.exit_code == 0
    assert "No matching events" in result.stdout


def test_the_command_only_reads(log_dir: Path) -> None:
    before = {p.name: p.read_bytes() for p in log_dir.iterdir()}
    invoke(log_dir, "--summary")
    assert {p.name: p.read_bytes() for p in log_dir.iterdir()} == before
