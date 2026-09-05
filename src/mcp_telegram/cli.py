"""MCP Telegram CLI."""

import asyncio
import importlib.metadata
import logging
import os
import sys

from collections.abc import Callable, Coroutine
from functools import wraps
from pathlib import Path
from typing import Any

import typer

from mcp.types import Tool
from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcp_telegram._compat import tool_input_schema
from mcp_telegram.config import (
    ConfigError,
    default_config_path,
    load_config,
    state_dir,
)
from mcp_telegram.runtime import build_runtime
from mcp_telegram.server import mcp
from mcp_telegram.telegram import Telegram

DISTRIBUTION_NAMES = ("telegram-mcp-enhanced", "mcp-telegram")
"""This project's name first, then upstream's, for installs from source."""


def configure_logging(level: str | None = None) -> None:
    """Set up logging on stderr.

    Enhanced: upstream logged at DEBUG unconditionally, which writes Telethon
    protocol detail — including message content — to the terminal of anyone
    running the server. The default is now INFO and the level is configurable.
    """
    resolved = level or os.environ.get("TELEGRAM_MCP_LOG_LEVEL", "INFO")
    logging.basicConfig(
        level=getattr(logging, resolved.strip().upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
        stream=sys.stderr,
        force=True,
    )


configure_logging()

app = typer.Typer(
    name="mcp-telegram",
    help="MCP Server for Telegram",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


def async_command(
    func: Callable[..., Coroutine[Any, Any, None]],
) -> Callable[..., None]:
    """Decorator to handle async Typer commands.

    Args:
        func: An async function that will be wrapped to work with Typer.

    Returns:
        A synchronous function that can be used with Typer.
    """

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> None:
        asyncio.run(func(*args, **kwargs))

    return wrapper


def _installed_version() -> str:
    for name in DISTRIBUTION_NAMES:
        try:
            return importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
    raise importlib.metadata.PackageNotFoundError(DISTRIBUTION_NAMES[0])


@app.command()
def version() -> None:
    """Show the MCP Telegram version."""
    try:
        version = _installed_version()
        console.print(
            Panel.fit(
                f"[bold blue]Telegram MCP Enhanced version {version}[/bold blue]\n"
                f"[dim]downstream of dryeab/mcp-telegram[/dim]",
                title="📦 Version",
                border_style="blue",
            )
        )
    except importlib.metadata.PackageNotFoundError:
        console.print(
            Panel.fit(
                "[bold red]Version unknown (package not installed)[/bold red]",
                title="❌ Error",
                border_style="red",
            )
        )
        sys.exit(1)


@app.command()
@async_command
async def login() -> None:
    """Login to Telegram."""
    console.print(
        Panel.fit(
            "[bold blue]Welcome to MCP Telegram![/bold blue]\n\n"
            "To proceed with login, you'll need your Telegram API credentials:\n"
            "1. Visit [link]https://my.telegram.org/apps[/link]\n"
            "2. Create a new application if you haven't already\n"
            "3. Copy your API ID and API Hash",
            title="🚀 Telegram Authentication",
            border_style="blue",
        )
    )

    tg = Telegram()

    console.print("\n[yellow]Please enter your credentials:[/yellow]")

    try:
        api_id = console.input(
            "\n[bold cyan]🔑 API ID[/bold cyan]\n"
            "[dim]Enter your Telegram API ID (found on my.telegram.org)[/dim]\n"
            "> ",
            password=True,
        )

        api_hash = console.input(
            "\n[bold cyan]🔒 API Hash[/bold cyan]\n"
            "[dim]Enter your Telegram API hash (found on my.telegram.org)[/dim]\n"
            "> ",
            password=True,
        )

        phone = console.input(
            "\n[bold cyan]📱 Phone Number[/bold cyan]\n"
            "[dim]Enter your phone number in international format \
                (e.g., +1234567890)[/dim]\n"
            "> "
        )

        tg.create_client(api_id=api_id, api_hash=api_hash)

        with console.status("[bold green]Connecting to Telegram...", spinner="dots"):
            await tg.client.connect()
            console.print(
                "\n[bold green]✓[/bold green] [dim]Connected to Telegram[/dim]"
            )

        def code_callback() -> str:
            return console.input(
                "\n[bold cyan]🔢 Verification Code[/bold cyan]\n"
                "[dim]Enter the code sent to your Telegram[/dim]\n"
                "> "
            )

        def password_callback() -> str:
            return console.input(
                "\n[bold cyan]🔐 Two-Factor Authentication[/bold cyan]\n"
                "[dim]Enter your 2FA password[/dim]\n"
                "> ",
                password=True,
            )

        await tg.client.start(
            phone=phone,
            code_callback=code_callback,
            password=password_callback,
        )  # type: ignore

        console.print("\n[bold green]✓[/bold green] [dim]Successfully logged in[/dim]")

        user = await tg.client.get_me()

        console.print(
            Panel.fit(
                f"[bold green]Authentication successful![/bold green]\n"
                f"[dim]Welcome, {user.first_name}! You can now use MCP Telegram commands.[/dim]",  # type: ignore  # noqa: E501
                title="🎉 Success",
                border_style="green",
            )
        )

    except ValueError:
        console.print(
            "\n[bold red]✗ Error:[/bold red] API ID must be a number", style="red"
        )
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]✗ Error:[/bold red] {str(e)}", style="red")
        sys.exit(1)
    finally:
        if tg.is_connected:
            await tg.client.disconnect()  # type: ignore


@app.command()
def start() -> None:
    """Start the MCP Telegram server."""
    try:
        config = load_config()
    except ConfigError as exc:
        # Fail closed: a server whose policy will not load must not start.
        console.print(
            Panel.fit(
                f"[bold red]Security configuration is invalid.[/bold red]\n\n{exc}",
                title="❌ Refusing to start",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    configure_logging(config.log_level)
    mcp.run()


@app.command()
def logout() -> None:
    """Show instructions on how to logout from Telegram."""
    console.print(
        Panel.fit(
            "[bold blue]How to Logout from Telegram[/bold blue]\n\n"
            "To logout from your Telegram account, please follow these steps:\n\n"
            "1. Open your Telegram app\n"
            "2. Go to [bold]Settings[/bold]\n"
            "3. Select [bold]Privacy and Security[/bold]\n"
            "4. Scroll down to find [bold]'Active Sessions'[/bold]\n"
            "5. Find and terminate the session with the name of your app\n   "
            "(This is the app name you created on [link]my.telegram.org/apps[/link])\n\n"  # noqa: E501
            "[yellow]Note:[/yellow] After logging out, you can use the [bold]clear-session[/bold] "  # noqa: E501
            "command to remove local session data.",
            title="🚪 Logout Instructions",
            border_style="blue",
        )
    )


@app.command()
def clear_session() -> None:
    """Delete the local Telegram session file and its SQLite companions."""

    telegram = Telegram()
    session_files = telegram.session_files()

    if not session_files:
        console.print(
            Panel.fit(
                "[bold yellow]No session file found![/bold yellow]\n"
                "[dim]The session file may have already been deleted or never existed.[/dim]",  # noqa: E501
                title="ℹ️ Info",
                border_style="yellow",
            )
        )
        return

    removed: list[str] = []
    failed: list[tuple[Path, str]] = []
    for path in session_files:
        # Every file is attempted. Stopping at the first error would skip the
        # companions, which is precisely where cached contact data survives.
        try:
            os.remove(path)
            removed.append(path.name)
        except Exception as e:
            failed.append((path, str(e)))

    if failed:
        detail = "\n".join(f"  {path}: {reason}" for path, reason in failed)
        console.print(
            Panel.fit(
                "[bold red]Session data was NOT fully removed.[/bold red]\n"
                f"[dim]Deleted: {', '.join(removed) or 'nothing'}[/dim]\n\n"
                f"[bold]Still present:[/bold]\n{detail}\n\n"
                "[dim]These files can hold authentication material and cached "
                "contact data. Remove them before treating the session as "
                "cleared.[/dim]",
                title="❌ Incomplete",
                border_style="red",
            )
        )
        # Non-zero, so a script following the documented deletion steps cannot
        # mistake a partial purge for a completed one.
        raise typer.Exit(code=1)

    console.print(
        Panel.fit(
            "[bold green]Session file successfully deleted![/bold green]\n"
            f"[dim]Removed: {', '.join(removed)}[/dim]\n"
            "[dim]You can now safely create a new session by logging in again.[/dim]",
            title="🗑️ Session Cleared",
            border_style="green",
        )
    )


def _format_parameters(schema: dict[str, Any]) -> str:
    """Formats the parameters from a tool's input schema for display."""
    if not schema.get("properties"):
        return "[dim]No parameters[/dim]"

    params: list[str] = []
    properties: dict[str, dict[str, Any]] = schema.get("properties", {})
    required_params: set[str] = set(schema.get("required", []))

    for name, details in properties.items():
        param_type: str = details.get("type", "any")
        description: str = details.get("description", "")
        param_str: str = f"[bold]{name}[/bold]: [italic]{param_type}[/italic]"
        if description:
            param_str += f" - [dim]{description}[/dim]"

        if name in required_params:
            params.append(f"[red]•[/red] {param_str} [bold red](required)[/bold red]")
        else:
            params.append(f"[dim]•[/dim] {param_str}")

    return "\n".join(params) if params else "[dim]No parameters[/dim]"


@app.command()
@async_command
async def tools() -> None:
    """List all available tools in a table format."""
    try:
        tools: list[Tool] = await mcp.list_tools()
    except Exception as e:
        console.print(f"[bold red]Error fetching tools:[/bold red] {e}")
        raise typer.Exit(code=1)

    if not tools:
        console.print("[yellow]No tools available.[/yellow]")
        return

    table = Table(
        title="🔧 Available Tools",
        box=ROUNDED,
        show_header=True,
        header_style="bold blue",
        show_lines=True,
        expand=True,
    )

    table.add_column("Name", style="cyan", width=20, overflow="fold")
    table.add_column("Description", style="dim", ratio=2, overflow="fold")
    table.add_column("Parameters", ratio=3, overflow="fold")

    for tool in tools:
        table.add_row(
            f"[bold]{tool.name}[/bold]",
            tool.description or "[dim]No description[/dim]",
            _format_parameters(tool_input_schema(tool)),
        )

    console.print(table)


# --------------------------------------------------------------------------- #
# Security commands. Added by Telegram MCP Enhanced.
# --------------------------------------------------------------------------- #

CONFIG_TEMPLATE = """# Telegram MCP Enhanced configuration.
# Every setting below is optional; the values shown are the defaults unless a
# comment says otherwise. See docs/CONFIGURATION.md for the full reference.

log_level = "INFO"

[security.prompt_injection]
enabled = true
# "flag" keeps the original message and attaches metadata (recommended),
# "redact" replaces matched spans, "block" withholds high-risk content.
mode = "flag"
block_risk_threshold = "high_risk"
scan_dialog_titles = true
scan_media_filenames = true
max_scan_chars = 20000
disabled_rules = []

# Add your own detection rules:
# [[security.prompt_injection.custom_patterns]]
# id = "internal_project_names"
# pattern = "project (bluebird|redwood)"
# risk = "suspicious"
# description = "Mentions an internal codename"

[security.logging]
enabled = true
# Message text is never written to the security log unless you turn this on.
include_message_content = false
max_bytes = 1000000
backup_count = 3

[security.files]
# Refuse to upload credentials, keys, session files and shell history.
protect_sensitive_paths = true
# Uncomment to allow uploads from these directories *only*:
# allowed_upload_dirs = ["~/Documents/telegram-outbox"]
# allowed_download_dirs = []
extra_denied_patterns = []

[permissions]
# Leave allowed_chats empty and this server can reach every chat on the
# account. List chats here and everything else is denied by default.
# IDs may be written with or without the -100 prefix.
allowed_chats = []
denied_chats = []
# default_policy = "deny"

allow_read = true
allow_search = true
allow_send = true
allow_edit = false
allow_delete = false
allow_drafts = true
allow_download = true
allow_admin = false

[rate_limit]
enabled = true
minimum_interval_ms = 500
max_concurrent = 2
max_retries = 2
max_flood_wait_seconds = 60
queue_timeout_seconds = 120

# Per-operation-class token buckets.
# [rate_limit.buckets.read]
# capacity = 20
# refill_per_minute = 60
"""


@app.command()
def init_config(
    path: str = typer.Option(
        "", "--path", help="Where to write the file. Defaults to the standard location."
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Write a starter security configuration file."""
    target = Path(path).expanduser() if path else default_config_path()

    if target.exists() and not force:
        console.print(
            Panel.fit(
                f"[bold yellow]{target} already exists.[/bold yellow]\n"
                "[dim]Pass --force to overwrite it.[/dim]",
                title="ℹ️ Nothing written",
                border_style="yellow",
            )
        )
        raise typer.Exit(code=1)

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(CONFIG_TEMPLATE, encoding="utf-8")
    except OSError as exc:
        console.print(f"[bold red]✗ Could not write {target}:[/bold red] {exc}")
        raise typer.Exit(code=1)

    console.print(
        Panel.fit(
            f"[bold green]Configuration written to[/bold green]\n{target}\n\n"
            "[dim]Edit it to restrict chats and operations, then restart the "
            "server.[/dim]",
            title="✅ Config created",
            border_style="green",
        )
    )


@app.command()
def security() -> None:
    """Show the security and reliability policy this server would enforce."""
    try:
        config = load_config()
    except ConfigError as exc:
        console.print(
            Panel.fit(
                f"[bold red]{exc}[/bold red]",
                title="❌ Invalid configuration",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    runtime = build_runtime(config)
    summary = runtime.describe()
    source = config.source_path or "built-in defaults (no config file found)"

    console.print(
        Panel.fit(
            f"[bold]Config file:[/bold] {source}\n"
            f"[bold]Security log:[/bold] "
            f"{runtime.audit.path if config.security_logging.enabled else 'disabled'}",
            title="🔐 Telegram MCP Enhanced",
            border_style="blue",
        )
    )

    permissions = Table(title="Operation permissions", box=ROUNDED, expand=True)
    permissions.add_column("Operation", style="cyan")
    permissions.add_column("Allowed")
    for name, granted in summary.permissions.items():
        permissions.add_row(name, "[green]yes[/green]" if granted else "[red]no[/red]")
    console.print(permissions)

    chat_access = summary.chat_access
    detection = summary.prompt_injection_detection
    rate_limit = summary.rate_limit

    other = Table(box=ROUNDED, expand=True, show_header=False)
    other.add_column("Setting", style="cyan")
    other.add_column("Value")
    other.add_row("Chat access control", _yes_no(chat_access.filtering_active))
    other.add_row("Default chat policy", chat_access.default_policy)
    other.add_row("Allowed chats", str(chat_access.allowed_chats_configured))
    other.add_row("Denied chats", str(chat_access.denied_chats_configured))
    other.add_row("Injection detection", _yes_no(detection.enabled))
    other.add_row("Security mode", detection.mode)
    other.add_row("Active rules", str(detection.active_rules))
    other.add_row("Rate limiting", _yes_no(rate_limit.enabled))
    other.add_row("Minimum interval", f"{rate_limit.minimum_interval_ms} ms")
    other.add_row("Max concurrent", str(rate_limit.max_concurrent))
    other.add_row("Max flood wait", f"{rate_limit.max_flood_wait_seconds:g} s")
    console.print(other)

    if not chat_access.filtering_active:
        console.print(
            "[yellow]⚠ This server can reach every chat on the account. "
            r"Add allowed_chats under \[permissions] to restrict it "
            "(mcp-telegram init-config).[/yellow]"
        )
    runtime.audit.close()


def _yes_no(value: object) -> str:
    return "[green]yes[/green]" if value else "[red]no[/red]"


@app.command()
def paths() -> None:
    """Show every location this server reads or writes.

    Added by Telegram MCP Enhanced. Resolving these by hand is error-prone: the
    XDG specification says a relative `XDG_STATE_HOME` must be ignored in favour
    of the default, so a shell command that expands the variable literally can
    both miss real data and delete an unrelated directory. This prints what the
    running program actually uses.
    """
    try:
        config = load_config()
    except ConfigError as exc:
        console.print(
            Panel.fit(
                f"[bold red]{exc}[/bold red]",
                title="❌ Invalid configuration",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    telegram = Telegram()
    locations: list[tuple[str, Path, str]] = [
        (
            "Session",
            telegram.session_file.with_suffix(".session"),
            "credential + cached contacts",
        ),
        ("Downloads", state_dir() / "downloads", "media you downloaded"),
        (
            "Security log",
            config.security_logging.resolved_path(),
            "security events" if config.security_logging.enabled else "disabled",
        ),
        (
            "Configuration",
            config.source_path or default_config_path(),
            "policy settings" if config.source_path else "not created yet",
        ),
    ]

    table = Table(
        title="📁 Storage locations", box=ROUNDED, show_lines=False, expand=True
    )
    table.add_column("What", style="cyan", no_wrap=True)
    table.add_column("Path", overflow="fold")
    table.add_column("State", no_wrap=True)

    for label, path, note in locations:
        if path.exists():
            size = _directory_size(path) if path.is_dir() else path.stat().st_size
            state = f"[green]{_human_size(size)}[/green]"
        else:
            state = "[dim]absent[/dim]"
        table.add_row(label, str(path), f"{state} [dim]· {note}[/dim]")

    console.print(table)

    companions = [
        path
        for path in telegram.session_files()
        if path.name.endswith(Telegram.SESSION_COMPANION_SUFFIXES)
    ]
    if companions:
        console.print(
            "[yellow]SQLite companion files present: "
            f"{', '.join(path.name for path in companions)}[/yellow]\n"
            "[dim]An interrupted write leaves these beside the session; they can "
            "hold cached contact data. `clear-session` removes them.[/dim]"
        )

    rotated = sorted(
        config.security_logging.resolved_path().parent.glob(
            config.security_logging.resolved_path().name + ".*"
        )
    )
    if rotated:
        console.print(
            f"[dim]Rotated log copies: {', '.join(p.name for p in rotated)}[/dim]"
        )

    console.print(
        "\n[dim]Diagnostics are written to stderr, not to a file. Whatever "
        "launched this server decides whether they are kept — see PRIVACY.md.[/dim]"
    )


def _directory_size(path: Path) -> int:
    return sum(child.stat().st_size for child in path.rglob("*") if child.is_file())


def _human_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size = int(size / 1024)
    return f"{size} B"
