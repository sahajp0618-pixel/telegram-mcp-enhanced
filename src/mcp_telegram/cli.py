"""MCP Telegram CLI."""

import asyncio
import importlib.metadata
import logging
import os
import sys

from collections.abc import Callable, Coroutine
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Any

import typer

from mcp.types import Tool
from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcp_telegram._compat import tool_input_schema
from mcp_telegram.config import (
    ConfigError,
    SecurityLoggingSettings,
    default_config_path,
    load_config,
    state_dir,
)
from mcp_telegram.reliability.scheduler import unmetered
from mcp_telegram.runtime import build_runtime
from mcp_telegram.security.audit import SecurityAuditLog
from mcp_telegram.security.gateway import ContentGateway
from mcp_telegram.security.injection import DEFAULT_RULES, InjectionDetector
from mcp_telegram.security.models import RISK_FOR_CLASSIFICATION, SecurityMode
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
            with unmetered():
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

        with unmetered():
            # Signing in is the operator acting, not the agent spending budget.
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


class ConfigPreset(str, Enum):
    """Named policies make restrictive setup possible without editing many flags."""

    READ_ONLY = "read-only"
    ASSISTANT = "assistant"
    LOCKED_DOWN = "locked-down"


def _preset_template(preset: ConfigPreset) -> str:
    """Share the full reference so presets cannot lose guidance as settings grow."""
    locked = preset is ConfigPreset.LOCKED_DOWN
    drafts = preset is ConfigPreset.ASSISTANT
    mode = "block" if locked else "flag"
    purpose = {
        ConfigPreset.READ_ONLY: (
            "Read and search every chat; downloads are allowed.\n"
            "# Sending, editing, deleting, drafts and administration are disabled.\n"
            "# The agent cannot write messages or drafts to Telegram."
        ),
        ConfigPreset.ASSISTANT: (
            "Read, search, download and prepare drafts in every chat.\n"
            "# Drafts let the agent prepare a message for a human to review and send.\n"
            "# It never sends on its own in this preset. Sending, editing, deleting\n"
            "# and administration are disabled until you change their permissions."
        ),
        ConfigPreset.LOCKED_DOWN: (
            "No chat access until you fill in allowed_chats below.\n"
            "# Only reading and searching are enabled for chats you later allow.\n"
            "# Sending, editing, deleting, drafts, downloads and administration\n"
            "# are disabled. High-risk injection content is blocked. Operations\n"
            "# run one at a time, at least 1000 ms apart."
        ),
    }[preset]
    chat_policy = (
        "# Deny every chat until you uncomment and replace this example.\n"
        '# allowed_chats = ["-1001234567890"]\n'
        'default_policy = "deny"'
        if locked
        else "# Every chat is reachable. List chats to deny all others.\n"
        "allowed_chats = []\n"
        '# default_policy = "deny"'
    )
    return f'''# Telegram MCP Enhanced configuration: {preset.value}.
# {purpose}
# These values define this preset, rather than the built-in defaults.
# Environment variables override this file. See docs/CONFIGURATION.md.

# Keep diagnostics at INFO; DEBUG can include message content.
log_level = "INFO"

[security.prompt_injection]
# Scan untrusted content, including titles and sender-supplied file names.
enabled = true
# "flag" preserves content with metadata; "redact" replaces matched spans;
# "block" withholds content at or above block_risk_threshold.
mode = "{mode}"
block_risk_threshold = "high_risk"
scan_dialog_titles = true
scan_media_filenames = true
# Content beyond this scan limit is classified suspicious.
max_scan_chars = 20000
# List built-in rule IDs here to disable them.
disabled_rules = []
# Add custom rules by uncommenting this table and replacing the example.
# [[security.prompt_injection.custom_patterns]]
# id = "internal_project_names"
# pattern = "project (bluebird|redwood)"
# risk = "suspicious"
# description = "Mentions an internal codename"

[security.logging]
# Record security events without message text.
enabled = true
include_message_content = false
# Defaults to the state directory; uncomment to choose another path.
# path = "~/.local/state/mcp-telegram/security.log"
# Rotate at this size and retain this many backups.
max_bytes = 1000000
backup_count = 3

[security.files]
# Refuse uploads of credentials, keys, sessions and shell history.
protect_sensitive_paths = true
# Keep sends within one Telegram album; 0 disables only the byte limit.
max_files_per_message = 10
max_upload_bytes = 2147483648
# Non-empty lists restrict uploads or downloads to these directories.
allowed_upload_dirs = []
allowed_download_dirs = []
# Additional fnmatch patterns for paths or file names to refuse.
extra_denied_patterns = []

[permissions]
{chat_policy}
# Denied chats always win over allowed chats.
denied_chats = []
# Read and search still require chat access.
allow_read = true
allow_search = true
# Message writes are disabled; change each permission deliberately.
allow_send = false
allow_edit = false
allow_delete = false
# Drafts are stored in Telegram for human review; they do not send a message.
allow_drafts = {str(drafts).lower()}
# Downloads write media to local disk, subject to the file policy above.
allow_download = {str(not locked).lower()}
# Administrative operations remain disabled.
allow_admin = false

[rate_limit]
# Pace requests and retain budgets and FloodWait cooldowns across restarts.
enabled = true
persist_state = true
# Minimum gap between RPCs, and maximum tool operations in flight.
minimum_interval_ms = {1000 if locked else 500}
max_concurrent = {1 if locked else 2}
# Bound retries, flood waits and time spent waiting for a scheduler slot.
max_retries = 2
max_flood_wait_seconds = 60
queue_timeout_seconds = 120
# Bound read results and cap examined messages.
max_messages_per_call = 200
max_messages_scanned = 500

# Each class has its own token capacity and refill per minute.
[rate_limit.buckets.read]
capacity = 20
refill_per_minute = 60

[rate_limit.buckets.search]
capacity = 5
refill_per_minute = 20

[rate_limit.buckets.write]
capacity = 5
refill_per_minute = 20

[rate_limit.buckets.media]
capacity = 3
refill_per_minute = 10

[rate_limit.buckets.admin]
capacity = 2
refill_per_minute = 5
'''


@app.command()
def init_config(
    path: str = typer.Option(
        "", "--path", help="Where to write the file. Defaults to the standard location."
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
    preset: ConfigPreset | None = typer.Option(
        None,
        "--preset",
        help=(
            "Choose read-only, assistant, or locked-down. "
            "Omit to keep the original template."
        ),
    ),
) -> None:
    """Write a commented policy so operators can review it before starting."""
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
        target.write_text(
            CONFIG_TEMPLATE if preset is None else _preset_template(preset),
            encoding="utf-8",
        )
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
            "Reliability state",
            state_dir() / "rate-limit.json",
            "budgets + cooldown" if config.rate_limit.persist_state else "disabled",
        ),
        *(
            ("Reliability temporary", path, "interrupted snapshot")
            for path in sorted(state_dir().glob("rate-limit.json.*.tmp"))
        ),
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


@app.command()
def explain(
    text: str | None = typer.Argument(None, help="Text to assess locally."),
    file: Path | None = typer.Option(
        None, "--file", help="Read UTF-8 text from this file instead."
    ),
) -> None:
    """Explain detections and preview modes without auditing synthetic messages.

    Added by Telegram MCP Enhanced. A dedicated disabled audit sink lets previews
    reuse the real gateway policy even when content logging is enabled globally.
    No runtime is built, so this diagnostic cannot write audit or session state.
    """
    if (text is None) == (file is None):
        raise typer.BadParameter("Provide exactly one of TEXT or --file PATH.")
    try:
        config = load_config()
        if file is not None:
            # Preserve CRLF: flag mode promises the original text, not universal
            # newline conversion performed by Path.read_text().
            text = file.read_bytes().decode("utf-8")
    except (ConfigError, OSError, UnicodeError) as exc:
        console.print(
            Panel.fit(Text(str(exc)), title="❌ Cannot explain", border_style="red")
        )
        raise typer.Exit(code=1) from exc
    assert text is not None
    settings = config.prompt_injection
    detector = InjectionDetector(
        enabled=settings.enabled,
        custom_patterns=settings.custom_patterns,
        disabled_rules=settings.disabled_rules,
        max_scan_chars=settings.max_scan_chars,
    )
    result = detector.scan(text)
    summary = Table(box=ROUNDED, expand=True, show_header=False)
    summary.add_column("Setting", style="cyan")
    summary.add_column("Value")
    summary.add_row("Classification", result.classification.value)
    summary.add_row(
        "Prompt-injection risk", RISK_FOR_CLASSIFICATION[result.classification].value
    )
    summary.add_row("Configured mode", settings.mode.value)
    summary.add_row("Scanned", _yes_no(result.scanned))
    summary.add_row("Truncated for scanning", _yes_no(result.truncated))
    summary.add_row("Span budget exhausted (capped)", _yes_no(result.capped))
    console.print(Panel(summary, title="🔐 Detection explanation", border_style="blue"))

    matches = list(result.matches)
    if result.capped:
        # The shared span budget can omit entire later rules. Isolated scans
        # recover one example per omitted rule without changing policy results.
        rules = (*DEFAULT_RULES, *settings.custom_patterns)
        for rule in rules:
            if rule.id in result.rule_ids or rule.id in settings.disabled_rules:
                continue
            isolated = InjectionDetector(
                custom_patterns=settings.custom_patterns,
                disabled_rules=[r.id for r in rules if r.id != rule.id],
                max_scan_chars=settings.max_scan_chars,
            )
            matches.extend(
                [m for m in isolated.scan(text).matches if m.rule_id == rule.id][:1]
            )
        structural = InjectionDetector(
            disabled_rules=[r.id for r in DEFAULT_RULES],
            max_scan_chars=settings.max_scan_chars,
        ).scan(text)
        for match in structural.matches:
            if match.rule_id not in {m.rule_id for m in matches}:
                matches.append(match)
    table = Table(title="Matched rules", box=ROUNDED, expand=True, show_lines=True)
    table.add_column("Rule ID", style="cyan", overflow="fold")
    table.add_column("Description", overflow="fold")
    table.add_column("Span and context", overflow="fold")
    for match in matches:
        context = Text(f"[{match.start}:{match.end}] ")
        context.append(text[max(0, match.start - 40) : match.start])
        context.append("⟦")
        context.append(text[match.start : match.end], style="bold red")
        context.append("⟧")
        context.append(text[match.end : match.end + 40])
        table.add_row(Text(match.rule_id), Text(match.description), context)
    if not matches:
        table.add_row("—", "No rules matched", "—")
    console.print(table)
    audit = SecurityAuditLog(SecurityLoggingSettings(enabled=False))
    for mode in SecurityMode:
        gateway = ContentGateway(
            settings.model_copy(update={"mode": mode}), detector, audit
        )
        output, metadata = gateway.assess(text, tool="explain")
        console.print(
            Panel(
                Text(output or ""),
                title=f"{mode.value}: {metadata.classification.value} / "
                f"{metadata.action_taken.value}",
                border_style="blue",
            )
        )
