"""Configuration for the security and reliability layer.

Added by Telegram MCP Enhanced.

Configuration is resolved from three sources, in increasing order of priority:

1. built-in defaults;
2. a TOML file (``$TELEGRAM_MCP_CONFIG``, else
   ``<xdg_config_home>/mcp-telegram/config.toml``);
3. a fixed set of environment variables.

Upstream's ``API_ID`` / ``API_HASH`` handling is untouched and still lives in
:mod:`mcp_telegram.telegram`; this module never reads or stores credentials.
"""

from __future__ import annotations

import os
import sys

from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from xdg_base_dirs import xdg_config_home, xdg_state_home

from mcp_telegram.security.models import Classification, PatternRule, SecurityMode

if sys.version_info >= (3, 11):  # pragma: no cover - trivial branch
    import tomllib
else:  # pragma: no cover - trivial branch
    import tomli as tomllib

__all__ = [
    "APP_NAME",
    "BucketSettings",
    "ChatPolicy",
    "Config",
    "ConfigError",
    "FileAccessSettings",
    "OutboundSettings",
    "PermissionSettings",
    "PromptInjectionSettings",
    "RateLimitSettings",
    "SecurityLoggingSettings",
    "SessionSettings",
    "CONFIRM",
    "PROFILE_OPERATIONS",
    "PermissionProfile",
    "PermissionValue",
    "default_config_path",
    "load_config",
    "state_dir",
]

APP_NAME = "mcp-telegram"
"""Kept identical to upstream so existing Telethon sessions keep working."""


class ConfigError(RuntimeError):
    """Raised when configuration is present but unusable.

    Per the fail-safe principle the server refuses to start rather than
    silently falling back to a weaker policy than the operator intended.
    """


def state_dir() -> Path:
    return xdg_state_home() / APP_NAME


def default_config_path() -> Path:
    return xdg_config_home() / APP_NAME / "config.toml"


class _Strict(BaseModel):
    """Base model that rejects unknown keys so config typos are never silent."""

    model_config = ConfigDict(extra="forbid")


class ChatPolicy(str):
    ALLOW = "allow"
    DENY = "deny"


class PromptInjectionSettings(_Strict):
    """``[security.prompt_injection]``."""

    enabled: bool = True
    mode: SecurityMode = SecurityMode.FLAG
    block_risk_threshold: Classification = Classification.HIGH_RISK
    custom_patterns: list[PatternRule] = Field(default_factory=list)
    disabled_rules: list[str] = Field(default_factory=list)
    scan_dialog_titles: bool = True
    scan_media_filenames: bool = True
    max_scan_chars: int = Field(default=20_000, ge=0)

    @field_validator("custom_patterns", mode="before")
    @classmethod
    def _coerce_patterns(cls, value: Any) -> Any:
        """Accept both PRD spellings: bare regex strings and full tables."""
        if not isinstance(value, list):
            return value
        coerced: list[Any] = []
        for index, item in enumerate(value):
            if isinstance(item, str):
                coerced.append({"id": f"custom_{index + 1}", "pattern": item})
            else:
                coerced.append(item)
        return coerced

    @field_validator("block_risk_threshold")
    @classmethod
    def _threshold_must_be_actionable(cls, value: Classification) -> Classification:
        if value is Classification.NORMAL:
            raise ValueError(
                "block_risk_threshold='normal' would block every message; "
                "use 'suspicious' or 'high_risk'"
            )
        return value


class OutboundSettings(_Strict):
    """Bound model-composed text because inbound scanning cannot prevent leaks."""

    enabled: bool = True
    block_credentials: bool = True
    max_message_chars: int = Field(default=4096, ge=0)
    block_bulk_quotes: bool = True
    bulk_quote_min_chars: int = Field(default=2000, ge=1)
    bulk_quote_ratio: float = Field(default=0.9, gt=0, le=1)


CONFIRM = "confirm"
"""The third permission value: allowed, but only after a human approves it."""

PermissionValue = bool | Literal["confirm"]


def _permission_value(value: Any) -> Any:
    """Accept `true`, `false` or `"confirm"`, and nothing that merely resembles them.

    A string such as `"false"` is refused rather than coerced. TOML has real
    booleans, so a quoted one is a typo, and pydantic's lax mode would otherwise
    read `"no"` and `"off"` as booleans while `"confirm"` stayed a string —
    exactly the ambiguity a security setting must not have.
    """
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str) and value.strip().lower() == CONFIRM:
        return CONFIRM
    raise ValueError('must be true, false or "confirm"')


PROFILE_OPERATIONS = (
    "allow_read",
    "allow_send",
    "allow_edit",
    "allow_delete",
    "allow_drafts",
    "allow_download",
)
"""The permissions a per-chat profile may override.

`allow_search` and `allow_admin` are deliberately absent. Search spans every
chat on the account, so no single chat's profile can govern it, and there are no
administrative tools for a chat to scope.
"""


class PermissionProfile(_Strict):
    """``[[permissions.profiles]]`` — operation permissions for specific chats.

    A profile changes *what* may be done in a chat, never *whether* the chat may
    be reached: `allowed_chats`, `denied_chats` and `default_policy` still decide
    that, so listing a chat here does not grant access to it.
    """

    chats: list[str] = Field(min_length=1)
    allow_read: PermissionValue | None = None
    allow_send: PermissionValue | None = None
    allow_edit: PermissionValue | None = None
    allow_delete: PermissionValue | None = None
    allow_drafts: PermissionValue | None = None
    allow_download: PermissionValue | None = None

    @model_validator(mode="before")
    @classmethod
    def _no_global_only_keys(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for key in ("allow_search", "allow_admin"):
                if key in data:
                    raise ValueError(
                        f"{key} cannot be set per chat: it is not scoped to a single "
                        "chat. Set it under [permissions] instead."
                    )
        return data

    @field_validator(*PROFILE_OPERATIONS, mode="before")
    @classmethod
    def _valid_permission(cls, value: Any) -> Any:
        return _permission_value(value)

    @field_validator("chats", mode="before")
    @classmethod
    def _stringify(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return value

    @field_validator("chats")
    @classmethod
    def _no_wildcard(cls, value: list[str]) -> list[str]:
        if "*" in value:
            raise ValueError(
                'a profile cannot match "*"; set the permission under [permissions] '
                "to apply it to every chat"
            )
        return value


class PermissionSettings(_Strict):
    """``[permissions]`` — server-side enforcement, independent of the LLM."""

    default_policy: str | None = None
    allowed_chats: list[str] = Field(default_factory=list)
    denied_chats: list[str] = Field(default_factory=list)

    allow_read: PermissionValue = True
    allow_search: PermissionValue = True
    allow_send: PermissionValue = True
    allow_edit: PermissionValue = False
    allow_delete: PermissionValue = False
    allow_drafts: PermissionValue = True
    allow_download: PermissionValue = True
    allow_admin: PermissionValue = False

    profiles: list[PermissionProfile] = Field(default_factory=list)
    """Per-chat overrides, first match wins. See :class:`PermissionProfile`."""

    confirm_timeout_seconds: float = Field(default=120, gt=0)
    """How long to wait for a human to answer a confirmation before refusing."""

    @field_validator(
        "allow_read",
        "allow_search",
        "allow_send",
        "allow_edit",
        "allow_delete",
        "allow_drafts",
        "allow_download",
        "allow_admin",
        mode="before",
    )
    @classmethod
    def _valid_permission(cls, value: Any) -> Any:
        if value is None:
            raise ValueError('must be true, false or "confirm"')
        return _permission_value(value)

    @field_validator("default_policy")
    @classmethod
    def _valid_policy(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if normalized not in (ChatPolicy.ALLOW, ChatPolicy.DENY):
            raise ValueError("default_policy must be 'allow' or 'deny'")
        return normalized

    @field_validator("allowed_chats", "denied_chats", mode="before")
    @classmethod
    def _stringify(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return value

    @property
    def effective_default_policy(self) -> str:
        """Resolve the chat policy that actually applies.

        An explicit setting always wins. Otherwise an operator who listed
        allowed chats gets allowlist semantics (deny everything else), and an
        operator who configured no chat rules at all keeps upstream behaviour.
        :attr:`chat_filtering_active` reports which of those is in force so the
        server can say so at startup.
        """
        if self.default_policy is not None:
            return self.default_policy
        return ChatPolicy.DENY if self.allowed_chats else ChatPolicy.ALLOW

    @property
    def chat_filtering_active(self) -> bool:
        return (
            self.effective_default_policy == ChatPolicy.DENY
            or bool(self.denied_chats)
            or bool(self.allowed_chats)
        )


ALBUM_SIZE = 10
"""Attachments Telegram groups into one message. A send of this size or less is
a single request, which is what makes an automatic retry safe."""


class FileAccessSettings(_Strict):
    """``[security.files]`` — keeps local secrets out of Telegram.

    Added by Telegram MCP Enhanced: upstream ``send_message`` will upload any
    path the model names, which turns a prompt injection into file exfiltration.
    """

    protect_sensitive_paths: bool = True
    max_files_per_message: int = Field(default=ALBUM_SIZE, ge=1, le=ALBUM_SIZE)
    """Ceiling on attachments in a single send. Cannot exceed Telegram's album
    size of ten.

    Two reasons, and the second is why it is a hard limit rather than a default.
    An unbounded list is unbounded upload traffic bought with a single write
    token. And Telethon sends a longer list as *several* albums in sequence, so
    a flood wait on the second album would make the retry re-deliver the first:
    a send is not idempotent, and this layer retries automatically. Held to one
    album, a send either happens or is refused, and a retry cannot duplicate it.
    """
    max_upload_bytes: int = Field(default=2 * 1024**3, ge=0)
    """Ceiling on the combined size of one send's attachments. 0 disables it."""
    allowed_upload_dirs: list[str] = Field(default_factory=list)
    allowed_download_dirs: list[str] = Field(default_factory=list)
    extra_denied_patterns: list[str] = Field(default_factory=list)

    # -- downloaded attachment inspection ------------------------------------ #
    max_download_bytes: int = Field(default=200 * 1024**2, ge=0)
    """Ceiling on one downloaded attachment. 0 disables it.

    Checked against the size Telegram reports *before* anything is transferred,
    and again against the bytes actually written, because a sender controls the
    reported size of some media types.
    """
    allowed_download_extensions: list[str] = Field(default_factory=list)
    """When non-empty, only attachments with one of these extensions download."""
    block_executables: bool = True
    """Refuse executables, judged by extension and by the file's first bytes."""
    verify_file_type: bool = True
    """Compare the file's magic bytes with its declared type and flag a mismatch."""
    scan_text_attachments: bool = True
    """Run the injection detector over the contents of text-like attachments."""
    text_scan_max_bytes: int = Field(default=256 * 1024, ge=1)
    """How much of a text-like attachment is read for scanning."""

    @field_validator("allowed_download_extensions")
    @classmethod
    def _normalise_extensions(cls, value: list[str]) -> list[str]:
        return [
            "." + item.strip().lower().lstrip(".") for item in value if item.strip()
        ]


class SessionSettings(_Strict):
    """``[session]`` — where the Telegram session credential is kept.

    Added by Telegram MCP Enhanced. The default is upstream's SQLite file, now
    created owner-only. `keyring` keeps a Telethon `StringSession` in the
    operating system's credential store instead (Keychain, Secret Service,
    Windows Credential Locker), which needs the optional `keyring` extra.
    """

    storage: Literal["file", "keyring"] = "file"
    keyring_service: str = Field(default="telegram-mcp-enhanced", min_length=1)
    keyring_username: str = Field(default="session", min_length=1)


class SecurityLoggingSettings(_Strict):
    """``[security.logging]``."""

    enabled: bool = True
    include_message_content: bool = False
    path: str | None = None
    max_bytes: int = Field(default=1_000_000, ge=0)
    backup_count: int = Field(default=3, ge=0)

    def resolved_path(self) -> Path:
        if self.path:
            return Path(self.path).expanduser()
        return state_dir() / "security.log"


class BucketSettings(_Strict):
    capacity: float = Field(gt=0)
    refill_per_minute: float = Field(gt=0)


DEFAULT_BUCKETS: dict[str, dict[str, float]] = {
    "read": {"capacity": 20, "refill_per_minute": 60},
    "search": {"capacity": 5, "refill_per_minute": 20},
    "write": {"capacity": 5, "refill_per_minute": 20},
    "media": {"capacity": 3, "refill_per_minute": 10},
    "admin": {"capacity": 2, "refill_per_minute": 5},
}


class RateLimitSettings(_Strict):
    """``[rate_limit]``."""

    enabled: bool = True
    persist_state: bool = True
    """Carry budgets and the flood-wait cooldown across a restart.

    Without this the limits live only in memory, so anything that restarts the
    server — a crash loop, a client respawning it on error, a user retrying —
    resets every budget to full and forgets a wait Telegram asked for. The
    protection would disappear exactly when it is most needed.
    """
    minimum_interval_ms: int = Field(default=500, ge=0)
    max_concurrent: int = Field(default=2, ge=1)
    max_retries: int = Field(default=2, ge=0)
    max_flood_wait_seconds: float = Field(default=60, ge=0)
    queue_timeout_seconds: float = Field(default=120, gt=0)
    max_messages_per_call: int = Field(default=200, ge=1)
    """Ceiling on `limit` for a single read.

    Bound response size and time holding a tool slot even with RPC metering.
    """
    max_messages_scanned: int = Field(default=500, ge=1)
    """Ceiling on messages *examined* by one read, not just returned.

    Service and empty messages are skipped without counting toward `limit`, so a
    history full of them could otherwise page indefinitely even for `limit=1`.
    """
    buckets: dict[str, BucketSettings] = Field(
        default_factory=lambda: {
            name: BucketSettings(**values) for name, values in DEFAULT_BUCKETS.items()
        }
    )

    @field_validator("buckets")
    @classmethod
    def _known_buckets(
        cls, value: dict[str, BucketSettings]
    ) -> dict[str, BucketSettings]:
        merged = {
            name: BucketSettings(**values) for name, values in DEFAULT_BUCKETS.items()
        }
        for name, bucket in value.items():
            if name not in merged:
                raise ValueError(
                    f"unknown rate-limit bucket {name!r}; "
                    f"expected one of {sorted(merged)}"
                )
            merged[name] = bucket
        return merged


class Config(_Strict):
    """The complete enhanced-layer configuration."""

    log_level: str = "INFO"
    dry_run: bool = False
    """Run every check, then stop short of changing anything on Telegram.

    Writes are simulated, not refused: the point is to exercise the whole policy
    chain — chat authorization including the resolution round trip, permissions,
    file and outbound checks and tool admission — and only
    replace the final Telegram call. A configuration that would refuse an
    operation still refuses it here, which is what makes a dry run worth
    running.
    """
    prompt_injection: PromptInjectionSettings = Field(
        default_factory=PromptInjectionSettings
    )
    outbound: OutboundSettings = Field(default_factory=OutboundSettings)
    permissions: PermissionSettings = Field(default_factory=PermissionSettings)
    files: FileAccessSettings = Field(default_factory=FileAccessSettings)
    security_logging: SecurityLoggingSettings = Field(
        default_factory=SecurityLoggingSettings
    )
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    session: SessionSettings = Field(default_factory=SessionSettings)

    source_path: Path | None = None
    """The config file this was loaded from, if any. Never sent to the model."""

    @field_validator("log_level")
    @classmethod
    def _valid_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError(f"invalid log_level {value!r}")
        return normalized


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

_SECTION_MAP: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("prompt_injection", ("security", "prompt_injection")),
    ("files", ("security", "files")),
    ("outbound", ("security", "outbound")),
    ("security_logging", ("security", "logging")),
    ("permissions", ("permissions",)),
    ("rate_limit", ("rate_limit",)),
    ("session", ("session",)),
)

_TOP_LEVEL_SCALARS = frozenset(
    name
    for name, field in Config.model_fields.items()
    if name != "source_path" and not hasattr(field.annotation, "model_fields")
)
"""Top-level settings that are plain values rather than `[sections]`."""

_KNOWN_TOP_LEVEL = _TOP_LEVEL_SCALARS | {
    "security",
    "permissions",
    "rate_limit",
    "session",
}
_KNOWN_SECURITY_SUBSECTIONS = {"prompt_injection", "files", "logging", "outbound"}


def _bool(raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"expected a boolean, got {raw!r}")


def _permission(raw: str) -> bool | str:
    """An `allow_*` override: a boolean, or `confirm`."""
    if raw.strip().lower() == CONFIRM:
        return CONFIRM
    return _bool(raw)


def _csv(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


_ENV_OVERRIDES: tuple[tuple[str, tuple[str, ...], Callable[[str], Any]], ...] = (
    ("TELEGRAM_MCP_LOG_LEVEL", ("log_level",), str),
    ("TELEGRAM_MCP_DRY_RUN", ("dry_run",), _bool),
    ("TELEGRAM_MCP_SECURITY_ENABLED", ("prompt_injection", "enabled"), _bool),
    ("TELEGRAM_MCP_SECURITY_MODE", ("prompt_injection", "mode"), str),
    ("TELEGRAM_MCP_DEFAULT_CHAT_POLICY", ("permissions", "default_policy"), str),
    ("TELEGRAM_MCP_ALLOWED_CHATS", ("permissions", "allowed_chats"), _csv),
    ("TELEGRAM_MCP_DENIED_CHATS", ("permissions", "denied_chats"), _csv),
    ("TELEGRAM_MCP_ALLOW_READ", ("permissions", "allow_read"), _permission),
    ("TELEGRAM_MCP_ALLOW_SEARCH", ("permissions", "allow_search"), _permission),
    ("TELEGRAM_MCP_ALLOW_SEND", ("permissions", "allow_send"), _permission),
    ("TELEGRAM_MCP_ALLOW_EDIT", ("permissions", "allow_edit"), _permission),
    ("TELEGRAM_MCP_ALLOW_DELETE", ("permissions", "allow_delete"), _permission),
    ("TELEGRAM_MCP_ALLOW_DRAFTS", ("permissions", "allow_drafts"), _permission),
    ("TELEGRAM_MCP_ALLOW_DOWNLOAD", ("permissions", "allow_download"), _permission),
    ("TELEGRAM_MCP_ALLOW_ADMIN", ("permissions", "allow_admin"), _permission),
    ("TELEGRAM_MCP_RATE_LIMIT_ENABLED", ("rate_limit", "enabled"), _bool),
    ("TELEGRAM_MCP_MIN_INTERVAL_MS", ("rate_limit", "minimum_interval_ms"), int),
    ("TELEGRAM_MCP_MAX_CONCURRENT", ("rate_limit", "max_concurrent"), int),
    ("TELEGRAM_MCP_MAX_RETRIES", ("rate_limit", "max_retries"), int),
    (
        "TELEGRAM_MCP_MAX_FLOOD_WAIT_SECONDS",
        ("rate_limit", "max_flood_wait_seconds"),
        float,
    ),
    ("TELEGRAM_MCP_SECURITY_LOG_ENABLED", ("security_logging", "enabled"), _bool),
    ("TELEGRAM_MCP_SECURITY_LOG_PATH", ("security_logging", "path"), str),
)


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except OSError as exc:
        raise ConfigError(f"could not read config file {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc


def _flatten(raw: dict[str, Any], path: Path) -> dict[str, Any]:
    unknown_top = set(raw) - _KNOWN_TOP_LEVEL
    if unknown_top:
        raise ConfigError(
            f"unknown section(s) {sorted(unknown_top)} in {path}; "
            f"expected {sorted(_KNOWN_TOP_LEVEL)}"
        )
    security = raw.get("security", {})
    if not isinstance(security, dict):
        raise ConfigError(f"[security] must be a table in {path}")
    unknown_security = set(security) - _KNOWN_SECURITY_SUBSECTIONS
    if unknown_security:
        raise ConfigError(
            f"unknown section(s) security.{sorted(unknown_security)} in {path}"
        )

    data: dict[str, Any] = {}
    # Every top-level scalar, derived from the model rather than listed here.
    # A key named in _KNOWN_TOP_LEVEL passes validation, so one that is then
    # dropped on the way into Config is worse than an unknown key: the operator
    # writing `dry_run = true` would get no error and none of the behaviour.
    for field in _TOP_LEVEL_SCALARS:
        if field in raw:
            data[field] = raw[field]
    for field, keys in _SECTION_MAP:
        cursor: Any = raw
        for key in keys:
            if not isinstance(cursor, dict) or key not in cursor:
                cursor = None
                break
            cursor = cursor[key]
        if cursor is not None:
            data[field] = cursor
    return data


def _apply_env(data: dict[str, Any], environ: dict[str, str]) -> None:
    for name, keys, parser in _ENV_OVERRIDES:
        if name not in environ:
            continue
        try:
            value = parser(environ[name])
        except ConfigError:
            raise
        except Exception as exc:
            raise ConfigError(f"invalid value for {name}: {exc}") from exc
        section, *rest = keys
        if not rest:
            data[section] = value
        else:
            bucket = data.setdefault(section, {})
            if not isinstance(bucket, dict):
                bucket = {}
                data[section] = bucket
            bucket[rest[0]] = value


def load_config(
    path: Path | None = None, environ: dict[str, str] | None = None
) -> Config:
    """Build the effective configuration.

    Raises:
        ConfigError: if a config file is present but malformed, or an
            environment override is invalid. The server treats this as fatal
            rather than starting with unintended defaults.
    """
    env = dict(os.environ if environ is None else environ)

    source: Path | None = None
    if path is not None:
        source = Path(path).expanduser()
        if not source.exists():
            raise ConfigError(f"config file not found: {source}")
    elif env.get("TELEGRAM_MCP_CONFIG"):
        source = Path(env["TELEGRAM_MCP_CONFIG"]).expanduser()
        if not source.exists():
            raise ConfigError(f"TELEGRAM_MCP_CONFIG points at a missing file: {source}")
    else:
        candidate = default_config_path()
        source = candidate if candidate.exists() else None

    data = _flatten(_read_toml(source), source) if source is not None else {}
    _apply_env(data, env)

    try:
        config = Config.model_validate(data)
    except ValidationError as exc:
        location = f" in {source}" if source else " from environment overrides"
        raise ConfigError(f"invalid configuration{location}:\n{exc}") from exc

    config.source_path = source
    return config
