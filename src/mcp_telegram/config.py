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
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
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
    "PermissionSettings",
    "PromptInjectionSettings",
    "RateLimitSettings",
    "SecurityLoggingSettings",
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


class PermissionSettings(_Strict):
    """``[permissions]`` — server-side enforcement, independent of the LLM."""

    default_policy: str | None = None
    allowed_chats: list[str] = Field(default_factory=list)
    denied_chats: list[str] = Field(default_factory=list)

    allow_read: bool = True
    allow_search: bool = True
    allow_send: bool = True
    allow_edit: bool = False
    allow_delete: bool = False
    allow_drafts: bool = True
    allow_download: bool = True
    allow_admin: bool = False

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


class FileAccessSettings(_Strict):
    """``[security.files]`` — keeps local secrets out of Telegram.

    Added by Telegram MCP Enhanced: upstream ``send_message`` will upload any
    path the model names, which turns a prompt injection into file exfiltration.
    """

    protect_sensitive_paths: bool = True
    max_files_per_message: int = Field(default=10, ge=1)
    """Ceiling on attachments in a single send.

    Telegram groups attachments into albums of ten, and Telethon uploads a
    longer list as several albums inside one scheduler slot, so an unbounded
    list is unbounded upload traffic bought with a single write token.
    """
    max_upload_bytes: int = Field(default=2 * 1024**3, ge=0)
    """Ceiling on the combined size of one send's attachments. 0 disables it."""
    allowed_upload_dirs: list[str] = Field(default_factory=list)
    allowed_download_dirs: list[str] = Field(default_factory=list)
    extra_denied_patterns: list[str] = Field(default_factory=list)


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
    minimum_interval_ms: int = Field(default=500, ge=0)
    max_concurrent: int = Field(default=2, ge=1)
    max_retries: int = Field(default=2, ge=0)
    max_flood_wait_seconds: float = Field(default=60, ge=0)
    queue_timeout_seconds: float = Field(default=120, gt=0)
    max_messages_per_call: int = Field(default=200, ge=1)
    """Ceiling on `limit` for a single read.

    One MCP call takes one scheduler slot but paginates, so an unbounded limit
    would let a single token generate an unbounded number of Telegram requests.
    """
    messages_per_token: int = Field(default=100, ge=1)
    """How many messages one read token pays for."""
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
    prompt_injection: PromptInjectionSettings = Field(
        default_factory=PromptInjectionSettings
    )
    permissions: PermissionSettings = Field(default_factory=PermissionSettings)
    files: FileAccessSettings = Field(default_factory=FileAccessSettings)
    security_logging: SecurityLoggingSettings = Field(
        default_factory=SecurityLoggingSettings
    )
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)

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
    ("security_logging", ("security", "logging")),
    ("permissions", ("permissions",)),
    ("rate_limit", ("rate_limit",)),
)

_KNOWN_TOP_LEVEL = {"log_level", "security", "permissions", "rate_limit"}
_KNOWN_SECURITY_SUBSECTIONS = {"prompt_injection", "files", "logging"}


def _bool(raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"expected a boolean, got {raw!r}")


def _csv(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


_ENV_OVERRIDES: tuple[tuple[str, tuple[str, ...], Callable[[str], Any]], ...] = (
    ("TELEGRAM_MCP_LOG_LEVEL", ("log_level",), str),
    ("TELEGRAM_MCP_SECURITY_ENABLED", ("prompt_injection", "enabled"), _bool),
    ("TELEGRAM_MCP_SECURITY_MODE", ("prompt_injection", "mode"), str),
    ("TELEGRAM_MCP_DEFAULT_CHAT_POLICY", ("permissions", "default_policy"), str),
    ("TELEGRAM_MCP_ALLOWED_CHATS", ("permissions", "allowed_chats"), _csv),
    ("TELEGRAM_MCP_DENIED_CHATS", ("permissions", "denied_chats"), _csv),
    ("TELEGRAM_MCP_ALLOW_READ", ("permissions", "allow_read"), _bool),
    ("TELEGRAM_MCP_ALLOW_SEARCH", ("permissions", "allow_search"), _bool),
    ("TELEGRAM_MCP_ALLOW_SEND", ("permissions", "allow_send"), _bool),
    ("TELEGRAM_MCP_ALLOW_EDIT", ("permissions", "allow_edit"), _bool),
    ("TELEGRAM_MCP_ALLOW_DELETE", ("permissions", "allow_delete"), _bool),
    ("TELEGRAM_MCP_ALLOW_DRAFTS", ("permissions", "allow_drafts"), _bool),
    ("TELEGRAM_MCP_ALLOW_DOWNLOAD", ("permissions", "allow_download"), _bool),
    ("TELEGRAM_MCP_ALLOW_ADMIN", ("permissions", "allow_admin"), _bool),
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
    if "log_level" in raw:
        data["log_level"] = raw["log_level"]
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
