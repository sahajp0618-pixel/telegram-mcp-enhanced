"""Process-wide security and reliability runtime.

Added by Telegram MCP Enhanced.

One place builds the detector, gateway, permission enforcer, rate limiter,
scheduler, audit log and file guard, and every MCP tool shares them. Tests
replace the whole runtime in one call.
"""

from __future__ import annotations

import logging

from dataclasses import dataclass
from pathlib import Path

from mcp_telegram.config import Config, load_config, state_dir
from mcp_telegram.reliability.rate_limiter import MultiClassRateLimiter
from mcp_telegram.reliability.scheduler import RequestScheduler
from mcp_telegram.security.audit import SecurityAuditLog
from mcp_telegram.security.files import FileAccessGuard
from mcp_telegram.security.gateway import ContentGateway
from mcp_telegram.security.injection import InjectionDetector
from mcp_telegram.security.permissions import PermissionEnforcer

__all__ = [
    "Runtime",
    "build_runtime",
    "get_runtime",
    "log_startup",
    "reset_runtime",
    "set_runtime",
]

logger = logging.getLogger(__name__)


@dataclass
class Runtime:
    """Everything the middleware needs, built once."""

    config: Config
    audit: SecurityAuditLog
    detector: InjectionDetector
    gateway: ContentGateway
    enforcer: PermissionEnforcer
    limiter: MultiClassRateLimiter
    scheduler: RequestScheduler
    files: FileAccessGuard

    def describe(self) -> dict[str, object]:
        """A summary safe to show the model: policy only, never credentials."""
        permissions = self.config.permissions
        rate_limit = self.config.rate_limit
        injection = self.config.prompt_injection
        return {
            "prompt_injection_detection": {
                "enabled": injection.enabled,
                "mode": injection.mode.value,
                "block_risk_threshold": injection.block_risk_threshold.value,
                "active_rules": len(self.detector.rule_ids),
            },
            "permissions": self.enforcer.allowed_operations(),
            "chat_access": {
                "filtering_active": permissions.chat_filtering_active,
                "default_policy": permissions.effective_default_policy,
                "allowed_chats_configured": len(permissions.allowed_chats),
                "denied_chats_configured": len(permissions.denied_chats),
            },
            "rate_limit": {
                "enabled": rate_limit.enabled,
                "minimum_interval_ms": rate_limit.minimum_interval_ms,
                "max_concurrent": rate_limit.max_concurrent,
                "max_retries": rate_limit.max_retries,
                "max_flood_wait_seconds": rate_limit.max_flood_wait_seconds,
            },
            "scheduler": self.scheduler.stats(),
        }


def build_runtime(config: Config, *, state_directory: Path | None = None) -> Runtime:
    """Assemble a runtime from a validated configuration.

    Args:
        config: validated settings.
        state_directory: where session and download data live. Defaults to the
            XDG state directory; tests override it.
    """
    audit = SecurityAuditLog(config.security_logging)
    detector = InjectionDetector(
        enabled=config.prompt_injection.enabled,
        custom_patterns=config.prompt_injection.custom_patterns,
        disabled_rules=config.prompt_injection.disabled_rules,
        max_scan_chars=config.prompt_injection.max_scan_chars,
    )
    limiter = MultiClassRateLimiter(config.rate_limit.buckets)
    return Runtime(
        config=config,
        audit=audit,
        detector=detector,
        gateway=ContentGateway(config.prompt_injection, detector, audit),
        enforcer=PermissionEnforcer(config.permissions),
        limiter=limiter,
        scheduler=RequestScheduler(config.rate_limit, limiter),
        files=FileAccessGuard(
            config.files,
            state_dir=state_directory or state_dir(),
            audit=audit,
        ),
    )


_runtime: Runtime | None = None


def get_runtime() -> Runtime:
    """Return the process runtime, building it from configuration on first use.

    Raises:
        ConfigError: if configuration is present but unusable. Callers turn this
            into a refused operation rather than an unprotected one.
    """
    global _runtime
    if _runtime is None:
        _runtime = build_runtime(load_config())
    return _runtime


def set_runtime(runtime: Runtime) -> None:
    global _runtime
    _runtime = runtime


def reset_runtime() -> None:
    global _runtime
    if _runtime is not None:
        _runtime.audit.close()
    _runtime = None


def log_startup(runtime: Runtime) -> None:
    """Report the effective policy once, at startup."""
    config = runtime.config
    source = config.source_path or "built-in defaults (no config file found)"
    logger.info("Security configuration loaded from %s", source)
    logger.info(
        "Prompt-injection detection: %s (mode=%s, %d rules)",
        "enabled" if config.prompt_injection.enabled else "DISABLED",
        config.prompt_injection.mode.value,
        len(runtime.detector.rule_ids),
    )
    allowed = [
        name
        for name, granted in runtime.enforcer.allowed_operations().items()
        if granted
    ]
    logger.info("Permitted operations: %s", ", ".join(allowed) or "none")
    if config.permissions.chat_filtering_active:
        logger.info(
            "Chat access control active: default_policy=%s, %d allowed, %d denied",
            config.permissions.effective_default_policy,
            len(config.permissions.allowed_chats),
            len(config.permissions.denied_chats),
        )
    else:
        logger.warning(
            "Chat access control is NOT active: this server may reach every chat on "
            "the account. Set allowed_chats under [permissions] to restrict it."
        )
    if config.rate_limit.enabled:
        logger.info(
            "Rate limiting active: %dms minimum interval, max_concurrent=%d, "
            "max_retries=%d, max_flood_wait=%gs",
            config.rate_limit.minimum_interval_ms,
            config.rate_limit.max_concurrent,
            config.rate_limit.max_retries,
            config.rate_limit.max_flood_wait_seconds,
        )
    else:
        logger.warning(
            "Rate limiting is DISABLED; Telegram may flood-limit this account"
        )
    runtime.audit.record(
        "server_start",
        config_source=str(source),
        security_mode=config.prompt_injection.mode.value,
        chat_filtering=config.permissions.chat_filtering_active,
        rate_limiting=config.rate_limit.enabled,
    )
