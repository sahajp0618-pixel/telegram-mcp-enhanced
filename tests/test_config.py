"""Configuration loading, precedence and fail-safe behaviour (PRD sections 33, 39)."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_telegram.config import ChatPolicy, ConfigError, load_config
from mcp_telegram.security.models import SecurityMode


def write(tmp_path, body: str):
    path = tmp_path / "config.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_defaults_apply_with_no_config_file() -> None:
    config = load_config(environ={})
    assert config.prompt_injection.enabled is True
    assert config.prompt_injection.mode is SecurityMode.FLAG
    assert config.rate_limit.enabled is True
    assert config.rate_limit.minimum_interval_ms == 500
    assert config.source_path is None


def test_the_prd_configuration_shape_loads(tmp_path) -> None:
    path = write(
        tmp_path,
        """
[security.prompt_injection]
enabled = true
mode = "flag"
custom_patterns = []

[permissions]
default_policy = "deny"
allowed_chats = []
allow_read = true
allow_search = true
allow_send = true
allow_edit = false
allow_delete = false
allow_admin = false

[rate_limit]
enabled = true
minimum_interval_ms = 500
max_retries = 2
max_flood_wait_seconds = 60

[security.logging]
enabled = true
include_message_content = false
""",
    )
    config = load_config(path, environ={})
    assert config.permissions.effective_default_policy == ChatPolicy.DENY
    assert config.rate_limit.max_flood_wait_seconds == 60
    assert config.security_logging.include_message_content is False
    assert config.source_path == path


def test_environment_overrides_the_file(tmp_path) -> None:
    path = write(tmp_path, '[security.prompt_injection]\nmode = "flag"\n')
    config = load_config(path, environ={"TELEGRAM_MCP_SECURITY_MODE": "block"})
    assert config.prompt_injection.mode is SecurityMode.BLOCK


def test_config_path_comes_from_the_environment(tmp_path) -> None:
    path = write(tmp_path, "[permissions]\nallow_send = false\n")
    config = load_config(environ={"TELEGRAM_MCP_CONFIG": str(path)})
    assert config.permissions.allow_send is False


def test_a_missing_configured_file_is_an_error(tmp_path) -> None:
    with pytest.raises(ConfigError, match="missing file"):
        load_config(environ={"TELEGRAM_MCP_CONFIG": str(tmp_path / "nope.toml")})


def test_malformed_toml_is_rejected(tmp_path) -> None:
    path = write(tmp_path, "[permissions\nallow_send = true\n")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(path, environ={})


def test_a_misspelled_key_is_rejected_rather_than_ignored(tmp_path) -> None:
    """A silently ignored typo in a security setting is a security failure."""
    path = write(tmp_path, "[permissions]\nallow_delet = true\n")
    with pytest.raises(ConfigError, match="invalid configuration"):
        load_config(path, environ={})


def test_an_unknown_section_is_rejected(tmp_path) -> None:
    path = write(tmp_path, "[permission]\nallow_delete = true\n")
    with pytest.raises(ConfigError, match="unknown section"):
        load_config(path, environ={})


def test_an_unknown_security_subsection_is_rejected(tmp_path) -> None:
    path = write(tmp_path, "[security.injection]\nenabled = true\n")
    with pytest.raises(ConfigError, match="unknown section"):
        load_config(path, environ={})


def test_an_invalid_environment_value_is_rejected() -> None:
    with pytest.raises(ConfigError, match="boolean"):
        load_config(environ={"TELEGRAM_MCP_ALLOW_DELETE": "perhaps"})


def test_an_invalid_mode_is_rejected() -> None:
    with pytest.raises(ConfigError, match="invalid configuration"):
        load_config(environ={"TELEGRAM_MCP_SECURITY_MODE": "shred"})


def test_allowed_chats_can_be_set_from_the_environment() -> None:
    config = load_config(environ={"TELEGRAM_MCP_ALLOWED_CHATS": "-100123, @alice"})
    assert config.permissions.allowed_chats == ["-100123", "@alice"]
    assert config.permissions.effective_default_policy == ChatPolicy.DENY


def test_an_allowlist_implies_deny_by_default() -> None:
    config = load_config(environ={"TELEGRAM_MCP_ALLOWED_CHATS": "-100123"})
    assert config.permissions.effective_default_policy == ChatPolicy.DENY
    assert config.permissions.chat_filtering_active is True


def test_no_chat_rules_keeps_upstream_reach() -> None:
    config = load_config(environ={})
    assert config.permissions.effective_default_policy == ChatPolicy.ALLOW
    assert config.permissions.chat_filtering_active is False


def test_an_explicit_policy_overrides_the_inference() -> None:
    config = load_config(
        environ={
            "TELEGRAM_MCP_ALLOWED_CHATS": "-100123",
            "TELEGRAM_MCP_DEFAULT_CHAT_POLICY": "allow",
        }
    )
    assert config.permissions.effective_default_policy == ChatPolicy.ALLOW


def test_rate_limit_buckets_can_be_tuned_individually(tmp_path) -> None:
    path = write(
        tmp_path,
        "[rate_limit.buckets.write]\ncapacity = 1\nrefill_per_minute = 2\n",
    )
    config = load_config(path, environ={})
    assert config.rate_limit.buckets["write"].capacity == 1
    assert config.rate_limit.buckets["read"].capacity == 20, "others keep defaults"


def test_an_unknown_bucket_is_rejected(tmp_path) -> None:
    path = write(
        tmp_path,
        "[rate_limit.buckets.telepathy]\ncapacity = 1\nrefill_per_minute = 2\n",
    )
    with pytest.raises(ConfigError, match="unknown rate-limit bucket"):
        load_config(path, environ={})


def test_log_level_is_validated() -> None:
    assert load_config(environ={"TELEGRAM_MCP_LOG_LEVEL": "debug"}).log_level == "DEBUG"
    with pytest.raises(ConfigError, match="invalid log_level"):
        load_config(environ={"TELEGRAM_MCP_LOG_LEVEL": "chatty"})


def test_the_shipped_template_is_valid(tmp_path) -> None:
    from mcp_telegram.cli import CONFIG_TEMPLATE

    path = write(tmp_path, CONFIG_TEMPLATE)
    config = load_config(path, environ={})
    assert config.prompt_injection.mode is SecurityMode.FLAG
    assert config.permissions.allow_delete is False


def test_credentials_are_never_part_of_this_configuration() -> None:
    config = load_config(environ={"API_ID": "1", "API_HASH": "secret"})
    dumped = config.model_dump_json()
    assert "secret" not in dumped
    assert "api_hash" not in dumped.lower()


def test_every_setting_and_operation_is_documented() -> None:
    """Docs drift silently; a test does not."""
    import pathlib

    from mcp_telegram.config import Config
    from mcp_telegram.security.injection import DEFAULT_RULES, STRUCTURAL_RULE_IDS
    from mcp_telegram.security.permissions import Operation

    reference = pathlib.Path("docs/CONFIGURATION.md").read_text()

    def leaf_fields(model: type) -> list[str]:
        names: list[str] = []
        for name, field in model.model_fields.items():
            annotation = field.annotation
            if hasattr(annotation, "model_fields"):
                names += leaf_fields(annotation)  # type: ignore[arg-type]
            else:
                names.append(name)
        return names

    undocumented = [
        name
        for name in leaf_fields(Config)
        if name != "source_path" and name not in reference
    ]
    assert undocumented == [], f"settings missing from the reference: {undocumented}"

    missing_rules = [rule.id for rule in DEFAULT_RULES if rule.id not in reference]
    assert missing_rules == [], f"rules missing from the reference: {missing_rules}"

    missing_structural = [
        rule_id for rule_id in STRUCTURAL_RULE_IDS if rule_id not in reference
    ]
    assert missing_structural == []

    missing_operations = [
        operation.value
        for operation in Operation
        if operation is not Operation.RESOLVE_ENTITY
        and operation.value not in reference
    ]
    assert missing_operations == []


@pytest.mark.parametrize(
    ("preset", "drafts", "download", "policy", "mode", "interval", "concurrent"),
    [
        ("read-only", False, True, "allow", "flag", 500, 2),
        ("assistant", True, True, "allow", "flag", 500, 2),
        ("locked-down", False, False, "deny", "block", 1000, 1),
    ],
)
def test_presets_load_with_the_claimed_policy(
    tmp_path: Path,
    preset: str,
    drafts: bool,
    download: bool,
    policy: str,
    mode: str,
    interval: int,
    concurrent: int,
) -> None:
    """Exercise the written file so CLI selection and policy cannot drift apart."""
    from typer.testing import CliRunner

    from mcp_telegram.cli import app
    from mcp_telegram.config import Config

    path = tmp_path / "custom.toml"
    path.write_text("existing policy", encoding="utf-8")
    args = ["init-config", "--preset", preset, "--path", str(path)]
    runner = CliRunner()
    assert runner.invoke(app, args).exit_code != 0
    assert path.read_text() == "existing policy"
    result = runner.invoke(app, [*args, "--force"])
    assert result.exit_code == 0, result.output
    config = load_config(path, environ={})
    assert config.permissions.model_dump() == {
        "default_policy": "deny" if policy == "deny" else None,
        "allowed_chats": [],
        "denied_chats": [],
        "allow_read": True,
        "allow_search": True,
        "allow_send": False,
        "allow_edit": False,
        "allow_delete": False,
        "allow_drafts": drafts,
        "allow_download": download,
        "allow_admin": False,
    }
    assert config.permissions.effective_default_policy == policy
    expected = Config()
    expected.permissions = config.permissions
    expected.prompt_injection.mode = SecurityMode(mode)
    expected.rate_limit.minimum_interval_ms = interval
    expected.rate_limit.max_concurrent = concurrent
    assert config.model_dump(exclude={"source_path"}) == expected.model_dump(
        exclude={"source_path"}
    )


def test_locked_down_denies_chats_until_allowlist_is_filled(tmp_path: Path) -> None:
    """An empty allowlist must refuse real access, not just look restrictive."""
    from mcp_telegram.cli import ConfigPreset, _preset_template
    from mcp_telegram.security.permissions import (
        ChatDecision,
        PermissionEnforcer,
        ResolvedChat,
    )

    body = _preset_template(ConfigPreset.LOCKED_DOWN)
    placeholder = '# allowed_chats = ["-1001234567890"]'
    assert placeholder in body
    path = write(tmp_path, body)
    enforcer = PermissionEnforcer(load_config(path, environ={}).permissions)
    for entity in ("me", "@alice", "-1001234567890", 12345):
        assert enforcer.decide_chat(entity).decision is ChatDecision.DENY
    assert (
        enforcer.decide_resolved(
            ResolvedChat(peer_id=-1001234567890, username="alice")
        ).decision
        is ChatDecision.DENY
    )
    path.write_text(body.replace(placeholder, placeholder[2:]), encoding="utf-8")
    enforcer = PermissionEnforcer(load_config(path, environ={}).permissions)
    assert enforcer.is_chat_allowed(-1001234567890)
    assert not enforcer.is_chat_allowed(12345)


def test_init_config_without_preset_preserves_original_template(tmp_path: Path) -> None:
    """Existing setup scripts must keep producing the same starter policy."""
    from typer.testing import CliRunner

    from mcp_telegram.cli import CONFIG_TEMPLATE, app

    path = tmp_path / "config.toml"
    result = CliRunner().invoke(app, ["init-config", "--path", str(path)])
    assert result.exit_code == 0, result.output
    assert path.read_text() == CONFIG_TEMPLATE


def test_init_config_help_lists_presets() -> None:
    """Operators should not need an external reference to discover valid choices."""
    from typer.testing import CliRunner

    from mcp_telegram.cli import app

    result = CliRunner().invoke(app, ["init-config", "--help"], terminal_width=120)
    assert result.exit_code == 0
    for name in ("read-only", "assistant", "locked-down"):
        assert name in result.output


def test_invalid_preset_fails_without_writing(tmp_path: Path) -> None:
    """A typo must never silently generate a more permissive policy."""
    from typer.testing import CliRunner

    from mcp_telegram.cli import app

    path = tmp_path / "config.toml"
    path.write_text("existing policy", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        ["init-config", "--preset", "unknown", "--path", str(path), "--force"],
    )
    assert result.exit_code != 0
    assert "Invalid value" in result.output
    assert "unknown" in result.output
    assert "Traceback" not in result.output
    assert path.read_text() == "existing policy"


def test_a_deny_all_configuration_warns_that_nothing_will_work(caplog) -> None:
    """Correct and completely inert looks exactly like broken.

    `default_policy = "deny"` with an empty `allowed_chats` refuses every call.
    The locked-down preset ships in that state deliberately, so the operator has
    to be told plainly rather than left reading INFO lines that sound healthy.
    """
    import logging

    from mcp_telegram.runtime import build_runtime, log_startup

    config = load_config(environ={"TELEGRAM_MCP_DEFAULT_CHAT_POLICY": "deny"})
    assert config.permissions.allowed_chats == []

    with caplog.at_level(logging.WARNING):
        log_startup(build_runtime(config))

    warnings = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("denies EVERY chat" in message for message in warnings), warnings
    assert any("allowed_chats" in message for message in warnings)


def test_a_configured_allowlist_does_not_trigger_the_deny_all_warning(caplog) -> None:
    import logging

    from mcp_telegram.runtime import build_runtime, log_startup

    config = load_config(environ={"TELEGRAM_MCP_ALLOWED_CHATS": "-1001234567890"})
    with caplog.at_level(logging.WARNING):
        log_startup(build_runtime(config))
    assert not any("denies EVERY chat" in r.message for r in caplog.records)


def test_the_sensitive_file_globs_are_documented_exactly() -> None:
    """The refusal list is a security claim, so the docs must match the code.

    An audit found the reference listing `credentials*` where the code has
    `credentials` and `credentials.*` -- a wildcard that would also deny an
    unrelated `credentialsReport.csv` -- and omitting eleven real patterns
    including `.env.*`, `*.pfx` and `shadow`. An operator reading it could not
    tell what would actually be refused.
    """
    import pathlib

    from mcp_telegram.security.files import SENSITIVE_FILE_GLOBS

    reference = pathlib.Path("docs/CONFIGURATION.md").read_text()
    undocumented = sorted(
        glob for glob in SENSITIVE_FILE_GLOBS if f"`{glob}`" not in reference
    )
    assert not undocumented, (
        "these patterns are refused but not listed in docs/CONFIGURATION.md: "
        f"{undocumented}"
    )


def test_every_audit_event_is_documented() -> None:
    """A security log is only useful if its vocabulary is written down."""
    import pathlib
    import re

    reference = pathlib.Path("docs/CONFIGURATION.md").read_text()
    source = " ".join(
        path.read_text() for path in pathlib.Path("src/mcp_telegram").rglob("*.py")
    )
    emitted = set(re.findall(r'audit\.record\(\s*"([a-z_]+)"', source))
    assert emitted, "no audit events found; the check would pass vacuously"
    undocumented = sorted(event for event in emitted if f"`{event}`" not in reference)
    assert not undocumented, (
        f"these audit events are emitted but not documented: {undocumented}"
    )
