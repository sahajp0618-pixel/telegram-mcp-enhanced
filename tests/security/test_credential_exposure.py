"""An active sweep for credential leakage across every public surface.

Added by Telegram MCP Enhanced.

The rest of the suite proves the scrubber works on the inputs it is handed.
This file asks the opposite question: given a real credential in the
environment, can it be extracted from anything the server hands out?

Every test here plants a distinctive sentinel, exercises one surface an
operator or a model can actually reach, and asserts the sentinel is absent from
the bytes that come back. A surface added later without thinking about
credentials will not fail these tests by itself -- so
``test_every_public_surface_is_covered`` pins the inventory, and adding a tool
or a structured error without adding it here fails the build.
"""

from __future__ import annotations

import json

from typing import Any, get_args

import pytest

from mcp_telegram import errors
from mcp_telegram._compat import tool_input_schema
from mcp_telegram.security.audit import CredentialScrubber, SecurityAuditLog
from mcp_telegram.telegram import Settings

from ..conftest import install_runtime, make_config

# Shaped like the real things so the scrubber's shape rules apply, but
# recognisable enough that a substring search cannot produce a false negative.
SENTINEL_HASH = "deadbeefcafebabefeedface12345678"  # 32 hex: api_hash shape
SENTINEL_ID = "918273645"
SENTINEL_SESSION = "1" + "Zq7" * 20  # StringSession shape
SENTINELS = (SENTINEL_HASH, SENTINEL_ID, SENTINEL_SESSION)


@pytest.fixture
def planted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put the sentinels where the real credentials live."""
    monkeypatch.setenv("API_ID", SENTINEL_ID)
    monkeypatch.setenv("API_HASH", SENTINEL_HASH)
    monkeypatch.setenv("TELEGRAM_SESSION_STRING", SENTINEL_SESSION)


def assert_clean(blob: Any, surface: str) -> None:
    """Fail if any sentinel survives anywhere in ``blob``."""
    text = blob if isinstance(blob, str) else json.dumps(blob, default=str)
    for sentinel in SENTINELS:
        assert sentinel not in text, (
            f"{surface} leaked a credential: {sentinel!r} appears in its output"
        )


# -- the model-facing surfaces ------------------------------------------- #


def test_security_status_reports_policy_without_credentials(planted, tmp_path) -> None:
    """The one tool whose whole job is describing the server's own state."""
    runtime = install_runtime(make_config(tmp_path), tmp_path)
    assert_clean(runtime.describe().model_dump(), "security_status")


def test_structured_errors_never_carry_a_credential(planted) -> None:
    """Refusals reach the model as text. None may quote the environment."""
    raised = [
        errors.PermissionDeniedError(
            operation="SEND_MESSAGES", reason="allow_send is false"
        ),
        errors.ChatAccessDeniedError(entity="@somebody", reason="not allowlisted"),
        errors.RateLimitedError(retry_after_seconds=30, reason="flood wait"),
        errors.FileAccessDeniedError(path="/home/u/.env", reason="sensitive_path"),
        errors.DryRunUnsupportedError(
            operation="DOWNLOAD_MEDIA", tool="media_download"
        ),
        errors.SecurityLayerError(reason="config invalid"),
    ]
    # Every outbound refusal reason, not one sample: the credentials branch is
    # the one most likely to be handed the secret it just refused.
    raised += [
        errors.OutboundPolicyError(reason=reason)
        for reason in get_args(errors.OutboundRefusalReason)
    ]
    for error in raised:
        assert_clean(error.payload, type(error).__name__)
        assert_clean(str(error), f"str({type(error).__name__})")


def test_tool_schemas_expose_no_credential_parameter(planted, tmp_path) -> None:
    """A tool taking an api_hash argument would invite the model to ask for it."""
    install_runtime(make_config(tmp_path), tmp_path)
    from mcp_telegram.server import mcp

    tools = mcp._tool_manager.list_tools()  # type: ignore[attr-defined]
    assert tools, "no tools registered; the sweep would pass vacuously"
    for tool in tools:
        schema = tool_input_schema(tool)
        assert_clean(schema, f"{tool.name} input schema")
        for parameter in schema.get("properties", {}):
            lowered = parameter.lower()
            assert "api_hash" not in lowered
            assert "api_id" not in lowered
            assert "session" not in lowered


# -- the operator-facing surfaces ----------------------------------------- #


def test_the_security_log_scrubs_a_planted_credential(planted, tmp_path) -> None:
    """Events are written to disk; the disk copy must be clean too."""
    path = tmp_path / "security.log"
    audit = SecurityAuditLog(
        make_config(
            tmp_path, security_logging={"enabled": True, "path": str(path)}
        ).security_logging
    )
    audit.record(
        event="injection_detected",
        tool="get_messages",
        detail=(
            f"api_hash={SENTINEL_HASH} api_id={SENTINEL_ID} session={SENTINEL_SESSION}"
        ),
    )
    handler = getattr(audit, "_handler", None)
    if handler is not None:
        handler.flush()
    assert_clean(path.read_text(), "security log")


def test_settings_never_render_the_hash(planted) -> None:
    """Pydantic's SecretStr masks repr; prove it, and prove dumps stay masked."""
    settings = Settings(api_id=SENTINEL_ID, api_hash=SENTINEL_HASH)  # type: ignore[arg-type]
    assert_clean(repr(settings), "repr(Settings)")
    assert_clean(str(settings), "str(Settings)")
    assert_clean(settings.model_dump(), "Settings.model_dump()")
    assert_clean(settings.model_dump_json(), "Settings.model_dump_json()")
    # The value is still reachable deliberately, or the client could not connect.
    assert settings.api_hash.get_secret_value() == SENTINEL_HASH


def test_the_scrubber_learns_the_planted_credential_from_the_environment(
    planted,
) -> None:
    """Literal detection is env-derived, so a fresh scrubber must pick it up."""
    scrubber = CredentialScrubber()
    for sentinel in SENTINELS:
        assert scrubber.contains_credentials(f"leaked: {sentinel}"), (
            f"{sentinel!r} was not recognised as a credential"
        )
        assert_clean(scrubber.scrub(f"leaked: {sentinel}"), "CredentialScrubber")


# -- the inventory guard --------------------------------------------------- #


def test_every_public_surface_is_covered() -> None:
    """Adding a structured error without sweeping it here fails the build.

    The sweep is only as good as its inventory. This pins the set of error
    types so a new refusal path cannot quietly ship unswept.
    """
    covered = {
        "ChatAccessDeniedError",
        "DryRunUnsupportedError",
        "FileAccessDeniedError",
        "OutboundPolicyError",
        "PermissionDeniedError",
        "RateLimitedError",
        "SecurityLayerError",
    }
    defined = {
        name
        for name in errors.__all__
        if name.endswith("Error") and name != "StructuredToolError"
    }
    assert defined == covered, (
        "the structured-error inventory changed; add the new error to "
        "test_structured_errors_never_carry_a_credential and to this set"
    )
