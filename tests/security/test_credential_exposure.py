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
import os
import subprocess
import sys

from typing import Any, get_args

import pytest

from mcp_telegram import errors
from mcp_telegram._compat import tool_parameter_schema
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


_FORBIDDEN_PARAMETER_HINTS = ("api_hash", "api_id", "session", "password")


def credential_parameters(schema: dict[str, Any]) -> list[str]:
    """Parameter names in ``schema`` that ask the caller for a secret."""
    return [
        name
        for name in schema.get("properties", {})
        if any(hint in name.lower() for hint in _FORBIDDEN_PARAMETER_HINTS)
    ]


def test_tool_schemas_expose_no_credential_parameter(planted, tmp_path) -> None:
    """A tool taking an api_hash argument would invite the model to ask for it."""
    install_runtime(make_config(tmp_path), tmp_path)
    from mcp_telegram.server import mcp

    tools = mcp._tool_manager.list_tools()  # type: ignore[attr-defined]
    assert tools, "no tools registered; the sweep would pass vacuously"
    inspected = 0
    for tool in tools:
        schema = tool_parameter_schema(tool)
        # An empty schema means the reader missed where this SDK keeps it, and
        # every check below would then pass without inspecting anything. Tools
        # here all take arguments except `security_status`.
        if not schema and tool.name != "security_status":
            raise AssertionError(
                f"no schema found for {tool.name}; tool_parameter_schema needs "
                "to learn where this SDK generation stores it"
            )
        if schema:
            inspected += 1
        assert_clean(schema, f"{tool.name} schema")
        assert not credential_parameters(schema), (
            f"{tool.name} asks the caller for a credential"
        )
    assert inspected >= 9, (
        f"only {inspected} tool schemas were actually read; the sweep is "
        "inspecting almost nothing"
    )


def test_the_parameter_check_would_catch_a_credential_argument() -> None:
    """Prove the guard above can fail, so a pass means something.

    A review found the original version reading a field the SDK does not use,
    so every tool produced `{}` and the check passed vacuously -- including for
    a tool deliberately registered with an `api_hash` parameter.
    """
    hostile = {
        "properties": {
            "entity": {"type": "string"},
            "api_hash": {"type": "string"},
        }
    }
    assert credential_parameters(hostile) == ["api_hash"]
    assert credential_parameters({"properties": {"entity": {"type": "string"}}}) == []


def test_the_schema_reader_finds_each_sdk_spelling() -> None:
    """`parameters`, `input_schema` and `inputSchema` have all been used."""
    schema = {"properties": {"entity": {"type": "string"}}}
    for attribute in ("parameters", "input_schema", "inputSchema"):
        tool = type("FakeTool", (), {attribute: schema})()
        assert tool_parameter_schema(tool) == schema, (
            f"the reader missed a schema stored as {attribute}"
        )
    assert tool_parameter_schema(object()) == {}


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


# -- misconfiguration, which is where the leaks actually were -------------- #

# Each of these raised an exception quoting a credential before it was fixed.
# They run in a subprocess because what matters is the *rendered traceback* on
# stderr -- what an MCP client captures into its own log file -- not the
# exception object an in-process test would inspect.
MISCONFIGURATIONS = {
    "swapped": {"API_ID": SENTINEL_HASH, "API_HASH": SENTINEL_ID},
    "id_missing": {"API_HASH": SENTINEL_HASH},
    "hash_missing": {"API_ID": SENTINEL_ID},
    "both_missing": {},
    "id_not_numeric": {"API_ID": "not-a-number", "API_HASH": SENTINEL_HASH},
    "id_empty": {"API_ID": "", "API_HASH": SENTINEL_HASH},
}

# `capture_locals=True` is the whole point. A review found a plaintext hash
# sitting in a frame local after the exception message itself had been
# sanitised: `raise ... from None` hides the exception chain and does nothing
# about locals, and `traceback.print_exc()` does not render them, so the first
# version of this probe passed while the credential was still there. Anything
# that renders locals -- rich's `show_locals`, a crash reporter, typer's own
# pretty tracebacks -- would have printed it.
_STARTUP_PROBE = """
import traceback
from mcp_telegram.telegram import Telegram
try:
    Telegram().create_client()
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
    traceback.print_exc()
    print("".join(
        traceback.TracebackException.from_exception(
            exc, capture_locals=True
        ).format()
    ))
"""


@pytest.mark.parametrize("name", sorted(MISCONFIGURATIONS))
def test_a_misconfigured_credential_is_never_echoed(name: str) -> None:
    """The most likely operator mistake must not write a secret to a log.

    Three real leaks lived here. Pydantic reports a missing field by echoing
    the whole input mapping, so `API_HASH` set with `API_ID` missing printed
    the plaintext hash. `int()` puts the offending string in its own
    `ValueError`, so swapping the two variables printed it again. And after
    both messages were sanitised, the value was still sitting in a frame local
    for any renderer that captures them.

    The probe renders the traceback both ways for that reason.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("API_ID", "API_HASH")
    }
    env.update(MISCONFIGURATIONS[name])
    result = subprocess.run(
        [sys.executable, "-c", _STARTUP_PROBE],
        capture_output=True,
        text=True,
        env=env,
    )
    assert_clean(result.stdout + result.stderr, f"startup with {name} credentials")


def test_the_misconfiguration_probe_would_notice_a_leak() -> None:
    """Prove the probe above can fail, so its passing means something."""
    with pytest.raises(AssertionError):
        assert_clean(f"ValueError: {SENTINEL_HASH}", "a deliberately leaky string")


# A failure with *valid* credentials is the harder case: the hash has to reach
# Telethon as a plain string, so it genuinely exists in a frame. What must not
# happen is for it to survive a *failure* -- an unusable session database
# unwinds through the client constructor and Telethon's own frames, both
# holding the plaintext. A corrupt or leftover session is realistic here: a
# server killed rather than shut down can leave one.
#
# The probe never binds the credential to a name of its own, or it would appear
# in the traceback by its own doing and prove nothing.
_CONSTRUCTOR_PROBE = """
import os, pathlib, traceback
from mcp_telegram.telegram import Telegram

state = pathlib.Path(os.environ["XDG_STATE_HOME"]) / "mcp-telegram"
state.mkdir(parents=True, exist_ok=True)
(state / "session.session").mkdir(exist_ok=True)   # a directory: unopenable

try:
    if os.environ["PROBE_MODE"] == "env":
        Telegram().create_client()
    else:
        Telegram().create_client(
            api_id=os.environ["API_ID"], api_hash=os.environ["API_HASH"]
        )
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
    print("".join(
        traceback.TracebackException.from_exception(
            exc, capture_locals=True
        ).format()
    ))
else:
    raise SystemExit("the session failure did not trigger")
"""


@pytest.mark.parametrize("mode", ["env", "explicit"])
def test_a_client_that_fails_to_start_does_not_print_the_hash(
    mode: str, tmp_path
) -> None:
    """Valid credentials, unusable session, traceback rendered with locals.

    Covers both routes in: the environment, and the explicit arguments `login`
    passes after a person types them at a prompt.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("API_ID", "API_HASH")
    }
    env.update(
        {
            "API_ID": SENTINEL_ID,
            "API_HASH": SENTINEL_HASH,
            "XDG_STATE_HOME": str(tmp_path),
            "PROBE_MODE": mode,
        }
    )
    result = subprocess.run(
        [sys.executable, "-c", _CONSTRUCTOR_PROBE],
        capture_output=True,
        text=True,
        env=env,
    )
    output = result.stdout + result.stderr
    assert "the session failure did not trigger" not in output, (
        "the probe no longer reproduces a constructor failure, so it proves "
        "nothing; find another way to make the session unusable"
    )
    assert_clean(output, f"client construction failure via {mode}")


# Driving `create_client` directly does not exercise `login`'s own frame,
# which holds both prompt results for the whole of connection and sign-in. A
# review pointed out that the probe above claimed to cover the login route and
# did not. This one runs the actual command with the prompts stubbed.
_LOGIN_PROBE = """
import os, pathlib, traceback
import mcp_telegram.cli as cli

state = pathlib.Path(os.environ["XDG_STATE_HOME"]) / "mcp-telegram"
state.mkdir(parents=True, exist_ok=True)
(state / "session.session").mkdir(exist_ok=True)   # a directory: unopenable

answers = iter([os.environ["API_ID"], os.environ["API_HASH"], "+15551234567"])
cli.console.input = lambda *a, **k: next(answers)

try:
    cli.login()   # the sync wrapper Typer actually invokes
except BaseException as exc:
    print(f"{type(exc).__name__}: {exc}")
    print("".join(
        traceback.TracebackException.from_exception(
            exc, capture_locals=True
        ).format()
    ))
else:
    raise SystemExit("login did not fail; the probe proves nothing")
"""


def test_the_login_command_does_not_print_the_credentials(tmp_path) -> None:
    """The real command, with the prompts stubbed and the session unusable.

    `login` reads both values from `console.input` and keeps them in its own
    frame while it connects and signs in. Clearing the callee's parameters does
    nothing about that.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("API_ID", "API_HASH")
    }
    env.update(
        {
            "API_ID": SENTINEL_ID,
            "API_HASH": SENTINEL_HASH,
            "XDG_STATE_HOME": str(tmp_path),
        }
    )
    result = subprocess.run(
        [sys.executable, "-c", _LOGIN_PROBE],
        capture_output=True,
        text=True,
        env=env,
    )
    output = result.stdout + result.stderr
    assert "login did not fail" not in output, (
        "the probe no longer reproduces a login failure, so it proves nothing"
    )
    assert_clean(output, "the login command")


def test_the_cli_never_renders_frame_locals() -> None:
    """The one setting that closes this whole class at the renderer.

    Every other test here scrubs a frame this project controls. Telethon's
    sign-in frames hold the phone number, the login code and the 2FA password
    as ordinary locals, and nothing in this codebase can reach them -- so the
    only complete fix is for the renderer never to print locals at all.

    Typer's own default for this changed between releases: `True` in 0.15.2,
    which this project's lockfile pins, `False` later. Leaving it unset makes
    the behaviour depend on which version a resolver happened to choose, which
    is not a basis for a security property.
    """
    import inspect

    import mcp_telegram.cli as cli

    assert cli.app.pretty_exceptions_show_locals is False, (
        "the CLI would render frame locals in a traceback, which prints "
        "credentials held by Telethon's frames as well as this project's"
    )
    # Checking the value alone is not enough: under a typer whose default is
    # already False it would pass while the setting was absent, and then start
    # failing for whoever resolved an older one. The point is that it is
    # stated, not that today's dependency happens to agree.
    assert "pretty_exceptions_show_locals=False" in inspect.getsource(cli), (
        "the CLI relies on typer's default for this rather than setting it; "
        "that default has differed between typer releases"
    )


# A prompt that raises is a likelier route to a traceback than a failing
# constructor: EOF in a non-interactive terminal, or an interrupt part-way
# through typing. Cleanup scoped to client construction alone missed it.
_PROMPT_FAILURE_PROBE = """
import os, traceback
import mcp_telegram.cli as cli

answers = iter([os.environ["API_ID"], os.environ["API_HASH"]])


def failing_input(*args, **kwargs):
    try:
        return next(answers)
    except StopIteration:
        raise EOFError("no input available")   # the phone prompt


cli.console.input = failing_input

try:
    cli.login()
except BaseException as exc:
    print(f"{type(exc).__name__}: {exc}")
    print("".join(
        traceback.TracebackException.from_exception(
            exc, capture_locals=True
        ).format()
    ))
else:
    raise SystemExit("login did not fail; the probe proves nothing")
"""


def test_a_prompt_that_raises_does_not_strand_the_credentials(tmp_path) -> None:
    """The API id and hash are already typed when the phone prompt fails."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("API_ID", "API_HASH")
    }
    env.update(
        {
            "API_ID": SENTINEL_ID,
            "API_HASH": SENTINEL_HASH,
            "XDG_STATE_HOME": str(tmp_path),
        }
    )
    result = subprocess.run(
        [sys.executable, "-c", _PROMPT_FAILURE_PROBE],
        capture_output=True,
        text=True,
        env=env,
    )
    output = result.stdout + result.stderr
    assert "login did not fail" not in output, (
        "the probe no longer reproduces a failing prompt, so it proves nothing"
    )
    assert_clean(output, "login interrupted at the phone prompt")


# The scrubber learns literal values from `os.environ`, which covers the server
# but not `login`, where the credentials are typed at a prompt and may be
# nowhere in the environment. The hash is still caught by shape; a numeric
# api_id matches no shape rule, so it would survive on whatever the exception
# text happened to contain. The constructor is stubbed to echo both, because a
# real Telethon failure does not quote its arguments -- this is defence in
# depth against a path that might, not a reproduction of a live leak.
_UNSEEDED_PROBE = """
import telethon
from mcp_telegram.telegram import Telegram


def boom(self, *args, **kwargs):
    raise RuntimeError(
        f"failed with api_id={kwargs.get('api_id')} "
        f"api_hash={kwargs.get('api_hash')}"
    )


telethon.TelegramClient.__init__ = boom

try:
    Telegram().create_client(api_id=API_ID_ARG, api_hash=API_HASH_ARG)
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
else:
    raise SystemExit("the constructor did not fail; the probe proves nothing")
"""


def test_credentials_typed_at_a_prompt_are_scrubbed_from_a_failure(
    tmp_path,
) -> None:
    """With nothing in the environment, the scrubber must learn from settings."""
    probe = _UNSEEDED_PROBE.replace("API_ID_ARG", repr(SENTINEL_ID)).replace(
        "API_HASH_ARG", repr(SENTINEL_HASH)
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("API_ID", "API_HASH")
    }
    env["XDG_STATE_HOME"] = str(tmp_path)
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        env=env,
    )
    output = result.stdout + result.stderr
    assert "API_ID" not in env, "the probe must run with an empty environment"
    assert "the constructor did not fail" not in output
    assert_clean(output, "a constructor failure quoting explicit credentials")


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
