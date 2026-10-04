"""Per-chat permission profiles (roadmap item 8).

A profile changes what may be done in a chat. It must never change whether the
chat can be reached, and it must be judged on the chat Telegram confirms, not
on the text the agent wrote.
"""

from __future__ import annotations

import pytest

from mcp_telegram import server
from mcp_telegram.config import ConfigError, load_config
from mcp_telegram.errors import ChatAccessDeniedError, PermissionDeniedError
from mcp_telegram.security.permissions import (
    Operation,
    OperationVerdict,
    PermissionEnforcer,
    ResolvedChat,
)

from ..conftest import install_runtime, make_config

ALICE = 1111
COMPANY = -1002222222222


def enforcer(**permissions: object) -> PermissionEnforcer:
    return PermissionEnforcer(make_config(permissions=permissions).permissions)


def write(tmp_path, body: str):
    path = tmp_path / "config.toml"
    path.write_text(body, encoding="utf-8")
    return path


# -- configuration ----------------------------------------------------------- #


def test_profiles_load_from_toml(tmp_path) -> None:
    path = write(
        tmp_path,
        """
[permissions]
allow_send = false

[[permissions.profiles]]
chats = ["-1002222222222"]
allow_download = false

[[permissions.profiles]]
chats = ["@alice", 1111]
allow_send = true
allow_delete = "confirm"
""",
    )
    permissions = load_config(path, environ={}).permissions
    assert [p.chats for p in permissions.profiles] == [
        ["-1002222222222"],
        ["@alice", "1111"],
    ]
    assert permissions.profiles[1].allow_delete == "confirm"
    assert permissions.profiles[1].allow_read is None


@pytest.mark.parametrize("key", ["allow_search", "allow_admin"])
def test_global_only_permissions_are_refused_in_a_profile(tmp_path, key) -> None:
    path = write(
        tmp_path, f'[[permissions.profiles]]\nchats = ["@alice"]\n{key} = true\n'
    )
    with pytest.raises(ConfigError, match=f"{key} cannot be set per chat"):
        load_config(path, environ={})


def test_a_profile_cannot_match_every_chat(tmp_path) -> None:
    path = write(
        tmp_path, '[[permissions.profiles]]\nchats = ["*"]\nallow_send = true\n'
    )
    with pytest.raises(ConfigError, match="cannot match"):
        load_config(path, environ={})


def test_a_profile_must_name_a_chat(tmp_path) -> None:
    path = write(tmp_path, "[[permissions.profiles]]\nchats = []\nallow_send = true\n")
    with pytest.raises(ConfigError):
        load_config(path, environ={})


@pytest.mark.parametrize("value", ['"true"', '"yes"', '"ask"', "1"])
def test_permission_values_are_not_guessed(tmp_path, value) -> None:
    """A quoted boolean is a typo; reading it leniently is how policy drifts."""
    path = write(tmp_path, f"[permissions]\nallow_send = {value}\n")
    with pytest.raises(ConfigError):
        load_config(path, environ={})


def test_unknown_profile_keys_are_refused(tmp_path) -> None:
    path = write(
        tmp_path, '[[permissions.profiles]]\nchats = ["@a"]\nallow_snd = true\n'
    )
    with pytest.raises(ConfigError):
        load_config(path, environ={})


# -- verdicts ---------------------------------------------------------------- #


def test_without_profiles_the_global_setting_decides_without_resolution() -> None:
    guard = enforcer(allow_send=False)
    result = guard.operation_verdict(Operation.SEND_MESSAGES, "@alice")
    assert result.verdict is OperationVerdict.DENY
    assert result.profile_index is None


def test_agreeing_profiles_need_no_resolution() -> None:
    guard = enforcer(
        allow_send=True, profiles=[{"chats": ["@alice"], "allow_send": True}]
    )
    assert (
        guard.operation_verdict(Operation.SEND_MESSAGES, "@bob").verdict
        is OperationVerdict.ALLOW
    )


def test_disagreeing_profiles_require_resolution_even_for_an_exact_id() -> None:
    """An id matching textually is not enough: an earlier profile might match
    the same peer by username, and first match wins."""
    guard = enforcer(
        allow_send=False,
        profiles=[{"chats": [str(ALICE)], "allow_send": True}],
    )
    assert (
        guard.operation_verdict(Operation.SEND_MESSAGES, str(ALICE)).verdict
        is OperationVerdict.NEEDS_RESOLUTION
    )


def test_resolved_profile_matches_by_id_or_username() -> None:
    guard = enforcer(
        allow_send=False, profiles=[{"chats": ["@alice"], "allow_send": True}]
    )
    by_name = guard.resolved_operation_verdict(
        Operation.SEND_MESSAGES, ResolvedChat(peer_id=ALICE, username="Alice")
    )
    assert by_name.verdict is OperationVerdict.ALLOW
    assert by_name.profile_index == 0
    other = guard.resolved_operation_verdict(
        Operation.SEND_MESSAGES, ResolvedChat(peer_id=9, username="mallory")
    )
    assert other.verdict is OperationVerdict.DENY
    assert other.profile_index is None


def test_first_matching_profile_decides_and_unset_falls_back_to_global() -> None:
    guard = enforcer(
        allow_send=True,
        allow_delete=False,
        profiles=[
            {"chats": ["@alice"], "allow_delete": "confirm"},
            {"chats": ["@alice"], "allow_send": False, "allow_delete": True},
        ],
    )
    alice = ResolvedChat(peer_id=ALICE, username="alice")
    assert (
        guard.resolved_operation_verdict(Operation.DELETE_MESSAGES, alice).verdict
        is OperationVerdict.CONFIRM
    )
    # The first profile leaves allow_send unset: global wins, the second
    # profile is never consulted.
    assert (
        guard.resolved_operation_verdict(Operation.SEND_MESSAGES, alice).verdict
        is OperationVerdict.ALLOW
    )


def test_unmarked_channel_id_in_a_profile_matches_the_resolved_channel() -> None:
    guard = enforcer(
        allow_read=True, profiles=[{"chats": ["2222222222"], "allow_read": False}]
    )
    assert (
        guard.resolved_operation_verdict(
            Operation.READ_MESSAGES, ResolvedChat(peer_id=COMPANY)
        ).verdict
        is OperationVerdict.DENY
    )


def test_search_is_never_decided_by_a_profile() -> None:
    guard = enforcer(
        allow_search=False, profiles=[{"chats": ["@a"], "allow_read": True}]
    )
    assert (
        guard.operation_verdict(Operation.SEARCH_MESSAGES, "@a").verdict
        is OperationVerdict.DENY
    )


# -- through the real tools -------------------------------------------------- #


@pytest.fixture
def chats(fake_tg):
    fake_tg.peer_ids.update({"alice": ALICE, "company": COMPANY})
    fake_tg.usernames.update(
        {
            "alice": "alice",
            str(ALICE): "alice",
            "company": "company",
            str(COMPANY): "company",
        }
    )
    return fake_tg


async def test_a_profile_enables_sending_in_one_chat_only(tmp_path, chats) -> None:
    install_runtime(
        make_config(
            tmp_path,
            permissions={
                "allow_send": False,
                "profiles": [{"chats": ["@alice"], "allow_send": True}],
            },
        ),
        tmp_path,
    )
    await server.send_message(entity="@alice", message="hi")
    # Executed against the peer that was checked, not the raw name.
    assert chats.calls[-1][0] == "send_message"
    assert chats.calls[-1][1][0] == ALICE

    with pytest.raises(PermissionDeniedError, match="SEND_MESSAGES"):
        await server.send_message(entity="@company", message="hi")
    assert [c for c in chats.called if c == "send_message"] == ["send_message"]


async def test_the_alias_an_agent_uses_does_not_change_the_profile(
    tmp_path, chats
) -> None:
    """Naming Alice by id must hit the profile written with her username."""
    install_runtime(
        make_config(
            tmp_path,
            permissions={
                "allow_send": True,
                "profiles": [{"chats": ["@alice"], "allow_send": False}],
            },
        ),
        tmp_path,
    )
    with pytest.raises(PermissionDeniedError) as raised:
        await server.send_message(entity=str(ALICE), message="hi")
    assert "profiles" in raised.value.details["reason"]
    assert "send_message" not in chats.called


async def test_a_profile_never_grants_chat_access(tmp_path, chats) -> None:
    install_runtime(
        make_config(
            tmp_path,
            permissions={
                "allowed_chats": ["@company"],
                "profiles": [{"chats": ["@alice"], "allow_send": True}],
                "allow_send": False,
            },
        ),
        tmp_path,
    )
    with pytest.raises(ChatAccessDeniedError):
        await server.send_message(entity="@alice", message="hi")
    assert "send_message" not in chats.called


async def test_an_unresolvable_chat_is_refused_when_profiles_disagree(
    tmp_path, chats
) -> None:
    install_runtime(
        make_config(
            tmp_path,
            permissions={
                "allow_send": False,
                "profiles": [{"chats": ["@alice"], "allow_send": True}],
            },
        ),
        tmp_path,
    )
    with pytest.raises(ChatAccessDeniedError, match="resolved"):
        await server.send_message(entity="@ghost", message="hi")
    assert "send_message" not in chats.called


async def test_no_resolution_when_every_profile_agrees(tmp_path, chats) -> None:
    install_runtime(
        make_config(
            tmp_path,
            permissions={
                "allow_read": True,
                "profiles": [{"chats": ["@alice"], "allow_read": True}],
            },
        ),
        tmp_path,
    )
    await server.get_messages(entity="12345")
    assert "resolve_chat_identity" not in chats.called


async def test_a_profile_denial_is_audited_with_the_resolved_chat(
    tmp_path, chats
) -> None:
    runtime = install_runtime(
        make_config(
            tmp_path,
            security_logging={"enabled": True},
            permissions={
                "allow_read": True,
                "profiles": [{"chats": ["@company"], "allow_read": False}],
            },
        ),
        tmp_path,
    )
    with pytest.raises(PermissionDeniedError):
        await server.get_messages(entity="@company")
    runtime.audit.close()
    log = (tmp_path / "security.log").read_text()
    assert '"permission_denied"' in log
    assert str(COMPANY) in log
