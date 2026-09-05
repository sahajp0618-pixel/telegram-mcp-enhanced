"""Chat-level access control (PRD section 20)."""

from __future__ import annotations

import pytest

from mcp_telegram.security.permissions import (
    ChatDecision,
    PermissionEnforcer,
    ResolvedChat,
    chat_tokens,
    resolved_tokens,
)

from ..conftest import make_config
from ..fakes import make_dialog


def enforcer(**permissions: object) -> PermissionEnforcer:
    return PermissionEnforcer(make_config(permissions=permissions).permissions)


def test_no_configuration_keeps_upstream_behaviour() -> None:
    guard = enforcer()
    assert guard.chat_filtering_active is False
    assert guard.decide_chat("@anyone").decision is ChatDecision.ALLOW


def test_listing_allowed_chats_denies_everything_else() -> None:
    guard = enforcer(allowed_chats=["-1001234567890"])
    assert guard.chat_filtering_active is True
    assert guard.decide_chat("-1001234567890").decision is ChatDecision.ALLOW
    assert guard.decide_chat("-1009999999999").decision is ChatDecision.DENY


def test_explicit_default_policy_wins() -> None:
    assert (
        enforcer(default_policy="deny").decide_chat("123").decision is ChatDecision.DENY
    )
    guard = enforcer(default_policy="allow", allowed_chats=["999"])
    assert guard.decide_chat("123").decision is ChatDecision.ALLOW


def test_denied_chats_override_an_allowlist() -> None:
    guard = enforcer(allowed_chats=["*"], denied_chats=["-100777"])
    assert guard.decide_chat("-100777").decision is ChatDecision.DENY
    assert (
        guard.decide_resolved(ResolvedChat(peer_id=-100888)).decision
        is ChatDecision.ALLOW
    )


def test_wildcard_allows_every_chat() -> None:
    guard = enforcer(allowed_chats=["*"])
    assert guard.decide_chat("-1005555555555").decision is ChatDecision.ALLOW


@pytest.mark.parametrize(
    "configured, requested",
    [
        ("@alice", "alice"),
        ("alice", "@alice"),
        ("ALICE", "alice"),
        ("@alice", "https://t.me/alice"),
    ],
)
def test_identifier_spellings_are_equivalent(configured: str, requested: str) -> None:
    guard = enforcer(allowed_chats=[configured])
    assert guard.decide_chat(requested).decision is ChatDecision.ALLOW


@pytest.mark.parametrize(
    "configured, resolved_id",
    [("-1001234567890", -1001234567890), ("1234567890", -1001234567890)],
)
def test_the_channel_prefix_is_reconciled_after_resolution(
    configured: str, resolved_id: int
) -> None:
    """Either spelling of a channel id names the same chat — once the type is known."""
    guard = enforcer(allowed_chats=[configured])
    assert guard.decide_chat(str(resolved_id).lstrip("-")[3:]) is not None
    assert (
        guard.decide_resolved(ResolvedChat(peer_id=resolved_id)).decision
        is ChatDecision.ALLOW
    )


def test_a_channel_allowlist_does_not_authorise_the_same_numbered_user() -> None:
    """`-1001234567890` and `1234567890` are different peers on Telegram."""
    guard = enforcer(allowed_chats=["-1001234567890"])
    assert guard.decide_chat("1234567890").decision is ChatDecision.NEEDS_RESOLUTION
    assert (
        guard.decide_resolved(ResolvedChat(peer_id=1234567890)).decision
        is ChatDecision.DENY
    )
    assert (
        guard.decide_resolved(ResolvedChat(peer_id=-1001234567890)).decision
        is ChatDecision.ALLOW
    )


def test_an_unresolvable_match_costs_no_telegram_round_trip() -> None:
    """Resolution that cannot change the answer is a wasted request and a probe."""
    guard = enforcer(allowed_chats=["-1001234567890"])
    assert guard.decide_chat("-1009999999999").decision is ChatDecision.DENY


def test_a_sign_flip_is_not_the_same_chat() -> None:
    """User 12345 and basic group -12345 are different chats."""
    guard = enforcer(allowed_chats=["12345"])
    assert guard.decide_chat("-12345").decision is ChatDecision.DENY


def test_usernames_need_resolution_before_denial() -> None:
    guard = enforcer(allowed_chats=["-1001234567890"])
    assert guard.decide_chat("@bob").decision is ChatDecision.NEEDS_RESOLUTION


def test_resolved_ids_are_checked_against_the_allowlist() -> None:
    guard = enforcer(allowed_chats=["-1001234567890"])
    allowed = ResolvedChat(peer_id=-1001234567890)
    denied = ResolvedChat(peer_id=-1009999999999)
    assert guard.decide_resolved(allowed).decision is ChatDecision.ALLOW
    assert guard.decide_resolved(denied).decision is ChatDecision.DENY


def test_a_resolved_username_satisfies_a_username_allowlist() -> None:
    """The agent gets numeric ids from search; the operator wrote a username."""
    guard = enforcer(allowed_chats=["@alice"])
    resolved = ResolvedChat(peer_id=12345, username="alice")
    assert guard.decide_resolved(resolved).decision is ChatDecision.ALLOW
    other = ResolvedChat(peer_id=999, username="mallory")
    assert guard.decide_resolved(other).decision is ChatDecision.DENY


def test_a_numeric_id_is_resolved_against_a_username_allowlist() -> None:
    """`search_dialogs` hands the agent an id, so an id must be resolvable."""
    guard = enforcer(allowed_chats=["@alice"])
    assert guard.decide_chat("12345").decision is ChatDecision.NEEDS_RESOLUTION


def test_a_numeric_id_is_denied_outright_against_a_numeric_allowlist() -> None:
    """Nothing Telegram could say makes an unlisted id into a listed one."""
    guard = enforcer(allowed_chats=["-1001234567890"])
    assert guard.decide_chat("-100999").decision is ChatDecision.DENY


def test_search_results_match_an_allowlist_written_as_a_username() -> None:
    guard = enforcer(allowed_chats=["@alice"])
    alice = make_dialog(12345, "Alice", "alice")
    mallory = make_dialog(999, "Mallory", "mallory")
    kept, withheld = guard.filter_dialogs([alice, mallory])
    assert [dialog.id for dialog in kept] == [12345]
    assert withheld == 1


def test_a_denied_username_beats_an_allowed_id_in_search_results() -> None:
    guard = enforcer(allowed_chats=["*"], denied_chats=["@mallory"])
    kept, withheld = guard.filter_dialogs([make_dialog(999, "Mallory", "mallory")])
    assert kept == [] and withheld == 1


def test_saved_messages_is_not_special_cased() -> None:
    guard = enforcer(allowed_chats=["-100123"])
    assert guard.decide_chat("me").decision is ChatDecision.NEEDS_RESOLUTION
    assert (
        enforcer(allowed_chats=["me"]).decide_chat("me").decision is ChatDecision.ALLOW
    )


def test_search_results_are_filtered_to_allowed_chats() -> None:
    guard = enforcer(allowed_chats=["-1001111111111"])
    dialogs = [make_dialog(-1001111111111), make_dialog(-1002222222222, "Other")]
    kept, withheld = guard.filter_dialogs(dialogs)
    assert [dialog.id for dialog in kept] == [-1001111111111]
    assert withheld == 1


def test_search_results_are_untouched_without_chat_filtering() -> None:
    dialogs = [make_dialog(-1001111111111), make_dialog(-1002222222222)]
    kept, withheld = enforcer().filter_dialogs(dialogs)
    assert len(kept) == 2 and withheld == 0


def test_raw_tokens_are_exact() -> None:
    """No numeric aliasing before the peer type is known."""
    assert chat_tokens("-1001234567890") == {"-1001234567890"}
    assert chat_tokens("@Alice") == {"alice"}


def test_resolved_tokens_expand_only_a_real_channel() -> None:
    channel = resolved_tokens(ResolvedChat(peer_id=-1001234567890, username="news"))
    assert channel == {"-1001234567890", "1234567890", "news"}
    user = resolved_tokens(ResolvedChat(peer_id=1234567890))
    assert user == {"1234567890"}, "a user id must not alias a channel"
