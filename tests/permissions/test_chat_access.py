"""Chat-level access control (PRD section 20)."""

from __future__ import annotations

import pytest

from mcp_telegram.security.permissions import (
    ChatDecision,
    PermissionEnforcer,
    chat_tokens,
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
    assert guard.decide_chat("-100888").decision is ChatDecision.ALLOW


def test_wildcard_allows_every_chat() -> None:
    guard = enforcer(allowed_chats=["*"])
    assert guard.decide_chat("-1005555555555").decision is ChatDecision.ALLOW


@pytest.mark.parametrize(
    "configured, requested",
    [
        ("-1001234567890", "1234567890"),
        ("1234567890", "-1001234567890"),
        ("@alice", "alice"),
        ("alice", "@alice"),
        ("ALICE", "alice"),
        ("@alice", "https://t.me/alice"),
    ],
)
def test_identifier_spellings_are_equivalent(configured: str, requested: str) -> None:
    guard = enforcer(allowed_chats=[configured])
    assert guard.decide_chat(requested).decision is ChatDecision.ALLOW


def test_a_sign_flip_is_not_the_same_chat() -> None:
    """User 12345 and basic group -12345 are different chats."""
    guard = enforcer(allowed_chats=["12345"])
    assert guard.decide_chat("-12345").decision is ChatDecision.DENY


def test_usernames_need_resolution_before_denial() -> None:
    guard = enforcer(allowed_chats=["-1001234567890"])
    assert guard.decide_chat("@bob").decision is ChatDecision.NEEDS_RESOLUTION


def test_resolved_ids_are_checked_against_the_allowlist() -> None:
    guard = enforcer(allowed_chats=["-1001234567890"])
    assert guard.decide_resolved_id(-1001234567890).decision is ChatDecision.ALLOW
    assert guard.decide_resolved_id(-1009999999999).decision is ChatDecision.DENY


def test_numeric_ids_are_never_sent_for_resolution() -> None:
    """An id that is not on the list cannot become allowed by resolving it."""
    guard = enforcer(allowed_chats=["@alice"])
    assert guard.decide_chat("-100999").decision is ChatDecision.DENY


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


def test_chat_tokens_cover_both_id_spellings() -> None:
    assert "1234567890" in chat_tokens("-1001234567890")
    assert "-1001234567890" in chat_tokens("1234567890")
