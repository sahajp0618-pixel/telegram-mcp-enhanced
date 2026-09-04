"""Independent operation permissions (PRD sections 19, 21, 42)."""

from __future__ import annotations

import pytest

from mcp_telegram.errors import PermissionDeniedError
from mcp_telegram.security.permissions import Operation, PermissionEnforcer

from ..conftest import make_config


def enforcer(**permissions: object) -> PermissionEnforcer:
    return PermissionEnforcer(make_config(permissions=permissions).permissions)


def test_defaults_allow_reading_but_not_destructive_writes() -> None:
    guard = enforcer()
    guard.check_operation(Operation.READ_MESSAGES)
    guard.check_operation(Operation.SEARCH_MESSAGES)
    guard.check_operation(Operation.SEND_MESSAGES)
    for operation in (
        Operation.EDIT_MESSAGES,
        Operation.DELETE_MESSAGES,
        Operation.ADMINISTRATIVE_ACTIONS,
    ):
        with pytest.raises(PermissionDeniedError):
            guard.check_operation(operation)


INDEPENDENT = [
    ("allow_read", Operation.READ_MESSAGES),
    ("allow_search", Operation.SEARCH_MESSAGES),
    ("allow_send", Operation.SEND_MESSAGES),
    ("allow_edit", Operation.EDIT_MESSAGES),
    ("allow_delete", Operation.DELETE_MESSAGES),
    ("allow_drafts", Operation.MANAGE_DRAFTS),
    ("allow_download", Operation.DOWNLOAD_MEDIA),
    ("allow_admin", Operation.ADMINISTRATIVE_ACTIONS),
]


@pytest.mark.parametrize("flag, operation", INDEPENDENT)
def test_each_permission_is_controlled_independently(flag: str, operation) -> None:
    """Granting one capability must not grant any other."""
    only_this = {name: False for name, _ in INDEPENDENT}
    only_this[flag] = True
    guard = enforcer(**only_this)

    guard.check_operation(operation)
    for other_flag, other_operation in INDEPENDENT:
        if other_flag == flag:
            continue
        with pytest.raises(PermissionDeniedError):
            guard.check_operation(other_operation)


def test_read_access_does_not_imply_write_access() -> None:
    guard = enforcer(
        allow_read=True, allow_send=False, allow_edit=False, allow_delete=False
    )
    guard.check_operation(Operation.READ_MESSAGES)
    for operation in (
        Operation.SEND_MESSAGES,
        Operation.EDIT_MESSAGES,
        Operation.DELETE_MESSAGES,
    ):
        with pytest.raises(PermissionDeniedError):
            guard.check_operation(operation)


def test_denial_explains_itself_without_leaking_configuration() -> None:
    guard = enforcer(allow_delete=False)
    with pytest.raises(PermissionDeniedError) as excinfo:
        guard.check_operation(Operation.DELETE_MESSAGES)
    payload = excinfo.value.payload
    assert payload["status"] == "permission_denied"
    assert payload["operation"] == "DELETE_MESSAGES"
    assert payload["retryable"] is False
    assert "allow_delete" in payload["reason"]
    assert "model cannot change this" in payload["hint"]


def test_allowed_operations_summary_covers_every_category() -> None:
    summary = enforcer().allowed_operations()
    assert set(summary) == {
        operation.value
        for operation in Operation
        if operation is not Operation.RESOLVE_ENTITY
    }
