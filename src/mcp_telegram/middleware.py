"""The single guard every Telegram-facing MCP tool passes through.

Added by Telegram MCP Enhanced.

Instead of each tool implementing its own checks, tools declare what they do
and this decorator applies the whole pipeline in the order the PRD specifies:

    chat authorization -> operation permission -> file-access policy
      -> rate limiter -> scheduler -> Telethon -> content gateway

Keeping it in one place is what makes the security posture auditable, keeps
upstream merges clean, and guarantees a new tool cannot accidentally skip a
layer.
"""

from __future__ import annotations

import functools
import inspect
import logging

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from mcp_telegram.config import ConfigError
from mcp_telegram.errors import SecurityLayerError, StructuredToolError
from mcp_telegram.reliability.floodwait import run_with_flood_protection
from mcp_telegram.runtime import Runtime, get_runtime
from mcp_telegram.security.permissions import (
    ChatDecision,
    OPERATION_CLASS,
    Operation,
    ResolvedChat,
)

__all__ = ["CallContext", "guarded", "set_entity_resolver"]

logger = logging.getLogger(__name__)

EntityResolver = Callable[[Any], Awaitable[ResolvedChat]]

_entity_resolver: EntityResolver | None = None


def set_entity_resolver(resolver: EntityResolver | None) -> None:
    """Register how an identifier is turned into a resolved chat identity.

    Registered by :mod:`mcp_telegram.server` so this module does not have to
    import the Telegram client, and replaceable in tests.
    """
    global _entity_resolver
    _entity_resolver = resolver


@dataclass
class CallContext:
    """What the post-processing hook needs to encapsulate a result."""

    tool: str
    operation: Operation
    runtime: Runtime
    entity: Any = None
    chat_id: int | None = None


def guarded(
    operation: Operation,
    *,
    entity_arg: str | None = None,
    entity_from: Callable[[dict[str, Any]], Any] | None = None,
    upload_paths_arg: str | None = None,
    download_path_arg: str | None = None,
    cost_from: Callable[[dict[str, Any]], float] | None = None,
    postprocess: Callable[[Any, CallContext], Any] | None = None,
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Wrap a tool in the server's security and reliability layers.

    Args:
        operation: the permission category this tool falls under.
        entity_arg: name of the argument naming the chat, for access control.
        entity_from: derives the chat from all arguments, when it is not a
            plain argument (used by `message_from_link`).
        upload_paths_arg: name of an argument holding local paths to upload.
        download_path_arg: name of an argument holding a local write target.
        cost_from: prices the call in rate-limit tokens from its arguments,
            for tools whose work scales with what the caller asked for.
        postprocess: passes the result through the untrusted content gateway.
    """

    def decorator(
        func: Callable[..., Awaitable[Any]],
    ) -> Callable[..., Awaitable[Any]]:
        signature = inspect.signature(func)
        tool_name = func.__name__

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                runtime = get_runtime()
            except ConfigError as exc:
                # Fail safe: a security layer that cannot be built refuses the
                # operation instead of running without it.
                logger.error("Refusing %s: %s", tool_name, exc)
                raise SecurityLayerError(reason=str(exc)) from exc

            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)

            entity = _extract_entity(arguments, entity_arg, entity_from)
            context = CallContext(
                tool=tool_name, operation=operation, runtime=runtime, entity=entity
            )

            # Local checks first, in the order the security hierarchy
            # specifies. Resolving an identifier costs a Telegram round trip, so
            # it waits until the free checks have all passed: an operation this
            # server would refuse anyway must not reach Telegram at all.
            decision = _authorize_chat(runtime, context, entity)
            _check_operation(runtime, context)
            _check_files(
                runtime, context, arguments, upload_paths_arg, download_path_arg
            )
            call_args, call_kwargs = args, kwargs
            if decision is ChatDecision.NEEDS_RESOLUTION:
                await _authorize_resolved_chat(runtime, context, entity)
                # Act on exactly the peer that was authorised. Passing the raw
                # identifier on would make Telegram resolve it a second time,
                # and a check that is not provably about the same chat as the
                # action is not much of a check.
                if entity_arg is not None and context.chat_id is not None:
                    bound.arguments[entity_arg] = context.chat_id
                    call_args, call_kwargs = bound.args, bound.kwargs

            result = await run_with_flood_protection(
                lambda: func(*call_args, **call_kwargs),
                scheduler=runtime.scheduler,
                operation_class=OPERATION_CLASS[operation].value,
                settings=runtime.config.rate_limit,
                audit=runtime.audit,
                tool=tool_name,
                cost=cost_from(arguments) if cost_from else 1.0,
            )

            if postprocess is None:
                return result
            try:
                return postprocess(result, context)
            except Exception as exc:
                # Never hand back unencapsulated external content because the
                # gateway failed.
                logger.exception("Content gateway failed for %s", tool_name)
                raise SecurityLayerError(
                    reason=f"content gateway failed: {exc}"
                ) from exc

        return wrapper

    return decorator


def _extract_entity(
    arguments: dict[str, Any],
    entity_arg: str | None,
    entity_from: Callable[[dict[str, Any]], Any] | None,
) -> Any:
    if entity_from is not None:
        try:
            return entity_from(arguments)
        except Exception:
            # An unparseable identifier is not authorized below.
            return None
    if entity_arg is not None:
        return arguments.get(entity_arg)
    return None


def _authorize_chat(
    runtime: Runtime, context: CallContext, entity: Any
) -> ChatDecision:
    """Chat-level access control, as far as it can go without asking Telegram.

    Returns the decision so the caller can run the resolution step later, once
    the remaining free checks have passed.
    """
    if entity is None:
        # `search_dialogs` has no single chat; its results are filtered instead.
        if (
            _requires_entity(context.operation)
            and runtime.enforcer.chat_filtering_active
        ):
            runtime.audit.permission_denied(
                tool=context.tool,
                operation=context.operation.value,
                reason="no usable chat identifier supplied",
            )
            raise runtime.enforcer.deny_chat("", "no usable chat identifier supplied")
        return ChatDecision.ALLOW

    result = runtime.enforcer.decide_chat(entity)
    if result.decision is ChatDecision.DENY:
        _deny_chat(runtime, context, entity, result.reason)
    return result.decision


async def _authorize_resolved_chat(
    runtime: Runtime, context: CallContext, entity: Any
) -> None:
    """Ask Telegram which peer an identifier names, then re-check the policy."""
    resolved = await _resolve_chat(runtime, context, entity)
    if resolved is None:
        _deny_chat(
            runtime,
            context,
            entity,
            "identifier could not be resolved, so access cannot be granted",
        )
        return
    context.chat_id = resolved.peer_id
    result = runtime.enforcer.decide_resolved(resolved)
    if result.decision is not ChatDecision.ALLOW:
        _deny_chat(runtime, context, entity, result.reason)


def _deny_chat(
    runtime: Runtime, context: CallContext, entity: Any, reason: str
) -> None:
    runtime.audit.permission_denied(
        tool=context.tool,
        operation=context.operation.value,
        reason=reason,
        chat_id=str(entity),
    )
    raise runtime.enforcer.deny_chat(entity, reason)


def _requires_entity(operation: Operation) -> bool:
    return operation not in (Operation.SEARCH_MESSAGES, Operation.RESOLVE_ENTITY)


async def _resolve_chat(
    runtime: Runtime, context: CallContext, entity: Any
) -> ResolvedChat | None:
    """Ask Telegram what peer an identifier refers to, through the scheduler."""
    if _entity_resolver is None:
        logger.warning("No entity resolver registered; cannot authorize %r", entity)
        return None
    try:
        return await run_with_flood_protection(
            lambda: _entity_resolver(entity),  # type: ignore[misc]
            scheduler=runtime.scheduler,
            operation_class=OPERATION_CLASS[Operation.RESOLVE_ENTITY].value,
            settings=runtime.config.rate_limit,
            audit=runtime.audit,
            tool=f"{context.tool}:resolve_entity",
        )
    except StructuredToolError:
        raise
    except Exception as exc:
        logger.warning("Could not resolve %r for %s: %s", entity, context.tool, exc)
        return None


def _check_operation(runtime: Runtime, context: CallContext) -> None:
    try:
        runtime.enforcer.check_operation(context.operation)
    except StructuredToolError as exc:
        runtime.audit.permission_denied(
            tool=context.tool,
            operation=context.operation.value,
            reason=exc.details.get("reason", "not permitted"),
        )
        raise


def _check_files(
    runtime: Runtime,
    context: CallContext,
    arguments: dict[str, Any],
    upload_paths_arg: str | None,
    download_path_arg: str | None,
) -> None:
    """Apply the local file policy before anything touches Telegram."""
    if upload_paths_arg:
        paths = arguments.get(upload_paths_arg) or []
        if isinstance(paths, str):
            paths = [paths]
        runtime.files.check_uploads([str(path) for path in paths], tool=context.tool)
    if download_path_arg:
        target = arguments.get(download_path_arg)
        if target:
            runtime.files.check_download_target(str(target), tool=context.tool)
