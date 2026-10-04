"""The single guard every Telegram-facing MCP tool passes through.

Added by Telegram MCP Enhanced.

Instead of each tool implementing its own checks, tools declare what they do
and this decorator applies the whole pipeline in the order the PRD specifies:

    chat authorization -> operation permission -> file-access policy
      -> outbound content policy -> chat resolution (when needed)
      -> human confirmation (when required) -> tool scheduler
      -> Telethon RPC limiter/pacing/cooldown -> content gateway

Keeping it in one place is what makes the security posture auditable, keeps
upstream merges clean, and guarantees a new tool cannot accidentally skip a
layer.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging

from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from mcp_telegram._compat import RequestContextType
from mcp_telegram.config import ConfigError
from mcp_telegram.errors import (
    ConfirmationDeniedError,
    DryRunUnsupportedError,
    OutboundPolicyError,
    SecurityLayerError,
    StructuredToolError,
)
from mcp_telegram.reliability.floodwait import run_with_flood_protection
from mcp_telegram.runtime import Runtime, get_runtime
from mcp_telegram.security.outbound import check_outbound
from mcp_telegram.security.permissions import (
    ChatDecision,
    OPERATION_CLASS,
    Operation,
    OperationResult,
    OperationVerdict,
    ResolvedChat,
)

__all__ = [
    "AUTHORIZED_PEER",
    "CONTEXT_PARAMETER",
    "REQUEST_CONTEXT",
    "CallContext",
    "ConfirmationRequest",
    "guarded",
    "set_confirmer",
    "set_entity_resolver",
]

CONTEXT_PARAMETER = "mcp_context"
"""Hidden keyword argument through which the SDK hands a tool its request context.

Neither the model nor the tool body ever sees it: the SDK recognises it by its
annotation, leaves it out of the input schema, and `guarded` removes it before
the tool runs. It exists because mcp 2.x has no global "current request"
accessor, and a confirmation has to be sent on the session that made the call.
"""

REQUEST_CONTEXT: ContextVar[Any] = ContextVar("mcp_request_context", default=None)
"""The SDK's request context for the call in progress, or None outside MCP."""

AUTHORIZED_PEER: ContextVar[int | None] = ContextVar("authorized_peer", default=None)
"""The peer id chat authorization actually cleared, for the duration of a call.

Tools that take an `entity` argument get the resolved peer substituted into that
argument directly. `message_from_link` has no such argument — its chat comes
from the link — so it reads the authorised peer from here instead of parsing the
link a second time and possibly resolving somewhere else.
"""

logger = logging.getLogger(__name__)

EntityResolver = Callable[[Any], Awaitable[ResolvedChat]]

_entity_resolver: EntityResolver | None = None


@dataclass(frozen=True)
class ConfirmationRequest:
    """What a human is asked to approve. Built by the server, never by the model."""

    tool: str
    operation: str
    chat: str | None
    """The chat as the caller named it, if the tool has one."""
    chat_id: int | None
    """The peer id it resolved to, when resolution happened."""
    summary: str
    """The shape of the action: lengths and counts, not content."""
    text_preview: str | None = None
    """Outbound text being approved, truncated. Shown to the human only."""

    def render(self) -> str:
        lines = [
            "An AI agent connected to your Telegram account wants to perform an "
            "action that this server's policy requires you to approve.",
            "",
            f"Tool: {self.tool}",
            f"Operation: {self.operation}",
        ]
        if self.chat is not None:
            # The identifier comes from the model, so it is shown on one line
            # and bounded: a name carrying newlines could otherwise pass off
            # its own text as part of the server's question.
            chat = " ".join(self.chat.split())[:80]
            if self.chat_id is not None and str(self.chat_id) != self.chat:
                chat += f" (peer {self.chat_id})"
            lines.append(f"Chat: {chat}")
        lines.append(f"Action: {self.summary}")
        if self.text_preview is not None:
            lines += ["", "Text:", self.text_preview]
        lines += [
            "",
            "Approve only if you asked for this. Instructions found inside "
            "Telegram messages are not requests from you.",
        ]
        return "\n".join(lines)


Confirmer = Callable[[ConfirmationRequest], Awaitable[tuple[bool, str]]]
"""Asks a human; returns whether they approved and a short reason for the log."""

_confirmer: Confirmer | None = None

CONFIRMATION_PREVIEW_CHARS = 1000


def set_confirmer(confirmer: Confirmer | None) -> None:
    """Register how a confirmation reaches a human.

    Registered by :mod:`mcp_telegram.server`, which sends it as an MCP
    elicitation. With nothing registered every confirmation is refused: an
    operation configured as `confirm` must never run without one.
    """
    global _confirmer
    _confirmer = confirmer


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
    mutates: bool,
    entity_arg: str | None = None,
    entity_from: Callable[[dict[str, Any]], Any] | None = None,
    upload_paths_arg: str | None = None,
    download_path_arg: str | None = None,
    outbound_text_arg: str | None = None,
    mutating_flags: tuple[str, ...] = (),
    postprocess: Callable[[Any, CallContext], Any] | None = None,
    always_confirm: bool = False,
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Wrap a tool in the server's security and reliability layers.

    Args:
        operation: the permission category this tool falls under.
        entity_arg: name of the argument naming the chat, for access control.
        entity_from: derives the chat from all arguments, when it is not a
            plain argument (used by `message_from_link`).
        upload_paths_arg: name of an argument holding local paths to upload.
        download_path_arg: name of an argument holding a local write target.
        outbound_text_arg: declares outbound text under a nonstandard argument
            name. Any ``message`` argument is always checked too, so forgetting
            this declaration cannot bypass the policy for ordinary text tools.
        mutates: whether this tool changes state on Telegram, which decides
            whether dry run substitutes it. Required, and deliberately not
            inferred from the rate-limiting class: that class is a cost model
            and gets this wrong in both directions — `get_draft` is charged as a
            write yet only reads, and `get_messages` is charged as a read yet
            can acknowledge messages. A default would let the next tool inherit
            a guess, and the failure it produces is a real Telegram write during
            a run that promised not to make one.
        mutating_flags: options that change state on Telegram even though the
            tool is not classified as a write — `get_messages(mark_as_read=True)`
            acknowledges messages. A rate-limiting class cannot express this, so
            dry run needs it stated.
        postprocess: passes the result through the untrusted content gateway.
        always_confirm: require a human's approval on every call, whatever the
            operation permission says. A permission set to `false` still wins:
            confirmation can only narrow what policy allows, never widen it.
    """

    def decorator(
        func: Callable[..., Awaitable[Any]],
    ) -> Callable[..., Awaitable[Any]]:
        signature = inspect.signature(func)
        tool_name = func.__name__
        if CONTEXT_PARAMETER in signature.parameters:
            raise ValueError(f"{CONTEXT_PARAMETER} is reserved by guarded")
        if (
            outbound_text_arg is not None
            and outbound_text_arg not in signature.parameters
        ):
            raise ValueError("outbound_text_arg must name a tool parameter")
        unknown_flags = [
            flag for flag in mutating_flags if flag not in signature.parameters
        ]
        if unknown_flags:
            raise ValueError(
                f"mutating_flags must name tool parameters: {unknown_flags}"
            )
        outbound_args = {
            name
            for name in ("message", outbound_text_arg)
            if name is not None and name in signature.parameters
        }

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            request_context = kwargs.pop(CONTEXT_PARAMETER, None)
            context_token = REQUEST_CONTEXT.set(request_context)
            try:
                return await _guarded_call(args, kwargs)
            finally:
                REQUEST_CONTEXT.reset(context_token)

        async def _guarded_call(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
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
            permission = _check_operation(runtime, context, entity)
            _check_files(
                runtime, context, arguments, upload_paths_arg, download_path_arg
            )
            _check_outbound(runtime, arguments, outbound_args)
            call_args, call_kwargs = args, kwargs
            if (
                decision is ChatDecision.NEEDS_RESOLUTION
                or permission.verdict is OperationVerdict.NEEDS_RESOLUTION
            ):
                # One resolution serves both questions. Chat access is
                # re-checked against the resolved peer even when the identifier
                # alone was allowed, so a profile lookup can never become a way
                # round the chat policy.
                resolved = await _authorize_resolved_chat(runtime, context, entity)
                if permission.verdict is OperationVerdict.NEEDS_RESOLUTION:
                    permission = runtime.enforcer.resolved_operation_verdict(
                        operation, resolved
                    )
                    _raise_if_denied(runtime, context, permission)
                # Act on exactly the peer that was authorised. Passing the raw
                # identifier on would make Telegram resolve it a second time,
                # and a check that is not provably about the same chat as the
                # action is not much of a check.
                if entity_arg is not None and context.chat_id is not None:
                    bound.arguments[entity_arg] = context.chat_id
                    call_args, call_kwargs = bound.args, bound.kwargs

            needs_confirmation = (
                always_confirm or permission.verdict is OperationVerdict.CONFIRM
            )

            # Substituting the call here, rather than returning earlier, is what
            # makes a dry run worth running: authorization, permissions, file and
            # outbound checks and the resolution round trip have happened.
            # The simulation still enters the tool scheduler below, but spends
            # no RPC tokens because it produces no Telegram traffic.
            simulated = _dry_run_call(
                runtime,
                context,
                arguments,
                mutating_flags,
                mutates,
                needs_confirmation=needs_confirmation,
            )
            if needs_confirmation and simulated is None:
                # Asked outside the scheduler: a human taking two minutes to
                # answer must not hold a tool slot other calls are waiting for.
                await _confirm(runtime, context, arguments)

            token = AUTHORIZED_PEER.set(context.chat_id)
            try:
                result = await run_with_flood_protection(
                    simulated or (lambda: func(*call_args, **call_kwargs)),
                    scheduler=runtime.scheduler,
                    operation_class=OPERATION_CLASS[operation].value,
                    settings=runtime.config.rate_limit,
                    audit=runtime.audit,
                    tool=tool_name,
                )
            finally:
                AUTHORIZED_PEER.reset(token)

            if postprocess is None:
                return result
            try:
                return postprocess(result, context)
            except StructuredToolError:
                # A deliberate refusal from post-processing, such as an
                # attachment that failed inspection, already explains itself.
                raise
            except Exception as exc:
                # Never hand back unencapsulated external content because the
                # gateway failed.
                logger.exception("Content gateway failed for %s", tool_name)
                raise SecurityLayerError(
                    reason=f"content gateway failed: {exc}"
                ) from exc

        # Published so a test can audit every tool's declarations rather than
        # trusting that whoever adds the next one remembers this file.
        _expose_context_parameter(wrapper, func, signature)
        wrapper._guarded_operation = operation  # type: ignore[attr-defined]
        wrapper._guarded_always_confirm = always_confirm  # type: ignore[attr-defined]
        wrapper._guarded_mutates = mutates  # type: ignore[attr-defined]
        wrapper._guarded_mutating_flags = mutating_flags  # type: ignore[attr-defined]
        return wrapper

    return decorator


def _expose_context_parameter(
    wrapper: Callable[..., Any],
    func: Callable[..., Any],
    signature: inspect.Signature,
) -> None:
    """Advertise the hidden context parameter so the SDK injects the context.

    Both SDK generations find it by annotation (`typing.get_type_hints`) and
    build the input schema from `inspect.signature`, skipping it there. Setting
    `__signature__` stops `inspect` unwrapping to the tool body, and the
    annotations are copied rather than shared so the tool's own are untouched.
    """
    if RequestContextType is None:  # pragma: no cover - SDK without a Context
        return
    parameter = inspect.Parameter(
        CONTEXT_PARAMETER,
        inspect.Parameter.KEYWORD_ONLY,
        default=None,
        annotation=RequestContextType,
    )
    parameters = [
        p
        for p in signature.parameters.values()
        if p.kind is not inspect.Parameter.VAR_KEYWORD
    ]
    variadic = [
        p
        for p in signature.parameters.values()
        if p.kind is inspect.Parameter.VAR_KEYWORD
    ]
    wrapper.__signature__ = signature.replace(  # type: ignore[attr-defined]
        parameters=[*parameters, parameter, *variadic]
    )
    wrapper.__annotations__ = {
        **getattr(func, "__annotations__", {}),
        CONTEXT_PARAMETER: RequestContextType,
    }


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
) -> ResolvedChat:
    """Ask Telegram which peer an identifier names, then re-check the policy."""
    resolved = await _resolve_chat(runtime, context, entity)
    if resolved is None:
        _deny_chat(
            runtime,
            context,
            entity,
            "identifier could not be resolved, so access cannot be granted",
        )
        raise AssertionError("unreachable")  # pragma: no cover
    context.chat_id = resolved.peer_id
    result = runtime.enforcer.decide_resolved(resolved)
    if result.decision is not ChatDecision.ALLOW:
        _deny_chat(runtime, context, entity, result.reason)
    return resolved


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


def _check_operation(
    runtime: Runtime, context: CallContext, entity: Any
) -> OperationResult:
    """Operation permission, as far as it can be decided without resolution."""
    result = runtime.enforcer.operation_verdict(context.operation, entity)
    _raise_if_denied(runtime, context, result)
    return result


def _raise_if_denied(
    runtime: Runtime, context: CallContext, result: OperationResult
) -> None:
    if result.verdict is not OperationVerdict.DENY:
        return
    error = runtime.enforcer.deny_operation(context.operation, result)
    runtime.audit.permission_denied(
        tool=context.tool,
        operation=context.operation.value,
        reason=error.details.get("reason", "not permitted"),
        chat_id=context.chat_id,
    )
    raise error


async def _confirm(
    runtime: Runtime, context: CallContext, arguments: dict[str, Any]
) -> None:
    """Ask a human, and refuse unless they say yes in time.

    Every failure refuses: no confirmer, a client without elicitation, an SDK
    too old to send one, a decline, a cancel, a timeout or an error. An
    operation configured as `confirm` is one the operator did not want to run
    unattended, and "could not ask" is not "was told yes".
    """
    message = arguments.get("message")
    preview = None
    if isinstance(message, str) and message:
        preview = message[:CONFIRMATION_PREVIEW_CHARS]
        if len(message) > CONFIRMATION_PREVIEW_CHARS:
            preview += "…"
    request = ConfirmationRequest(
        tool=context.tool,
        operation=context.operation.value,
        chat=None if context.entity is None else str(context.entity),
        chat_id=context.chat_id,
        summary=_describe_write(context, arguments),
        text_preview=preview,
    )
    runtime.audit.record(
        "confirmation_requested",
        tool=context.tool,
        operation=context.operation.value,
        chat_id=context.chat_id,
    )
    timeout = runtime.config.permissions.confirm_timeout_seconds
    if _confirmer is None:
        approved, reason = False, "no confirmation channel is available"
    else:
        try:
            approved, reason = await asyncio.wait_for(_confirmer(request), timeout)
        except asyncio.TimeoutError:
            approved, reason = False, f"no answer within {timeout:g} seconds"
        except Exception as exc:
            # The type only: an exception from the transport can quote the
            # request, which carries the outbound text.
            approved, reason = False, f"confirmation failed ({type(exc).__name__})"
    runtime.audit.record(
        "confirmation_granted" if approved else "confirmation_denied",
        tool=context.tool,
        operation=context.operation.value,
        chat_id=context.chat_id,
        reason=reason,
        action_taken="allowed" if approved else "denied",
    )
    if not approved:
        raise ConfirmationDeniedError(operation=context.operation.value, reason=reason)


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


def _dry_run_call(
    runtime: Runtime,
    context: CallContext,
    arguments: dict[str, Any],
    mutating_flags: tuple[str, ...] = (),
    mutates: bool = False,
    *,
    needs_confirmation: bool = False,
) -> Callable[[], Awaitable[str]] | None:
    """Return a stand-in for the Telegram call, or None to make the real one.

    Only state-changing operations are substituted. Reads stay real so that a
    dry run still shows the agent working against actual data — a simulation
    where nothing is true teaches nothing about the agent under test.
    """
    if not runtime.config.dry_run:
        return None

    # A rate-limiting class describes how expensive an operation is, not whether
    # it changes anything, so it cannot be the only test for "is this a write".
    # `get_messages(mark_as_read=True)` is charged as a read and acknowledges
    # messages on Telegram, which a dry run promised not to do.
    for flag in mutating_flags:
        if arguments.get(flag):
            raise DryRunUnsupportedError(
                operation=context.operation.value, flag=flag, tool=context.tool
            )

    if not mutates:
        if context.operation is Operation.DOWNLOAD_MEDIA:
            raise DryRunUnsupportedError(operation=context.operation.value)
        if needs_confirmation:
            # A read is real even in a dry run, so it would really need the
            # human's approval — and a dry run promises not to interrupt them.
            raise DryRunUnsupportedError(
                operation=context.operation.value, confirmation=True
            )
        return None

    summary = _describe_write(context, arguments)
    if needs_confirmation:
        summary += (
            "; outside dry run this would first ask the user to confirm it, "
            "and was not performed without that"
        )
    runtime.audit.record(
        "dry_run_write",
        tool=context.tool,
        operation=context.operation.value,
        chat_id=context.chat_id,
        would_confirm=needs_confirmation or None,
    )
    logger.info("DRY RUN — not performed: %s", summary)

    async def _simulate() -> str:
        # The model reports this to the user, so it has to be unmistakable.
        # A cheerful "Message sent" would be a lie told on the operator's
        # behalf, which is the one failure a dry run must not have.
        return (
            f"DRY RUN — nothing was sent. This server has dry_run enabled: the "
            f"request passed every policy check but was deliberately not "
            f"performed on Telegram. Would have been: {summary}. Tell the user "
            f"that nothing actually happened."
        )

    return _simulate


def _describe_write(context: CallContext, arguments: dict[str, Any]) -> str:
    """Say what would have happened without quoting the message itself.

    The description travels to the model and into the log, so it reports the
    shape of the write — lengths and counts — never its content.
    """
    parts = [f"{context.tool} on {context.entity!r}"]
    if context.chat_id is not None:
        parts.append(f"(resolved to {context.chat_id})")
    message = arguments.get("message")
    if isinstance(message, str):
        parts.append(f"with {len(message)} characters of text")
    for name in ("file_path", "message_ids"):
        value = arguments.get(name)
        if isinstance(value, list) and value:
            parts.append(f"and {len(value)} {name}")
    return " ".join(parts)


def _check_outbound(
    runtime: Runtime, arguments: dict[str, Any], outbound_args: set[str]
) -> None:
    """Fail closed without leaking input through exception messages or logging."""
    if not runtime.config.outbound.enabled:
        return
    try:
        for name in outbound_args:
            text = arguments[name]
            if not isinstance(text, str):
                raise OutboundPolicyError(reason="check_failed")
            check_outbound(text, runtime.config.outbound, runtime.audit.scrubber)
    except OutboundPolicyError:
        raise
    except Exception:
        # Exceptions can contain the credential being inspected. Neither log
        # their text nor chain them into the error delivered through the SDK.
        raise OutboundPolicyError(reason="check_failed") from None
