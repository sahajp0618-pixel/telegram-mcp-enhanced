"""Prompt-injection detection for externally supplied Telegram content.

Added by Telegram MCP Enhanced.

Detection produces a *risk signal*, never a claim of intent, and is only one
layer of the defence in depth described in the PRD. It runs entirely locally:
no content leaves the machine, no external API is called, and every pattern is
compiled once at initialisation.
"""

from __future__ import annotations

import re
import unicodedata

from dataclasses import dataclass, field

from mcp_telegram.security.models import Classification, PatternRule

__all__ = [
    "DEFAULT_RULES",
    "DetectionResult",
    "InjectionDetector",
    "RuleMatch",
    "normalize_with_map",
]

MAX_MATCHES = 50
"""Upper bound on recorded matches so a hostile message cannot burn CPU.

This caps what is *recorded*, never what is *evaluated*: every rule is always
run, so padding a message with cheap low-severity hits cannot stop a later rule
from firing and cannot lower the classification.
"""

MAX_MATCHES_PER_RULE = 10
"""Upper bound on recorded matches from any single rule."""

MAX_STRUCTURAL_RUNS = 20
"""Upper bound on reported runs of hidden characters per category."""

_STRUCTURAL_RULES: dict[str, tuple[Classification, str]] = {}
"""Populated below, once Classification aliases are defined."""

_WHITESPACE_RUN = re.compile(r"\s{80,}")
_BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩")
_TAG_RANGE = range(0xE0000, 0xE0080)

# Latin lookalikes used to slip past word-boundary patterns. Folded only in the
# matching view; the original text is never altered by normalisation.
_CONFUSABLES = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ѕ": "s",
    "һ": "h",
    "ԁ": "d",
    "ɡ": "g",
    "ı": "i",
    "ο": "o",
    "α": "a",
    "ε": "e",
    "ρ": "p",
    "τ": "t",
    "ν": "v",
    "ι": "i",
    "κ": "k",
    "Β": "B",
    "А": "A",
    "Е": "E",
    "О": "O",
    "С": "C",
    "Р": "P",
    "Х": "X",
    "М": "M",
    "Н": "H",
}


def normalize_with_map(text: str) -> tuple[str, list[int] | None]:
    """Return a match-friendly view of ``text`` plus an offset map.

    The view folds compatibility forms (NFKC), maps common homoglyphs to ASCII,
    drops Unicode format characters (zero-width, bidi, tag characters) and
    collapses long whitespace runs. ``map[i]`` is the index in ``text`` that
    produced character ``i`` of the view, so a match found in the view can be
    redacted at the right place in the untouched original. ``None`` is returned
    instead of a map when the view is character-for-character the original,
    which is the common case: plain ASCII needs no normalisation at all.
    """
    if text.isascii():
        return text, None

    out: list[str] = []
    offsets: list[int] = []
    prev_was_space = False

    for index, char in enumerate(text):
        if unicodedata.category(char) == "Cf":
            continue
        if char.isspace():
            if prev_was_space:
                continue
            prev_was_space = True
            out.append(" ")
            offsets.append(index)
            continue
        prev_was_space = False
        folded = _CONFUSABLES.get(char, char)
        for produced in unicodedata.normalize("NFKC", folded):
            out.append(produced)
            offsets.append(index)

    return "".join(out), offsets


@dataclass(frozen=True)
class RuleMatch:
    """One rule firing, with offsets into the *original* text."""

    rule_id: str
    classification: Classification
    start: int
    end: int
    description: str = ""


@dataclass
class DetectionResult:
    """Outcome of scanning one piece of external content."""

    classification: Classification = Classification.NORMAL
    matches: list[RuleMatch] = field(default_factory=list)
    scanned: bool = True
    truncated: bool = False

    @property
    def rule_ids(self) -> list[str]:
        seen: list[str] = []
        for match in self.matches:
            if match.rule_id not in seen:
                seen.append(match.rule_id)
        return seen

    @property
    def clean(self) -> bool:
        return self.classification is Classification.NORMAL


_H = Classification.HIGH_RISK
_S = Classification.SUSPICIOUS

DEFAULT_RULES: tuple[PatternRule, ...] = (
    # -- overriding existing instructions ---------------------------------- #
    PatternRule(
        id="instruction_override",
        pattern=(
            r"\b(?:ignore|disregard|forget|discard|override|delete)\b[^.\n]{0,40}"
            r"\b(?:previous|prior|above|earlier|preceding|initial|original|all|any|"
            r"your|the)\b[^.\n]{0,25}"
            r"\b(?:instruction|instructions|prompt|prompts|rule|rules|directive|"
            r"directives|guideline|guidelines|command|commands|context)\b"
        ),
        classification=_H,
        description="Attempts to cancel instructions the model already has",
    ),
    PatternRule(
        id="instruction_override_broad",
        pattern=(
            r"\b(?:ignore|disregard|forget)\s+(?:all|any|everything)\b[^.\n]{0,25}"
            r"\b(?:above|before|previous|prior|earlier|preceding|you were told)\b"
        ),
        classification=_H,
        description="Blanket request to discard prior context",
    ),
    # -- impersonating a trusted role -------------------------------------- #
    PatternRule(
        id="system_role_impersonation",
        pattern=(
            r"(?m)^\s*(?:#{1,6}\s*)?[\[<(]?\s*"
            r"(?:system|developer|assistant|admin|administrator|root)"
            r"\s*(?:message|prompt|note|instruction)?\s*[\]>)]?\s*[:>]"
        ),
        classification=_H,
        description="Text formatted to look like a system or developer turn",
    ),
    PatternRule(
        id="chat_template_markers",
        pattern=(
            r"<\|?(?:im_start|im_end|endoftext|system|assistant|user)\|?>"
            r"|\{\s*\"role\"\s*:\s*\"(?:system|developer|assistant)\""
            r"|<\/?(?:system|developer)_?(?:prompt|instructions?)>"
        ),
        classification=_H,
        description="Chat-template or role markers embedded in message text",
    ),
    PatternRule(
        id="fake_tool_result",
        pattern=(
            r"(?m)<\/?(?:tool_result|tool_response|tool_call|function_results?|"
            r"function_call|invoke|antml:[a-z_]+)\b"
            r"|^\s*(?:Observation|Tool output|Function result)\s*:"
        ),
        classification=_H,
        description="Content forged to look like an MCP or tool response",
    ),
    PatternRule(
        id="authority_claim",
        pattern=(
            r"\b(?:i am|i'm|this is|speaking as|on behalf of)\b[^.\n]{0,25}"
            r"\b(?:the\s+)?(?:system|administrator|admin|developer|operator|owner|"
            r"openai|anthropic|your\s+(?:creator|developer|owner|admin|operator))\b"
            r"|\b(?:authorized|approved|sanctioned|instructed)\s+by\s+"
            r"(?:the\s+)?(?:system|admin|administrator|developer|owner|operator)\b"
        ),
        classification=_H,
        description="False claim of privileged authority",
    ),
    # -- extracting prompts, credentials and other chats -------------------- #
    PatternRule(
        id="prompt_extraction",
        pattern=(
            r"\b(?:reveal|show|print|repeat|output|display|dump|disclose|expose|"
            r"tell me|give me|what are|what is|what's)\b[^.\n]{0,40}"
            r"\b(?:system|initial|hidden|original|full|exact|underlying|your)\b"
            r"[^.\n]{0,25}"
            r"\b(?:prompt|prompts|instruction|instructions|rules|directives|"
            r"configuration|guidelines)\b"
        ),
        classification=_H,
        description="Request to disclose hidden or system instructions",
    ),
    PatternRule(
        id="credential_exfiltration",
        pattern=(
            r"\b(?:send|share|reveal|show|print|give|provide|paste|forward|upload|"
            r"leak|export|read|dump|copy|post)\b[^.\n]{0,50}"
            r"\b(?:api[_\-\s]?hash|api[_\-\s]?id|api[_\-\s]?key|access[_\-\s]?token|"
            r"auth[_\-\s]?token|bearer\s+token|session\s+(?:file|string|data)|"
            r"private\s+key|secret\s+key|seed\s+phrase|recovery\s+phrase|"
            r"password|passphrase|credentials?|\.env)\b"
        ),
        classification=_H,
        description="Request to hand over credentials or session material",
    ),
    PatternRule(
        id="credential_reference",
        pattern=(
            r"\b(?:api[_\-\s]?hash|api[_\-\s]?id|session\s+string|"
            r"seed\s+phrase|recovery\s+phrase|private\s+key)\b"
        ),
        classification=_S,
        description="Mentions credential material (context may be innocent)",
    ),
    PatternRule(
        id="cross_chat_access",
        pattern=(
            r"\b(?:read|access|check|open|fetch|retrieve|list|search|look\s+(?:at|in)|"
            r"go\s+to|scan|browse)\b[^.\n]{0,40}"
            r"\b(?:other|another|all|every|unrelated|different|someone\s+else'?s?|"
            r"his|her|their)\b[^.\n]{0,25}"
            r"\b(?:chat|chats|conversation|conversations|dialog|dialogs|dm|dms|"
            r"inbox|messages)\b"
        ),
        classification=_H,
        description="Instructs the agent to reach into unrelated conversations",
    ),
    PatternRule(
        id="data_exfiltration",
        pattern=(
            r"\b(?:send|forward|post|upload|share|leak|exfiltrate|transmit|email)\b"
            r"[^.\n]{0,45}"
            r"\b(?:credentials?|password|api[_\-\s]?(?:key|hash|id)|token|secret|"
            r"private\s+key|session|this\s+(?:conversation|chat|history)|"
            r"these\s+messages|message\s+history|chat\s+history|contact\s+list|"
            r"contacts)\b"
        ),
        classification=_H,
        description="Instructs the agent to send private data elsewhere",
    ),
    # -- manipulating tool execution --------------------------------------- #
    PatternRule(
        id="tool_execution_request",
        pattern=(
            r"\b(?:call|execute|run|invoke|trigger|perform|use)\b[^.\n]{0,30}"
            r"\b(?:the\s+)?(?:tool|tools|function|functions|mcp|command|api\s+call)\b"
        ),
        classification=_H,
        description="Instructs the agent to execute tools",
    ),
    PatternRule(
        id="tool_name_invocation",
        pattern=(
            r"\b(?:send_message|edit_message|delete_message|get_messages|"
            r"search_dialogs|media_download|message_from_link|set_draft|get_draft)\s*\("
        ),
        classification=_H,
        description="Literal MCP tool call embedded in message text",
    ),
    PatternRule(
        id="agent_addressed_command",
        pattern=(
            r"\b(?:ai|a\.?i\.?|assistant|chatbot|chat\s?bot|llm|language\s+model|"
            r"agent|claude|chatgpt|gpt|gemini|copilot)\b\s*[,:!-]?\s*"
            r"(?:please\s+)?(?:now\s+)?"
            r"\b(?:ignore|send|forward|read|delete|edit|execute|run|reveal|call|"
            r"stop|disregard|download|export)\b"
        ),
        classification=_H,
        description="Message addressed to the AI rather than to the account owner",
    ),
    PatternRule(
        id="shell_command_injection",
        pattern=(
            r"(?:^|[\s`;|])(?:rm\s+-rf|curl\s+https?://|wget\s+https?://|"
            r"nc\s+-e|bash\s+-c|sh\s+-c|powershell\s+-e|eval\s*\()"
        ),
        classification=_H,
        description="Shell payload embedded in message text",
    ),
    # -- bypassing restrictions and redefining the model -------------------- #
    PatternRule(
        id="restriction_bypass",
        pattern=(
            r"\b(?:bypass|circumvent|disable|turn\s+off|switch\s+off|remove|evade|"
            r"get\s+around|work\s+around|skip)\b[^.\n]{0,30}"
            r"\b(?:safety|security|filter|filters|restriction|restrictions|"
            r"guardrail|guardrails|policy|policies|permission|permissions|"
            r"limitation|limitations|safeguard|safeguards|confirmation|approval)\b"
        ),
        classification=_H,
        description="Attempts to switch off protections",
    ),
    PatternRule(
        id="jailbreak_persona",
        pattern=(
            r"\b(?:jailbreak|jailbroken|dan\s+mode|do\s+anything\s+now|"
            r"developer\s+mode|god\s+mode|unrestricted\s+mode|no\s+restrictions\s+mode)\b"
        ),
        classification=_H,
        description="Known jailbreak persona vocabulary",
    ),
    PatternRule(
        id="role_redefinition",
        pattern=(
            r"\byou\s+are\s+now\b[^.\n]{0,30}"
            r"\b(?:an?\s+)?(?:ai|assistant|bot|model|agent|dan|admin|administrator|"
            r"developer|unrestricted|unfiltered|jailbroken|free|different)\b"
            r"|\bnew\s+(?:system\s+)?(?:instructions?|rules?|prompt|directives?)\b"
            r"|\byour\s+new\s+(?:role|task|purpose|instructions?|objective)\b"
        ),
        classification=_H,
        description="Attempts to redefine the model's role",
    ),
    PatternRule(
        id="role_play_request",
        pattern=(
            r"\b(?:act|behave|respond|reply)\s+as\s+(?:a|an|the)\b"
            r"|\bpretend\s+(?:to\s+be|you\s+are|that\s+you)\b"
            r"|\bfrom\s+now\s+on,?\s+you\b"
        ),
        classification=_S,
        description="Role-play framing (common in benign chat too)",
    ),
    PatternRule(
        id="conceal_from_user",
        pattern=(
            r"\b(?:do\s+not|don'?t|never|without)\s+"
            r"(?:tell|telling|inform|informing|notify|notifying|ask|asking|"
            r"mention|mentioning|show|showing|confirm|confirming)\b[^.\n]{0,25}"
            r"\b(?:the\s+)?(?:user|human|owner|operator|him|her|them|anyone)\b"
            r"|\b(?:secretly|silently|quietly|covertly)\s+"
            r"(?:send|forward|delete|read|execute|run|download)\b"
        ),
        classification=_H,
        description="Asks the agent to hide activity from its user",
    ),
    # -- obfuscation -------------------------------------------------------- #
    PatternRule(
        id="comment_smuggling",
        pattern=(
            r"<!--[^>]{0,300}?\b(?:ignore|system|instruction|instructions|prompt|"
            r"tool|assistant)\b"
            r"|\[//\]:\s*#[^\n]{0,200}?\b(?:ignore|system|instruction|prompt)\b"
        ),
        classification=_H,
        description="Instructions hidden inside comment syntax",
    ),
    PatternRule(
        id="encoded_payload",
        pattern=r"\b[A-Za-z0-9+/]{140,}={0,2}\b|(?:\\u00[0-9a-fA-F]{2}){10,}",
        classification=_S,
        description="Long encoded blob that may hide instructions",
    ),
)


_STRUCTURAL_RULES.update(
    {
        "unicode_tag_characters": (
            _H,
            "Unicode tag characters can hide an entire ASCII payload",
        ),
        "bidi_control_characters": (
            _H,
            "Bidirectional controls can reorder text away from what is read",
        ),
        "invisible_characters": (
            _S,
            "Zero-width or format characters embedded in the text",
        ),
        "excessive_whitespace": (
            _S,
            "Long blank run can push following text out of view",
        ),
    }
)

STRUCTURAL_RULE_IDS: tuple[str, ...] = tuple(_STRUCTURAL_RULES)
"""Rule ids produced by structural analysis rather than by a regex."""


class InjectionDetector:
    """Compiles the rule set once and scans text against it."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        custom_patterns: tuple[PatternRule, ...] | list[PatternRule] = (),
        disabled_rules: tuple[str, ...] | list[str] = (),
        max_scan_chars: int = 20_000,
    ) -> None:
        self.enabled = enabled
        self.max_scan_chars = max_scan_chars
        disabled = set(disabled_rules)

        self._rules: list[tuple[PatternRule, re.Pattern[str]]] = []
        seen: set[str] = set()
        for rule in (*DEFAULT_RULES, *custom_patterns):
            if rule.id in disabled:
                continue
            if rule.id in seen:
                raise ValueError(f"duplicate detection rule id: {rule.id!r}")
            seen.add(rule.id)
            flags = re.IGNORECASE if rule.ignore_case else 0
            try:
                compiled = re.compile(rule.pattern, flags)
            except re.error as exc:  # pragma: no cover - guarded by PatternRule
                raise ValueError(
                    f"invalid regular expression for rule {rule.id!r}: {exc}"
                ) from exc
            self._rules.append((rule, compiled))

    @property
    def rule_ids(self) -> list[str]:
        return [rule.id for rule, _ in self._rules]

    def scan(self, text: str | None) -> DetectionResult:
        """Scan one piece of external content."""
        if not self.enabled:
            return DetectionResult(scanned=False)
        if not text:
            return DetectionResult()

        raw = text
        truncated = False
        if self.max_scan_chars and len(text) > self.max_scan_chars:
            raw = text[: self.max_scan_chars]
            truncated = True

        view, offsets = normalize_with_map(raw)
        matches: list[RuleMatch] = []
        classification = Classification.NORMAL

        for rule, compiled in self._rules:
            hits = 0
            for found in compiled.finditer(view):
                hits += 1
                if len(matches) < MAX_MATCHES and hits <= MAX_MATCHES_PER_RULE:
                    start, end = _map_span(
                        offsets, found.start(), found.end(), len(raw)
                    )
                    matches.append(
                        RuleMatch(
                            rule_id=rule.id,
                            classification=rule.classification,
                            start=start,
                            end=end,
                            description=rule.description,
                        )
                    )
                if hits >= MAX_MATCHES_PER_RULE:
                    # Enough evidence from this rule; the rest of the rule set
                    # still runs.
                    break
            if hits and rule.classification.rank > classification.rank:
                classification = rule.classification

        for match in self._structural_matches(raw):
            matches.append(match)
            if match.classification.rank > classification.rank:
                classification = match.classification

        if truncated and classification.rank < Classification.SUSPICIOUS.rank:
            # Content too large to scan in full is treated as not fully cleared.
            classification = Classification.SUSPICIOUS
            matches.append(
                RuleMatch(
                    rule_id="content_truncated_for_scanning",
                    classification=Classification.SUSPICIOUS,
                    start=self.max_scan_chars,
                    end=self.max_scan_chars,
                    description="Content exceeded max_scan_chars and was only "
                    "partially analysed",
                )
            )

        return DetectionResult(
            classification=classification,
            matches=matches,
            scanned=True,
            truncated=truncated,
        )

    def _structural_matches(self, text: str) -> list[RuleMatch]:
        """Findings that regexes cannot express: invisible and reordered text.

        Offsets are emitted per contiguous run rather than as one span from the
        first to the last offender, so redact mode strips the hidden characters
        instead of the whole message.
        """
        found: list[RuleMatch] = []
        buckets: dict[str, list[int]] = {
            "unicode_tag_characters": [],
            "bidi_control_characters": [],
            "invisible_characters": [],
        }

        for index, char in enumerate(text):
            if char in _BIDI_CONTROLS:
                buckets["bidi_control_characters"].append(index)
            elif ord(char) in _TAG_RANGE:
                buckets["unicode_tag_characters"].append(index)
            elif unicodedata.category(char) == "Cf":
                buckets["invisible_characters"].append(index)

        for rule_id, positions in buckets.items():
            if not positions:
                continue
            meta = _STRUCTURAL_RULES[rule_id]
            for start, end in _contiguous_runs(positions)[:MAX_STRUCTURAL_RUNS]:
                found.append(RuleMatch(rule_id, meta[0], start, end, meta[1]))

        for run in _WHITESPACE_RUN.finditer(text):
            meta = _STRUCTURAL_RULES["excessive_whitespace"]
            found.append(
                RuleMatch(
                    "excessive_whitespace", meta[0], run.start(), run.end(), meta[1]
                )
            )
            if len(found) >= MAX_MATCHES:
                break

        return found


def _contiguous_runs(positions: list[int]) -> list[tuple[int, int]]:
    """Collapse sorted indices into ``(start, end)`` half-open runs."""
    runs: list[tuple[int, int]] = []
    start = previous = positions[0]
    for index in positions[1:]:
        if index == previous + 1:
            previous = index
            continue
        runs.append((start, previous + 1))
        start = previous = index
    runs.append((start, previous + 1))
    return runs


def _map_span(
    offsets: list[int] | None, start: int, end: int, raw_length: int
) -> tuple[int, int]:
    """Translate a span in the normalised view back to original offsets."""
    if offsets is None:
        return min(start, raw_length), min(end, raw_length)
    if not offsets:
        return 0, 0
    first = offsets[start] if start < len(offsets) else raw_length
    if end <= start:
        return first, first
    last_index = min(end, len(offsets)) - 1
    last = offsets[last_index] + 1 if last_index >= 0 else first
    return first, min(max(last, first), raw_length)
