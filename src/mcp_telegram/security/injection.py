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
    "MULTILINGUAL_RULES",
    "DetectionResult",
    "InjectionDetector",
    "RuleMatch",
    "normalize_with_map",
]

MAX_RECORDED_SPANS = 500
"""Upper bound on recorded match spans, so a hostile message cannot burn memory.

Spans are not merely diagnostic: redaction rewrites exactly the spans recorded
here, so a budget that is too small silently leaves matched text in place. It is
therefore generous, and exhausting it sets :attr:`DetectionResult.capped` so the
gateway can withhold the field rather than redact it incompletely.

The budget limits what is *recorded*, never what is *evaluated*: every rule is
always run, so padding a message with cheap low-severity hits cannot stop a
later rule from firing and cannot lower the classification.
"""

MAX_STRUCTURAL_RUNS = 20
"""Upper bound on reported runs of hidden characters per category."""

_STRUCTURAL_RULES: dict[str, tuple[Classification, str]] = {}
"""Populated below, once Classification aliases are defined."""

_WHITESPACE_RUN = re.compile(r"\s{80,}")

# Unicode Default_Ignorable_Code_Point characters that are *not* category Cf.
# They render as nothing, so a reader never sees them, but they sit inside a
# word and break every \b boundary: "I<U+034F>gnore" matches no rule at all.
_DEFAULT_IGNORABLE_SINGLES = frozenset(
    {0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x1D173}
)
_DEFAULT_IGNORABLE_RANGES = (
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0xFE00, 0xFE0F),  # variation selectors
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
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
    # Capitals matter more than lowercase, not less: an injection almost always
    # opens a sentence, so "Іgnore all previous instructions" is the natural
    # form of the attack — and U+0406 was absent while its lowercase twin was
    # present, which let the flagship rule be bypassed by one character.
    "В": "B",
    "К": "K",
    "Т": "T",
    "У": "Y",
    "І": "I",
    "Ј": "J",
    "Ѕ": "S",
    "ј": "j",
    "ԛ": "q",
    "ԝ": "w",
    "Α": "A",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
}


_TO_CYRILLIC = {
    "a": "а",
    "e": "е",
    "o": "о",
    "p": "р",
    "c": "с",
    "x": "х",
    "y": "у",
    "i": "і",
    "A": "А",
    "B": "В",
    "E": "Е",
    "K": "К",
    "M": "М",
    "H": "Н",
    "O": "О",
    "P": "Р",
    "C": "С",
    "T": "Т",
    "X": "Х",
    "Y": "У",
}
"""Latin letters that look Cyrillic, for rules written in Cyrillic.

The inverse of the Latin fold: `игнopируй` with Latin `o` and `p` reads as the
Russian word it imitates. Only the matching view changes, never the text.
"""

_FOLDS: dict[str, dict[str, str]] = {"latin": _CONFUSABLES, "cyrillic": _TO_CYRILLIC}


def _is_ignorable(code: int) -> bool:
    """Whether a code point is invisible to a reader but breaks word boundaries."""
    if code in _DEFAULT_IGNORABLE_SINGLES:
        return True
    return any(low <= code <= high for low, high in _DEFAULT_IGNORABLE_RANGES)


def normalize_with_map(
    text: str, *, fold_underscores: bool = True, script: str = "latin"
) -> tuple[str, list[int] | None]:
    """Return a match-friendly view of ``text`` plus an offset map.

    The view folds compatibility forms (NFKC), maps common homoglyphs to ASCII,
    drops characters that are invisible to a reader but break word boundaries
    (format characters, zero-width, bidi and tag characters, and the rest of the
    default-ignorable set), treats underscores as separators, and collapses long
    whitespace runs. ``map[i]`` is the index in ``text`` that produced character
    ``i`` of the view, so a match found in the view can be redacted at the right
    place in the untouched original. ``None`` is returned instead of a map when
    the view is character-for-character the original, which is the common case:
    ASCII only needs the underscore substitution, which preserves every offset.

    ``fold_underscores=False`` keeps `_` intact while still folding everything
    else. The two foldings do different jobs and only one of them is always
    wanted: folding homoglyphs and invisibles is what makes a rule hard to
    evade, whereas folding underscores is what lets `ignore_all_previous_…`
    read as a sentence. A rule that keys on a literal identifier — where
    `send_message` must not read as the English "send message" — needs the
    first without the second.

    ``script`` picks the direction lookalikes are folded in — see
    :attr:`PatternRule.script`. Under `cyrillic` even pure ASCII takes the
    slow path, since every Latin lookalike in it has to move.
    """
    fold = _FOLDS[script]
    if script == "latin" and text.isascii() and not _WHITESPACE_RUN.search(text):
        return (text.replace("_", " ") if fold_underscores else text), None

    out: list[str] = []
    offsets: list[int] = []
    prev_was_space = False

    for index, char in enumerate(text):
        if unicodedata.category(char) == "Cf" or _is_ignorable(ord(char)):
            continue
        if char == "_" and fold_underscores:
            char = " "
        if char.isspace():
            if prev_was_space:
                continue
            prev_was_space = True
            out.append(" ")
            offsets.append(index)
            continue
        prev_was_space = False
        folded = fold.get(char, char)
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
    capped: bool = False
    """True when more spans matched than were recorded.

    Redaction cannot be complete in that case, so the caller must withhold the
    content instead of rewriting part of it.
    """

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
            # Horizontal whitespace only, and bounded. `^` in multiline mode
            # already anchors after a newline, so consuming further newlines here
            # buys nothing — and three adjacent unbounded `\s*` groups let the
            # engine partition a long blank run exponentially many ways, which
            # turned a message of newlines into a server-wide freeze.
            r"(?m)^[ \t]{0,20}(?:#{1,6}[ \t]{0,10})?[\[<(]?[ \t]{0,10}"
            r"(?:system|developer|assistant|admin|administrator|root)"
            r"[ \t]{0,10}(?:message|prompt|note|instruction)?[ \t]{0,10}"
            r"[\]>)]?[ \t]{0,10}[:>]"
        ),
        classification=_H,
        description="Text formatted to look like a system or developer turn",
    ),
    PatternRule(
        id="chat_template_markers",
        pattern=(
            r"<\|?(?:im[_ ]start|im[_ ]end|endoftext|system|assistant|user)\|?>"
            r"|\{\s*\"role\"\s*:\s*\"(?:system|developer|assistant)\""
            r"|<\/?(?:system|developer)[_ ]?(?:prompt|instructions?)>"
        ),
        classification=_H,
        description="Chat-template or role markers embedded in message text",
    ),
    PatternRule(
        id="fake_tool_result",
        pattern=(
            r"(?m)<\/?(?:tool[_ ]result|tool[_ ]response|tool[_ ]call|"
            r"function[_ ]results?|function[_ ]call|invoke|antml:[a-z_ ]+)\b"
            r"|^[ \t]{0,20}(?:Observation|Tool output|Function result)[ \t]{0,10}:"
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
            # Both noun branches sit inside one group so the verb prefix governs
            # them equally. `.env` needs a branch of its own because a leading
            # `\b` before a literal dot only holds when a word character
            # precedes it: inside `\b(?:...)\b` that branch could never match
            # the usual "paste your .env" phrasing, and was dead. `.env.example`
            # and friends are committed placeholders by convention, so "copy
            # .env.example to .env" is setup instructions, not a secret request.
            # `.env.local` is deliberately NOT exempt: Next.js, Vite and CRA all
            # keep real credentials there, and it is gitignored precisely
            # because it holds them. The suffix takes a word boundary too, or
            # `.env.examplefoo` would inherit the exemption.
            r"(?:"
            r"\b(?:api[_\-\s]?hash|api[_\-\s]?id|api[_\-\s]?key|access[_\-\s]?token|"
            r"auth[_\-\s]?token|bearer\s+token|session\s+(?:file|string|data)|"
            r"private\s+key|secret\s+key|seed\s+phrase|recovery\s+phrase|"
            r"password|passphrase|credentials?)\b"
            r"|(?<![\w.])\.env\b(?!\.(?:example|sample|template|dist)\b)"
            r")"
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
            r"private\s+key|session|"
            # "this entire conversation" and "these last 50 messages" are the
            # same request as "this conversation"; requiring adjacency made the
            # rule evadable by inserting a single word.
            r"this(?:\s+[\w-]+){0,3}\s+(?:conversation|chat|history)|"
            r"these(?:\s+[\w-]+){0,3}\s+messages|"
            r"message\s+history|chat\s+history|contact\s+list|"
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
            r"\b(?:send[_ ]message|edit[_ ]message|delete[_ ]message|"
            r"get[_ ]messages|search[_ ]dialogs|media[_ ]download|"
            r"message[_ ]from[_ ]link|set[_ ]draft|get[_ ]draft)\s*\("
        ),
        classification=_H,
        description="Literal MCP tool call embedded in message text",
    ),
    # Naming a tool exactly is the signal: nobody writes `send_message` in a
    # chat message by accident, while "send message" is ordinary English. That
    # distinction only survives with underscores intact, so this rule reads the
    # view that keeps them — and still folds homoglyphs and invisibles, so the
    # canary cannot be evaded by the tricks every other rule resists.
    PatternRule(
        id="tool_surface_canary",
        pattern=(
            r"\b(?:send_message|edit_message|delete_message|get_messages|"
            r"search_dialogs|media_download|message_from_link|set_draft|"
            r"get_draft|security_status)\b(?!\s{0,20}\()"
        ),
        classification=_H,
        description="Exact MCP tool identifier reveals knowledge of the tool surface",
        preserve_underscores=True,
    ),
    PatternRule(
        id="agent_addressed_command",
        pattern=(
            r"\b(?:ai|a\.?i\.?|assistant|chatbot|chat\s?bot|llm|language\s+model|"
            # Bounded: two adjacent unbounded whitespace groups can each claim
            # the same blank run, which is quadratic on a long one.
            r"agent|claude|chatgpt|gpt|gemini|copilot)\b\s{0,10}[,:!-]?\s{0,10}"
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


_ES_VERB = (
    r"\b(?:ignora\w*|olvida\w*|descarta\w*|omit[ae]\w*|haz\s+caso\s+omiso\s+de)\b"
)
_API = r"[aа][pр][iі][_\s\-]?(?:h[aа]sh|[iі]d|k[eе][yу]|ключ\w*)"
"""`api_hash` as it appears in the Cyrillic-folded view, where `a`, `p` and `i`
have been mapped to their Cyrillic lookalikes."""

MULTILINGUAL_RULES: tuple[PatternRule, ...] = (
    # -- Spanish --------------------------------------------------------- #
    PatternRule(
        id="es_instruction_override",
        pattern=(
            _ES_VERB + r"[^.\n]{0,30}"
            r"\b(?:instrucciones|indicaciones|reglas|[oó]rdenes|directrices|"
            r"directivas|prompt)\b[^.\n]{0,20}"
            r"\b(?:anteriores|previas|iniciales|originales|recibidas|"
            r"del\s+sistema)\b"
            r"|\b(?:ignora|olvida|descarta)\s+(?:todo\s+)?lo\s+"
            r"(?:anterior|que\s+te\s+(?:dijeron|han\s+dicho))\b"
        ),
        classification=_H,
        description="Spanish: attempts to cancel the model's instructions",
    ),
    PatternRule(
        id="es_prompt_extraction",
        pattern=(
            r"\b(?:revela\w*|muestra\w*|mu[eé]strame|imprime|repite|dime|dame)\b"
            r"[^.\n]{0,30}\b(?:prompt|instrucciones)\s+"
            r"(?:del\s+sistema|ocultas|iniciales|originales|secretas)\b"
        ),
        classification=_H,
        description="Spanish: request to disclose hidden instructions",
    ),
    PatternRule(
        id="es_credential_exfiltration",
        pattern=(
            r"\b(?:env[ií]a\w*|manda\w*|reenv[ií]a\w*|comparte\w*|p[eé]ga\w*|"
            r"dame|revela\w*|sube\w*)\b[^.\n]{0,50}"
            r"\b(?:contrase[ñn]as?|credenciales|claves?\s+(?:api|privadas?|"
            r"secretas?)|api[_\s\-]?(?:hash|id|key)|tokens?\s+de\s+acceso|"
            r"archivo\s+de\s+sesi[oó]n|cadena\s+de\s+sesi[oó]n|"
            r"frase\s+(?:semilla|de\s+recuperaci[oó]n))\b"
        ),
        classification=_H,
        description="Spanish: request to hand over credentials",
    ),
    PatternRule(
        id="es_role_redefinition",
        pattern=(
            r"\bnuevas\s+instrucciones\s*:"
            r"|\bmodo\s+(?:desarrollador|sin\s+restricciones|dios)\b"
            r"|\b(?:ahora|a\s+partir\s+de\s+ahora)\s+eres\b[^.\n]{0,30}"
            r"\b(?:sin\s+restricciones|sin\s+filtros|liberad[oa]|desbloquead[oa])\b"
        ),
        classification=_H,
        description="Spanish: attempts to redefine the model's role",
    ),
    PatternRule(
        id="es_conceal_from_user",
        pattern=(
            r"\b(?:no\s+(?:se\s+lo\s+|le\s+)?(?:digas|avises|informes|menciones|"
            r"muestres)|sin\s+(?:dec[ií]rselo|avisar|informar)(?:le)?)\b[^.\n]{0,25}"
            r"\b(?:al\s+usuario|al\s+propietario|al\s+due[ñn]o|al\s+humano)\b"
            r"|\b(?:en\s+secreto|a\s+escondidas|sigilosamente)\s+"
            r"(?:env[ií]a|reenv[ií]a|borra|elimina|ejecuta|descarga)\b"
        ),
        classification=_H,
        description="Spanish: asks the agent to hide activity from its user",
    ),
    # -- Portuguese ------------------------------------------------------ #
    PatternRule(
        id="pt_instruction_override",
        pattern=(
            r"\b(?:ignor[ea]\w*|esque[cç]a\w*|desconsider[ea]\w*)\b[^.\n]{0,30}"
            r"\b(?:instru[cç][oõ]es|regras|ordens|diretrizes|prompt)\b[^.\n]{0,20}"
            r"\b(?:anteriores|pr[eé]vias|iniciais|originais|do\s+sistema)\b"
        ),
        classification=_H,
        description="Portuguese: attempts to cancel the model's instructions",
    ),
    PatternRule(
        id="pt_credential_exfiltration",
        pattern=(
            r"\b(?:envi[ea]\w*|mand[ea]\w*|compartilh[ea]\w*|me\s+d[eê]|"
            r"mostr[ea]\w*|revel[ea]\w*)\b[^.\n]{0,50}"
            r"\b(?:senhas?|credenciais|chaves?\s+(?:api|privadas?|secretas?)|"
            r"api[_\s\-]?(?:hash|id|key)|tokens?\s+de\s+acesso|"
            r"arquivo\s+de\s+sess[aã]o|frase\s+de\s+recupera[cç][aã]o)\b"
        ),
        classification=_H,
        description="Portuguese: request to hand over credentials",
    ),
    # -- French ---------------------------------------------------------- #
    PatternRule(
        id="fr_instruction_override",
        pattern=(
            r"\b(?:ignore[rz]?|oublie[rz]?)\b[^.\n]{0,30}"
            r"\b(?:instructions?|consignes?|r[eè]gles|directives|ordres|prompt)\b"
            r"[^.\n]{0,20}\b(?:pr[eé]c[eé]dent\w*|ant[eé]rieur\w*|ci-dessus|"
            r"initia\w*|d'origine|du\s+syst[eè]me)"
            r"|\b(?:ignore[rz]?|oublie[rz]?)\s+(?:tout\s+)?ce\s+qui\s+"
            r"(?:pr[eé]c[eè]de|est\s+au-dessus)\b"
        ),
        classification=_H,
        description="French: attempts to cancel the model's instructions",
    ),
    PatternRule(
        id="fr_credential_exfiltration",
        pattern=(
            r"\b(?:envoie\w*|transf[eè]re\w*|partage\w*|donne[- ]moi|"
            r"montre[- ]moi|r[eé]v[eè]le\w*|colle\w*)\b[^.\n]{0,50}"
            r"\b(?:mots?\s+de\s+passe|identifiants|cl[eé]s?\s+(?:api|priv[eé]es?|"
            r"secr[eè]tes?)|api[_\s\-]?(?:hash|id|key)|jetons?\s+d'acc[eè]s|"
            r"fichier\s+de\s+session|phrase\s+de\s+r[eé]cup[eé]ration)"
        ),
        classification=_H,
        description="French: request to hand over credentials",
    ),
    # -- German ---------------------------------------------------------- #
    PatternRule(
        id="de_instruction_override",
        pattern=(
            r"\b(?:ignorier\w*|vergiss|vergessen\s+sie|missachte\w*)\b[^.\n]{0,40}"
            r"\b(?:vorherig\w*|bisherig\w*|obig\w*|vorangegangen\w*|alle[nrs]?|"
            r"urspr[üu]nglich\w*|system)\b[^.\n]{0,25}"
            r"(?:anweisung\w*|instruktion\w*|regeln|befehl\w*|vorgaben|prompt\w*)"
        ),
        classification=_H,
        description="German: attempts to cancel the model's instructions",
    ),
    PatternRule(
        id="de_credential_exfiltration",
        pattern=(
            r"\b(?:schick\w*|sende\w*|gib|zeig\w*|verrat\w*|teile?|kopier\w*)\b"
            r"[^.\n]{0,50}"
            r"(?:passw[oö]rt\w*|kennw[oö]rt\w*|zugangsdaten|"
            r"api[_\s\-]?(?:hash|id|schl[üu]ssel\w*)|privaten?\s+schl[üu]ssel\w*|"
            r"sitzungsdatei|wiederherstellungsphrase)"
        ),
        classification=_H,
        description="German: request to hand over credentials",
    ),
    # -- Russian: matched against the Cyrillic-folded view -------------- #
    PatternRule(
        id="ru_instruction_override",
        pattern=(
            r"\b(?:проигнорируй\w*|игнорируй\w*|забудь\w*|отбрось\w*|"
            r"не\s+обращай\s+внимания\s+на)\b[^.\n]{0,40}"
            r"\b(?:предыдущ\w+|прежн\w+|вс[её]\w*|вышеуказанн\w+|изначальн\w+|"
            r"системн\w+|исходн\w+)\b[^.\n]{0,25}"
            r"\b(?:инструкци\w*|указани\w*|правил\w*|команд\w*|промпт\w*)"
        ),
        classification=_H,
        description="Russian: attempts to cancel the model's instructions",
        script="cyrillic",
    ),
    PatternRule(
        id="ru_prompt_extraction",
        pattern=(
            r"\b(?:покажи|выведи|раскрой|повтори|напиши|скажи|сообщи)\b[^.\n]{0,30}"
            r"\b(?:сво[йи]|тво[йи]|системн\w+|скрыт\w+|исходн\w+)\b[^.\n]{0,20}"
            r"\b(?:промпт\w*|инструкци\w*|системн\w+\s+подсказ\w*)"
        ),
        classification=_H,
        description="Russian: request to disclose hidden instructions",
        script="cyrillic",
    ),
    PatternRule(
        id="ru_credential_exfiltration",
        pattern=(
            r"\b(?:отправь\w*|перешли\w*|пришли\w*|скинь\w*|покажи|дай|сообщи|"
            r"выложи)\b[^.\n]{0,50}"
            r"(?:\bпарол\w+|" + _API + r"|\bключ\w*\s+(?:доступа|[aа][pр][iі])|"
            r"\bтокен\w*|\bсекретн\w+\s+ключ\w*|\bприватн\w+\s+ключ\w*|"
            r"\bсид[\s\-]?фраз\w*|\bфайл\w*\s+сесси\w+|\bстрок\w+\s+сесси\w+|"
            r"\bкод\w*\s+(?:подтверждения|входа))"
        ),
        classification=_H,
        description="Russian: request to hand over credentials",
        script="cyrillic",
    ),
    PatternRule(
        id="ru_role_redefinition",
        pattern=(
            r"\bтеперь\s+ты\b[^.\n]{0,30}"
            r"(?:без\s+ограничений|без\s+фильтров|не\s+ассистент|свободн\w+)"
            r"|\bнов\w+\s+инструкци\w*\s*:"
            r"|\bрежим\s+(?:разработчика|без\s+ограничений|бога)\b"
        ),
        classification=_H,
        description="Russian: attempts to redefine the model's role",
        script="cyrillic",
    ),
    PatternRule(
        id="ru_conceal_from_user",
        pattern=(
            r"\bне\s+(?:говори|сообщай|рассказывай|показывай)\b[^.\n]{0,25}"
            r"\b(?:пользовател\w+|владельц\w+|хозяин\w*)"
            r"|\b(?:тайно|незаметно|скрытно|втихую)\s+"
            r"(?:отправь|перешли|удали|прочитай|выполни|скачай)\w*"
        ),
        classification=_H,
        description="Russian: asks the agent to hide activity from its user",
        script="cyrillic",
    ),
    # -- Chinese: no word boundaries exist, so none are used ------------ #
    PatternRule(
        id="zh_instruction_override",
        pattern=(
            r"(?:忽略|无视|無視|忘记|忘記|忘掉|不要理会|不要理會|跳过|跳過)"
            r"[^。\n]{0,15}"
            r"(?:之前|以前|先前|上面|以上|上述|前面|所有|全部|原来|原來|原始|系统|系統)"
            r"[^。\n]{0,10}"
            r"(?:指令|指示|说明|說明|规则|規則|提示|命令|设定|設定|要求)"
        ),
        classification=_H,
        description="Chinese: attempts to cancel the model's instructions",
    ),
    PatternRule(
        id="zh_prompt_extraction",
        pattern=(
            r"(?:显示|顯示|输出|輸出|告诉我|告訴我|透露|泄露|洩露|重复|重複|打印|"
            r"给我看|給我看|列出)[^。\n]{0,15}"
            r"(?:你的|系统|系統|隐藏|隱藏|原始|初始)[^。\n]{0,8}"
            r"(?:提示词|提示詞|提示|指令|指示|设定|設定|规则|規則)"
        ),
        classification=_H,
        description="Chinese: request to disclose hidden instructions",
    ),
    PatternRule(
        id="zh_credential_exfiltration",
        pattern=(
            r"(?:发送|發送|发给|發給|转发|轉發|分享|告诉我|告訴我|给我|給我|提供|"
            r"上传|上傳|泄露|洩露)[^。\n]{0,30}"
            r"(?:密码|密碼|密钥|密鑰|私钥|私鑰|令牌|api[_ ]?(?:hash|id|key)|"
            r"验证码|驗證碼|助记词|助記詞|会话文件|會話文件|会话字符串|會話字串)"
            # The 把 construction fronts the object: "把密码发给我".
            r"|(?:把|将|將)[^。\n]{0,20}"
            r"(?:密码|密碼|密钥|密鑰|私钥|私鑰|令牌|验证码|驗證碼|助记词|助記詞|"
            r"会话文件|會話文件)[^。\n]{0,15}"
            r"(?:发给|發給|发送|發送|告诉|告訴|给|給|转发|轉發|分享|上传|上傳)"
        ),
        classification=_H,
        description="Chinese: request to hand over credentials",
    ),
    PatternRule(
        id="zh_role_redefinition",
        pattern=(
            r"(?:你现在是|你現在是|从现在起你是|從現在起你是|从现在开始你是|"
            r"從現在開始你是)[^。\n]{0,20}"
            r"(?:没有限制|沒有限制|不受限制|无限制|無限制|越狱|越獄)"
            r"|(?:开发者模式|開發者模式|越狱模式|越獄模式)"
            r"|新的?(?:系统|系統)?指令[:：]"
        ),
        classification=_H,
        description="Chinese: attempts to redefine the model's role",
    ),
    PatternRule(
        id="zh_conceal_from_user",
        pattern=(
            r"(?:不要|别|別|不许|不許)(?:告诉|告訴|通知|提醒|让|讓)[^。\n]{0,8}"
            r"(?:用户|用戶|主人|使用者)"
            r"|(?:偷偷|悄悄|秘密地?)(?:发送|發送|转发|轉發|删除|刪除|执行|執行|下载|下載)"
        ),
        classification=_H,
        description="Chinese: asks the agent to hide activity from its user",
    ),
)
"""Translations of the highest-value English rules.

Written per language rather than machine-translated: each follows that
language's word order and its own way of saying "the previous instructions".
Chinese patterns use no `\\b`, which needs word characters on one side and so
never fires between two ideographs.
"""

DEFAULT_RULES = DEFAULT_RULES + MULTILINGUAL_RULES


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
        capped = False

        # Other views are built only if a rule asks for one: keeping `_` keeps
        # a literal identifier distinct from the same words written as English,
        # and folding toward Cyrillic keeps Russian readable.
        views: dict[tuple[bool, str], tuple[str, list[int] | None]] = {
            (True, "latin"): (view, offsets)
        }

        for rule, compiled in self._rules:
            key = (not rule.preserve_underscores, rule.script)
            if key not in views:
                views[key] = normalize_with_map(
                    raw, fold_underscores=key[0], script=key[1]
                )
            rule_view, rule_offsets = views[key]
            if capped:
                # The span budget is spent, so only the classification is still
                # in question: one hit answers it without recording anything.
                if compiled.search(rule_view) is not None:
                    classification = max(
                        classification, rule.classification, key=lambda c: c.rank
                    )
                continue

            hits = 0
            for found in compiled.finditer(rule_view):
                hits += 1
                if len(matches) >= MAX_RECORDED_SPANS:
                    capped = True
                    break
                start, end = _map_span(
                    rule_offsets, found.start(), found.end(), len(raw)
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
            if hits and rule.classification.rank > classification.rank:
                classification = rule.classification

        structural, structural_capped = self._structural_matches(raw)
        capped = capped or structural_capped
        for match in structural:
            if len(matches) >= MAX_RECORDED_SPANS:
                capped = True
            else:
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
            capped=capped,
        )

    def _structural_matches(self, text: str) -> tuple[list[RuleMatch], bool]:
        """Findings that regexes cannot express: invisible and reordered text.

        Offsets are emitted per contiguous run rather than as one span from the
        first to the last offender, so redact mode strips the hidden characters
        instead of the whole message. Returns whether any run had to be dropped:
        an unrecorded run is one redaction would silently leave behind.
        """
        found: list[RuleMatch] = []
        capped = False
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
            elif unicodedata.category(char) == "Cf" or _is_ignorable(ord(char)):
                buckets["invisible_characters"].append(index)

        for rule_id, positions in buckets.items():
            if not positions:
                continue
            meta = _STRUCTURAL_RULES[rule_id]
            runs = _contiguous_runs(positions)
            if len(runs) > MAX_STRUCTURAL_RUNS:
                capped = True
            for start, end in runs[:MAX_STRUCTURAL_RUNS]:
                found.append(RuleMatch(rule_id, meta[0], start, end, meta[1]))

        for index, run in enumerate(_WHITESPACE_RUN.finditer(text)):
            if index >= MAX_STRUCTURAL_RUNS:
                capped = True
                break
            meta = _STRUCTURAL_RULES["excessive_whitespace"]
            found.append(
                RuleMatch(
                    "excessive_whitespace", meta[0], run.start(), run.end(), meta[1]
                )
            )

        return found, capped


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
