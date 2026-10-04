# Roadmap: what would make this the best Telegram MCP server

v1.0.0 covers the security and reliability architecture the project set out to
build. This document is the honest list of what it still does *not* do.

**Ordered by priority, most important first.** That order is a judgement call,
and the reasoning is stated for each so you can disagree with it. Three things
drove the ranking: whether an item closes a real hole rather than adding a
capability, whether it makes future work measurable instead of guesswork, and
value per unit of effort. Items an adversarial review flagged and v1.0.0 only
partly closed are marked.

Legend — **Impact**: how much better the product gets. **Effort**: S (a day),
M (a few days), L (a week or more).

---

## 1. Live integration test suite
**Impact: very high · Effort: M**

*First, because everything else is built on the assumption that this works.*

Every test uses a fake Telethon client. The real integration points —
`resolve_chat_identity`, `_unread_state`, the bulk read acknowledgement, actual
`FloodWaitError` objects — have never run against Telegram.

That mattered less when it was written. It matters a great deal now: after the
review rounds, **the chat allowlist depends on `resolve_chat_identity`**. A
username rule grants access only if that call returns the peer and username
Telegram really holds. If it behaves differently in reality than in the fake —
a different exception, a `None` username where one was expected, a cached entity
returning something stale — the allowlist is not what the tests say it is.

An opt-in `--live` suite against a throwaway account and a private test channel,
skipped by default and excluded from CI, would settle it. Ship nothing else
until this passes.

## 2. Outbound content policy
**Impact: very high · Effort: M · SHIPPED**

> **Shipped.** `[security.outbound]` refuses credential shapes, oversized
> messages and bulk-quoted text on sends, drafts and edits, before the call
> reaches Telegram. What remains unbuilt from the original item: seed-phrase and
> private-key detection beyond the audit scrubber's shapes, and the first-contact
> rule. The two heuristics below are conservative and can still be evaded by an
> attacker who simply does not mark quoted lines.

The gateway inspected everything coming *in* and nothing going *out*. The
exfiltration path an injection actually wants — persuade the model to compose a
message containing your secrets and send it — is unguarded, because the model
writes that text itself.

This was the largest remaining hole in the threat model. Scan message and draft
text before it leaves:

- refuse credential-shaped strings (API hashes, private keys, tokens, seed
  phrases) — the audit log's scrubber already recognises them;
- warn or refuse on bulk quoting of another chat's content;
- a configurable maximum length, and a first-contact rule per chat.

Inbound detection could not close this one, and nothing else in the list
protected against it either.

## 3. Human-in-the-loop confirmation for high-impact actions
**Impact: very high · Effort: M · SHIPPED**

> **Shipped.** Every `allow_*` accepts `"confirm"`, globally or per chat (item
> 8). The question goes to the person at the MCP client as an elicitation, after
> every other check and outside the scheduler; only an explicit tick approves,
> and decline, cancel, timeout, a client without elicitation, an SDK older than
> 1.9 or any error refuses. Dry run notes that it would ask instead of asking.
> **Not shipped:** `confirm_send_to_new_chats`, and elicitation on the
> 2026-07-28 MCP protocol, which carries questions inside a retried tool call
> rather than as a server request — there the confirmation is refused with a
> reason saying so.

Every operation is a static allow or deny, which forces a bad choice: turn
`allow_delete` off and the agent cannot help you clean up a thread, or turn it
on and one successful injection deletes messages unattended.

MCP supports *elicitation* — the server can put a question to the human. A
`confirm` tier would let operators say "deleting is allowed, but ask me first",
per operation and per chat:

```toml
[permissions]
allow_delete = "confirm"
confirm_send_to_new_chats = true
```

It converts the riskiest operations from a policy problem into a UX one, which
is where they belong. Below the two items above only because they close holes
that exist whatever the operator configures, whereas this one improves a choice
the operator is already making deliberately. Requires elicitation support in the
client, with a documented fallback to `deny`.

## 4. Rate-limiter and cooldown state that survives restarts
**Impact: high · Effort: S · SHIPPED**

> **Shipped.** Bucket levels and `cooldown_until` persist to the state directory
> and reload at startup, refilling for elapsed wall-clock time. Corrupt, empty or
> future-version state degrades to fresh buckets with a warning rather than
> crashing.

Token buckets and the FloodWait cooldown lived in memory. A client that restarts
the server — a crash loop, a client that respawns on error, a user retrying —
resets every budget to full and forgets that Telegram asked for a 300-second
wait. The protection disappears exactly when things are going wrong.

Persist bucket state and `cooldown_until` to the state directory and reload at
startup. **The best value-per-effort item on the list**: a day's work closing a
real hole, which is why it outranks several things with higher ceilings.

## 5. A labelled detection corpus with precision/recall reporting
**Impact: high · Effort: M · SHIPPED**

> **Shipped.** 116 labelled entries scored on every test run, with floors that
> fail the build on a new miss or a new false positive and name the entries that
> moved. It immediately found four detection bypasses. Measured quality and the
> five known false positives are in [DETECTION.md](DETECTION.md). Still English
> only — see item 10 — and written to probe boundaries rather than sampled from
> real traffic, so it is a regression measure, not a field estimate.

Detection quality was asserted by a hand-written test list. That proves the rules
do what their author expected; it does not measure whether they are *good*.
Without a metric, every new rule is a guess and every tuning change is a coin
flip.

Ship a labelled corpus — attacks and benign messages, including hard negatives
like security discussions and quoted attacks — plus a benchmark reporting
precision, recall and per-rule false-positive rates. Then improvements become
provable, contributors can show their rule helps, and the README can publish a
real number instead of a rule count.

Ranked here because it is *enabling* work: items 10, 12 and 16 are all guesswork
until this exists.

## 6. `explain` command for tuning detection
**Impact: medium-high · Effort: S · SHIPPED**

> **Shipped.** `telegram-mcp-enhanced explain "<text>"` reports the
> classification, matching rules and spans.

There was no way to ask "why was this flagged?" without reading the source.
`telegram-mcp-enhanced explain "<text>"` printing the classification, every rule
that matched, the matched spans and what each mode would do turns rule tuning
from guesswork into a two-second check.

A day's work that multiplies the value of item 5 and makes every detection
change after it cheaper.

## 7. Meter at the Telethon RPC boundary
**Impact: high · Effort: M · SHIPPED**

> Tool slots now govern concurrency; RPC admissions govern tokens, pacing and
> cooldown. Pagination is metered without reacquiring the semaphore. Estimates
> were removed. The hook sits on `TelegramClient._call` rather than `__call__`,
> so the download iterator's direct `_call` and exported/CDN senders are
> metered too, and a sender adapter admits every `sender.send`, so Telethon's
> internal retries for server errors and migrations are charged and gated like
> any other request. What remains below the boundary is MTProto's own
> transport-level retransmission and housekeeping (acks, pings, resends of
> unacknowledged messages), which never pass through `sender.send`.

Original rationale: the scheduler admitted one *tool call*, not one *Telegram
request*. A paginating call issued several requests under a single admission.
v1.0.0 narrows this — bulk read acknowledgement, a cap on `limit`, token cost
proportional to the pages a read will fetch, a ceiling on messages scanned — but
the proposed fix was to meter inside `TelegramClient.__call__`. The shipped
implementation covers that boundary; the bypasses noted above remain.

The care needed is re-entrancy: the outer call already holds the concurrency
semaphore, so per-RPC metering must apply the bucket and the pacing interval
only, never the semaphore, or a `max_concurrent = 1` server deadlocks against
itself.

## 8. Per-chat permission profiles
**Impact: high · Effort: M · SHIPPED**

> **Shipped** as `[[permissions.profiles]]`, first match wins, each profile
> overriding `allow_read`, `allow_send`, `allow_edit`, `allow_delete`,
> `allow_drafts` and `allow_download` with `true`, `false` or `"confirm"`.
> Profiles never grant chat access, and are matched against the peer Telegram
> confirms: when they would disagree about an operation the chat is resolved
> first, so naming a chat by id cannot dodge a profile written by username.

Permissions are global; chat access is a separate list. Real use wants them
combined: read-only in the company channel, send freely in the DM with your
partner, never touch anything else.

```toml
[[permissions.profiles]]
chats = ["-1001234567890"]
allow_send = false

[[permissions.profiles]]
chats = ["@alice"]
allow_send = true
allow_delete = "confirm"
```

The shape most real deployments actually want, and it composes with item 3.

## 9. Prebuilt policy presets
**Impact: medium-high · Effort: S · SHIPPED**

> **Shipped.** `init-config --preset read-only|assistant|locked-down`. The
> locked-down preset denies every chat until the operator names one, so startup
> now warns loudly rather than looking like a broken server.

`init-config --preset read-only|assistant|locked-down` instead of one template
plus prose. Most operators want a known-good starting point, not a tour of forty
settings.

Ranked above several technically deeper items because **security products fail
by misconfiguration more often than by defect**. A preset that is correct out of
the box protects more people than a control nobody enables. A day's work.

## 10. Localised and multilingual detection
**Impact: medium-high · Effort: M · SHIPPED (first pass)**

> **Shipped:** 21 rules translating the highest-value English ones into
> Spanish, Portuguese, French, German, Russian and Chinese, with 44 corpus
> entries — attacks and hard negatives — scored at the same 1.00 floors. The
> homoglyph fold that made Russian unmatchable is now per rule: Cyrillic rules
> fold lookalikes *into* Cyrillic instead. **Not shipped:** paraphrase coverage
> comparable to English, other languages, and Greek-specific rules.

Every rule is English. An injection written in Spanish, Russian or Chinese
passes cleanly, and the model will understand it perfectly well.

This is a genuine hole rather than polish — it was mis-ranked as polish in the
first draft of this document. Either translate the high-value rules or move them
to a language-agnostic form. Needs item 5 first, or there is no way to tell
whether a translated rule set is any good.

## 11. Session hardening
**Impact: medium · Effort: M · SHIPPED**

> **Shipped.** The state directory is `0700` and the session and its SQLite
> companions `0600`, enforced at creation, connection and sign-in. `[session]
> storage = "keyring"` keeps a `StringSession` in the OS credential store via
> the optional `keyring` extra, with `migrate-session` to move an existing
> login and `clear-session` removing it again. **Not shipped:** encrypting the
> SQLite file itself for platforms without a keyring.

The Telethon session is a plaintext SQLite file. Anything that can read the
user's home directory can impersonate the account — which is a larger prize than
anything else this server protects.

Support `StringSession` held in the OS keychain (Keychain, libsecret, DPAPI).
Ranked here rather than higher only because it is an exposure the operating
system is also responsible for, and the file guard already refuses to upload it.

## 12. Attachment content inspection
**Impact: medium · Effort: M · SHIPPED**

> **Shipped.** Before transfer: executable extensions, an optional extension
> allowlist and `max_download_bytes`. After: the written size, executable
> headers (PE, ELF, Mach-O, Java class, `#!`), a magic-byte check against the
> declared type, and injection scanning of UTF-8 text files; refused files are
> deleted. **Not shipped:** extracting text from PDFs and Office documents —
> they are identified, not opened.

`media_download` scans the file *name* and writes the file to disk. It does not
look at what the file is. An agent asked to "read the attached document" can be
handed a file whose contents are an injection payload, or an executable.

Add magic-byte type verification, a size ceiling, an optional extension
allowlist, and gateway scanning of extracted text for text-like formats.

## 13. Tool-name canary detection
**Impact: medium · Effort: S · PARTLY SHIPPED**

> **Shipped:** the `tool_surface_canary` rule flags incoming text containing an
> exact MCP tool identifier, matching against a view that keeps `_` so
> `send_message` stays distinct from the words "send message", while still
> folding homoglyphs and invisible characters.
> **Not shipped:** canaries for allowlisted chat IDs or the operator's username.

Flag any incoming message mentioning this server's own tool names, a chat ID
from the allowlist, or the operator's username. Nothing legitimate does that, so
it is high-signal with near-zero false positives — the cheapest detection win
available.

## 14. Dry-run mode
**Impact: medium · Effort: S · SHIPPED**

> **Shipped.** `dry_run = true` runs the whole policy chain and substitutes only
> the Telegram call for sends, edits, deletions and drafts. Reads stay real;
> `media_download` and `get_messages(mark_as_read=True)` are refused rather than
> faked. Whether a tool mutates is a required per-tool declaration, verified
> against the code. **Not shipped:** the end-to-end demo needing no account,
> which would require simulating reads too.

`dry_run = true` would let every write pass the full policy chain, log exactly
what it would have done, and return a realistic response without touching
Telegram. How you would safely evaluate a new agent, test a config change, or
reproduce a bug report — and how this project could ship an end-to-end demo that
needs no account.

## 15. Event subscriptions instead of polling
**Impact: high · Effort: L**

An agent that wants to know about new messages must call `get_messages` in a
loop — precisely the traffic pattern the rate limiter exists to suppress. The
server fights its own users.

Telethon already exposes an event stream. Surfacing new messages as an MCP
resource subscription would let an agent wait instead of poll: less traffic,
lower latency, no flood-wait risk. Content would flow through the same gateway.

High impact, but ranked here because it is a *capability* rather than a hole,
and it is the largest single piece of work on the list.

## 16. Quarantine retrieval
**Impact: medium · Effort: S · SHIPPED**

> **Shipped** as `get_quarantined_message(entity, message_id)`, which returns
> the original text with its safety metadata only after the user approves,
> every call, and still needs read permission and chat access.

In `block` mode the content is simply gone, so an operator cannot see what was
withheld without opening Telegram. A `get_quarantined_message` tool, gated
behind confirmation from item 3, would let a human inspect it deliberately.

## 17. Security log tooling
**Impact: medium · Effort: S · SHIPPED**

> **Shipped** as `telegram-mcp-enhanced log` with `--since`, `--event`,
> `--limit`, `--summary` and `--json`, reading rotated backups in order.

`telegram-mcp-enhanced log --since 1h --event injection_detected` to tail,
filter and summarise the audit trail, plus an export for SIEM ingestion. The log
exists; nothing helps you read it.

## 18. Docker image and MCP registry listing
**Impact: medium · Effort: S**

A published image and a listing in the MCP server registries is how most people
will find this. Distribution is a feature — ranked below the security items
because publishing something with a known hole in it is worse than publishing it
late.

## 19. Richer rate-limit shaping
**Impact: low-medium · Effort: S**

Per-tool rather than per-class budgets, a bandwidth-aware media bucket (media is
limited by request count, not bytes), and a burst allowance distinct from the
sustained rate. Refinement of something that already works.

## 20. Multi-account support
**Impact: low-medium · Effort: L**

One server, several accounts, each with its own session, policy and rate-limit
budget. Mostly a matter of making the runtime and state directory
account-scoped. Last because it multiplies the surface of everything above it,
so it is worth doing only once the rest is settled.

---

## Deliberately not planned

- **LLM-based detection.** Sending message content to a model for classification
  would break the privacy guarantee that analysis is local, add latency and cost
  per message, and introduce an injection surface inside the defence itself.
- **Auto-replying or agentic autonomy features.** This is a security layer, not
  an agent framework. Its job is to make someone else's agent safe.
- **Blocking by default.** Detection has false positives; a default that hides
  real messages would be worse than the problem. `flag` stays the default.

---

## If you only do four

Originally: 1, 2, 3 and 4. Items 2, 3, 4, 5, 7, 8, 14 and most of 10, 11, 12,
16 and 17 have since shipped. That leaves **item 1 above everything else**, and
more so than before: the chat allowlist, per-chat profiles and the confirmation
prompt's chat line all depend on `resolve_chat_identity`, and confirmation
depends on real clients' elicitation support — none of which has run against
real Telegram or a real client UI. After that: elicitation over the 2026-07-28
protocol (item 3's remainder), event subscriptions (15), and distribution (18).
