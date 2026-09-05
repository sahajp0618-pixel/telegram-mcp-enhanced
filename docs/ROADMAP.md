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
**Impact: very high · Effort: M · flagged by review, not closed**

The gateway inspects everything coming *in* and nothing going *out*. The
exfiltration path an injection actually wants — persuade the model to compose a
message containing your secrets and send it — is unguarded, because the model
writes that text itself.

This is the largest remaining hole in the threat model. Scan message and draft
text before it leaves:

- refuse credential-shaped strings (API hashes, private keys, tokens, seed
  phrases) — the audit log's scrubber already recognises them;
- warn or refuse on bulk quoting of another chat's content;
- a configurable maximum length, and a first-contact rule per chat.

Inbound detection cannot close this one. Nothing else in the list protects
against it either.

## 3. Human-in-the-loop confirmation for high-impact actions
**Impact: very high · Effort: M**

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
**Impact: high · Effort: S**

Token buckets and the FloodWait cooldown live in memory. A client that restarts
the server — a crash loop, a client that respawns on error, a user retrying —
resets every budget to full and forgets that Telegram asked for a 300-second
wait. The protection disappears exactly when things are going wrong.

Persist bucket state and `cooldown_until` to the state directory and reload at
startup. **The best value-per-effort item on the list**: a day's work closing a
real hole, which is why it outranks several things with higher ceilings.

## 5. A labelled detection corpus with precision/recall reporting
**Impact: high · Effort: M**

Detection quality is asserted by a hand-written test list. That proves the rules
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
**Impact: medium-high · Effort: S**

There is no way to ask "why was this flagged?" without reading the source.
`telegram-mcp-enhanced explain "<text>"` printing the classification, every rule
that matched, the matched spans and what each mode would do turns rule tuning
from guesswork into a two-second check.

A day's work that multiplies the value of item 5 and makes every detection
change after it cheaper.

## 7. Meter at the Telethon RPC boundary
**Impact: high · Effort: M · flagged by review twice, only narrowed**

The scheduler admits one *tool call* at a time, not one *Telegram request*. A
call that paginates still issues several requests under a single admission.
v1.0.0 narrows this — bulk read acknowledgement, a cap on `limit`, token cost
proportional to the pages a read will fetch, a ceiling on messages scanned — but
the complete fix is to meter inside `TelegramClient.__call__`, where every RPC
funnels through.

The care needed is re-entrancy: the outer call already holds the concurrency
semaphore, so per-RPC metering must apply the bucket and the pacing interval
only, never the semaphore, or a `max_concurrent = 1` server deadlocks against
itself.

## 8. Per-chat permission profiles
**Impact: high · Effort: M**

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
**Impact: medium-high · Effort: S**

`init-config --preset read-only|assistant|locked-down` instead of one template
plus prose. Most operators want a known-good starting point, not a tour of forty
settings.

Ranked above several technically deeper items because **security products fail
by misconfiguration more often than by defect**. A preset that is correct out of
the box protects more people than a control nobody enables. A day's work.

## 10. Localised and multilingual detection
**Impact: medium-high · Effort: M**

Every rule is English. An injection written in Spanish, Russian or Chinese
passes cleanly, and the model will understand it perfectly well.

This is a genuine hole rather than polish — it was mis-ranked as polish in the
first draft of this document. Either translate the high-value rules or move them
to a language-agnostic form. Needs item 5 first, or there is no way to tell
whether a translated rule set is any good.

## 11. Session hardening
**Impact: medium · Effort: M**

The Telethon session is a plaintext SQLite file. Anything that can read the
user's home directory can impersonate the account — which is a larger prize than
anything else this server protects.

Support `StringSession` held in the OS keychain (Keychain, libsecret, DPAPI).
Ranked here rather than higher only because it is an exposure the operating
system is also responsible for, and the file guard already refuses to upload it.

## 12. Attachment content inspection
**Impact: medium · Effort: M**

`media_download` scans the file *name* and writes the file to disk. It does not
look at what the file is. An agent asked to "read the attached document" can be
handed a file whose contents are an injection payload, or an executable.

Add magic-byte type verification, a size ceiling, an optional extension
allowlist, and gateway scanning of extracted text for text-like formats.

## 13. Tool-name canary detection
**Impact: medium · Effort: S**

Flag any incoming message mentioning this server's own tool names, a chat ID
from the allowlist, or the operator's username. Nothing legitimate does that, so
it is high-signal with near-zero false positives — the cheapest detection win
available.

## 14. Dry-run mode
**Impact: medium · Effort: S**

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
**Impact: medium · Effort: S**

In `block` mode the content is simply gone, so an operator cannot see what was
withheld without opening Telegram. A `get_quarantined_message` tool, gated
behind confirmation from item 3, would let a human inspect it deliberately.

## 17. Security log tooling
**Impact: medium · Effort: S**

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

1, 2, 3 and 4. The first tells you whether what exists actually works; the
second closes the biggest remaining hole; the third makes the dangerous
permissions usable; the fourth is a day's work that stops a crash loop
discarding every limit. Everything after that is improvement rather than repair.
