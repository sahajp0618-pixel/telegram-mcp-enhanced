# Roadmap: what would make this the best Telegram MCP server

v1.0.0 covers the security and reliability architecture the project set out to
build. This document is the honest list of what it still does *not* do, and what
would move it from "safe to point an agent at" to "the obvious choice".

Each item says what the gap is, why it matters, and roughly what it costs.
Items that an adversarial review flagged and v1.0.0 only partly closed are
marked as such. They
are ordered by value per unit of work, not by how interesting they are.

Legend — **Impact**: how much better the product gets. **Effort**: S (a day),
M (a few days), L (a week or more).

---

## Tier 1 — the gaps that matter most

### 1. Human-in-the-loop confirmation for high-impact actions
**Impact: very high · Effort: M**

Today every operation is a static allow or deny. That forces a bad choice: turn
`allow_delete` off and the agent cannot help you clean up a thread, or turn it
on and a successful injection can delete messages unattended.

MCP supports *elicitation* — the server can ask the client to put a question to
the human. A `confirm` policy tier would let operators say "deleting is allowed,
but ask me first", per operation and per chat:

```toml
[permissions]
allow_delete = "confirm"     # instead of true/false
confirm_send_to_new_chats = true
```

This is the single biggest improvement available. It converts the riskiest
operations from a policy problem into a UX problem, and it is exactly what an
autonomous agent's blast radius needs. Requires elicitation support in the
connected client, with a documented fallback to `deny` where it is unavailable.

### 2. Outbound content policy
**Impact: very high · Effort: M · flagged by review, not closed**

The gateway inspects everything coming *in* from Telegram and nothing going
*out*. The exfiltration path an injection actually wants — persuade the model to
compose a message containing your secrets and send it — is unguarded, because
the model writes that text itself.

An outbound policy would scan message and draft text before it leaves:

- refuse credential-shaped strings (API hashes, private keys, tokens, seed
  phrases) — the same scrubber the audit log already uses;
- warn or refuse on bulk quoting of another chat's content;
- configurable max length, and a per-chat first-contact rule.

This closes the loop that inbound detection alone cannot.

### 3. A labelled detection corpus with precision/recall reporting
**Impact: high · Effort: M**

Detection quality is currently asserted by a hand-written test list. That proves
the rules do what the author expected; it does not measure whether they are
*good*. Without a metric, every new rule is a guess and every tuning change is a
coin flip.

Ship a labelled corpus (attacks and benign messages, including hard negatives
like security discussions and quoted attacks) plus `pytest --benchmark-detection`
reporting precision, recall and per-rule false-positive rates. Then rule changes
become measurable, contributors can prove an improvement, and the README can
publish a real number instead of a rule count.

### 4. Event subscriptions instead of polling
**Impact: high · Effort: L**

An agent that wants to know about new messages has to call `get_messages` in a
loop — precisely the traffic pattern the rate limiter exists to suppress. The
server fights its own users.

Telethon already exposes an event stream. Surfacing new messages as an MCP
resource subscription (or a notification stream) would let an agent wait instead
of poll: less Telegram traffic, lower latency, and no flood-wait risk. Content
would flow through the same gateway, so the safety envelope is unchanged.

### 5. Meter at the Telethon RPC boundary
**Impact: high · Effort: M · flagged by review twice, only narrowed**

The scheduler admits one *tool call* at a time, not one *Telegram request*. A
call that paginates still issues several requests under a single admission.
v1.0.0 narrows this — bulk read acknowledgement, a cap on `limit`, and token
cost proportional to the pages a read will fetch — but the complete fix is to
meter inside `TelegramClient.__call__`, where every RPC funnels through.

The care needed is re-entrancy: the outer call already holds the concurrency
semaphore, so per-RPC metering must apply the bucket and the pacing interval
only, never the semaphore, or a `max_concurrent = 1` server deadlocks against
itself.

### 6. Rate-limiter and cooldown state that survives restarts
**Impact: high · Effort: S**

Token buckets and the FloodWait cooldown live in memory. An MCP client that
restarts the server — a crash loop, a client that respawns on error, a user
retrying — resets every budget to full and forgets that Telegram asked for a
300-second wait. The protection silently disappears exactly when things are
going wrong.

Persist bucket state and `cooldown_until` to the state directory and reload them
at startup. Small change, closes a real hole.

---

## Tier 2 — significant improvements

### 7. Per-chat permission profiles
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

### 8. Attachment content inspection
**Impact: medium-high · Effort: M**

`media_download` scans the *file name* and writes the file to disk. It does not
look at what the file is. An agent asked to "read the attached document" can be
handed a file whose contents are an injection payload, or an executable.

Add magic-byte type verification (does the content match the claimed MIME
type?), a size ceiling, an optional extension allowlist, and gateway scanning of
extracted text for text-like formats.

### 9. `explain` command for tuning detection
**Impact: medium-high · Effort: S**

There is no way to ask "why was this flagged?" without reading the source. A
`telegram-mcp-enhanced explain "<text>"` command that prints the classification,
every rule that matched, the matched spans and what each mode would do turns
rule tuning from guesswork into a two-second check. Cheap, and it makes every
other detection improvement easier to land.

### 10. Dry-run mode
**Impact: medium · Effort: S**

`dry_run = true` would let every write operation pass the full policy chain, log
exactly what it would have done, and return a realistic success response without
touching Telegram. This is how you would safely evaluate a new agent, test a
config change, or reproduce a report — and it is how the project could ship an
end-to-end demo that does not need an account.

### 11. Live integration test suite
**Impact: medium · Effort: M**

Every test uses a fake Telethon client, so the real integration points —
`resolve_peer_id`, `_unread_state`, actual FloodWait objects — are unproven
against Telegram itself. An opt-in `--live` suite running against a throwaway
account and a private test channel, skipped by default and excluded from CI,
would catch the class of bug that fakes cannot.

### 12. Session hardening
**Impact: medium · Effort: M**

The Telethon session is a plaintext SQLite file. Anything that can read the
user's home directory can impersonate the account. Support `StringSession` held
in the OS keychain (Keychain, libsecret, DPAPI), and document the tradeoff.

---

## Tier 3 — polish and reach

### 13. Multi-account support
**Effort: L** — one server, several accounts, each with its own session,
policy and rate-limit budget. Mostly a matter of making the runtime and state
directory account-scoped rather than global.

### 14. Security log tooling
**Effort: S** — `telegram-mcp-enhanced log --since 1h --event injection_detected`
to tail, filter and summarise the audit trail, plus an export for SIEM ingestion.
The log exists; nothing helps you read it.

### 15. Richer rate-limit shaping
**Effort: S** — per-tool rather than per-class budgets, a bandwidth-aware media
bucket (currently media is limited by request count, not bytes), and a burst
allowance distinct from the sustained rate.

### 16. Tool-name canary detection
**Effort: S** — flag any incoming message that mentions this server's own tool
names, chat IDs from the allowlist, or the operator's username. Nothing
legitimate does that; it is a high-signal, near-zero-false-positive rule.

### 17. Localised and multilingual detection
**Effort: M** — every rule is English. An injection written in Spanish, Russian
or Chinese passes cleanly. Either translate the rule set or move the high-value
rules to a language-agnostic form.

### 18. Quarantine retrieval
**Effort: S** — in `block` mode the content is simply gone, so an operator
cannot see what was withheld without reading the raw chat. A
`get_quarantined_message` tool, gated behind confirmation, would let the human
inspect it deliberately.

### 19. Prebuilt policy presets
**Effort: S** — `init-config --preset read-only|assistant|locked-down` instead of
one template plus prose. Most operators want a known-good starting point, not a
tour of thirty settings.

### 20. Docker image and MCP registry listing
**Effort: S** — a published image and a listing in the MCP server registries is
how most people will find this. Distribution is a feature.

---

## Deliberately not planned

- **LLM-based detection.** Sending message content to a model for classification
  would break the privacy guarantee that analysis is local, add latency and cost
  per message, and introduce an injection surface inside the defence itself.
- **Auto-replying or agentic autonomy features.** This is a security layer, not
  an agent framework. Its job is to make someone else's agent safe.
- **Blocking by default.** Detection has false positives; a default that hides
  real messages would be worse than the problem. `flag` stays the default.
