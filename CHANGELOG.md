# Changelog

All notable changes to Telegram MCP Enhanced are documented here. This project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Never replay a partly-successful batch. `delete_messages` chunks its ids, so
  deleting more than a hundred messages is a real multi-request batch; if one
  chunk succeeded and another flood-waited, retrying the tool made
  `delete_message` revalidate ids that no longer exist and report an
  authorization failure for an irreversible partial deletion. Publishing the
  cooldown is now separate from deciding what to replay, so other operations
  still hold back for a wait this one cannot retry.
- Recognise a flood wait wrapped in Telethon's `MultiError`. Any list-form call
  wraps its failures that way, and `delete_messages` always sends a list — even
  for one message — so a flood wait during a deletion was neither retried nor
  reported as the temporary condition it is, surfacing as a raw Telethon error.
  The longest wait in the group wins, since satisfying the shortest would walk
  straight into the next.

- Meter at the Telethon RPC boundary instead of estimating per tool call. Every
  request funnels through a metered `TelegramClient.__call__`, so a paginating
  read now spends one token per page rather than one token for the call; the
  token bucket and pacing interval moved there, while the concurrency semaphore
  stays at tool admission so a paginating call cannot deadlock against itself at
  `max_concurrent = 1`. `cost_from` and `messages_per_token` are removed — a
  config file still setting the latter now fails to load rather than silently
  doing nothing.
- Exempt connection and sign-in from that metering. A flood wait outliving a
  restart is intended, but metering `connect()` made it refuse server startup
  entirely rather than refusing tool calls.

- Meter each RPC crossing Telethon `__call__`, including pagination, with shared
  tokens, pacing and cooldown, while tool slots only govern concurrency and
  excessive-cooldown refusal. Remove `messages_per_token` and argument-based
  cost estimates; existing configs must remove that key. Scheduler dispatch
  stats now count RPC admissions. Direct `_call` transfers/internal retries
  remain below this boundary.

- Make `mutates` a required declaration on every guarded tool rather than
  inferring it from the rate-limiting class, so a new tool cannot inherit a
  guess; the audit of state-changing options now resolves annotations and has a
  test proving it can fail.
- Fix two dry-run defects found by adversarial review: `get_messages(mark_as_read=True)`
  acknowledged messages on Telegram during a dry run because it is charged as a
  read, and `get_draft` was simulated because it is charged as a write. Mutation
  is now declared per tool (`mutates`, `mutating_flags`) instead of inferred from
  the rate-limiting class, and a test pins exactly which tools are simulated.
- Fix `.env.local` being exempt from credential-exfiltration detection: it was
  added alongside `.env.example` as a placeholder, but it is where Next.js, Vite
  and Create React App keep real credentials. Placeholder suffixes now also
  require a word boundary.

- Add `dry_run`, which runs the whole policy chain — chat authorization
  including the resolution round trip, permissions, file and outbound checks,
  the rate limiter and the scheduler — and substitutes only the final Telegram
  call for sends, edits, deletions and drafts. Reads stay real; `media_download`
  is refused rather than faked. Startup warns loudly and `security_status`
  reports it, so a simulated send is never reported to the user as a real one.
- Fix top-level config keys other than `log_level` being silently dropped while
  still passing validation, which would have made `dry_run = true` a no-op with
  no error. Top-level scalars are now derived from the model.

- Add a labelled detection corpus (111 entries: 44 attacks, 67 benign) scored on
  every test run, with precision/recall floors that fail the build on a new miss
  or a new false positive and name the entries that moved. Record measured
  quality and five known false positives in `docs/DETECTION.md`.
- Fix three detection bypasses the corpus found: the `.env` branch of
  `credential_exfiltration` was unsatisfiable, `data_exfiltration` was evaded by
  inserting one adjective before "conversation", and Cyrillic capitals were
  absent from the homoglyph table, so `Іgnore all previous instructions`
  bypassed `instruction_override` entirely.

- Add configurable `[security.outbound]` middleware checks for outgoing message
  and draft text, also covering edits via the shared `message` argument guard.
  Refuse credentials using the audit scrubber's shared detection, excessive
  length and conservative bulk quoting. Return non-retryable, policy-labeled
  errors without rejected text, each carrying a fixed hint naming which check
  fired and the setting that relaxes it, so a refused credential is never
  reported as an unexplained failure; internal check failures also refuse the
  send.

- Add `init-config --preset` with `read-only`, `assistant` and `locked-down`
  commented policies, composable with `--path` and `--force`. Omitting the
  preset keeps the original starter template.

- Persist rate-limit budgets and FloodWait cooldowns across client restarts,
  with atomic snapshots and configurable opt-out.

## [1.0.0] — 2026-09-04

First release of the enhanced downstream project, based on
[dryeab/mcp-telegram](https://github.com/dryeab/mcp-telegram) v0.1.11.

### Inherited from upstream

The Telegram-to-MCP foundation, unchanged in behaviour except where noted under
*Fixed* and *Changed*:

- MCP server built on Telethon and MTProto, with the server name `mcp-telegram`.
- Messaging tools: `send_message`, `edit_message`, `delete_message`,
  `get_messages`.
- Search and navigation: `search_dialogs`, `message_from_link`.
- Draft management: `get_draft`, `set_draft`.
- Media handling: `media_download`.
- Telethon authentication and session lifecycle, including the CLI commands
  `login`, `logout`, `clear-session`, `start`, `tools` and `version`.
- The `API_ID` / `API_HASH` environment variables and the session file location.

### Added by Telegram MCP Enhanced

**Untrusted content handling**

- Untrusted content gateway: a single path for every externally authored string
  (message text, chat titles, usernames, sender-supplied file names).
- Prompt-injection detector with 22 built-in rules and structural analysis for
  invisible characters, bidirectional controls, Unicode tag characters and
  oversized blank runs.
- Evasion-resistant matching: NFKC folding, homoglyph mapping and format-
  character removal, with match offsets mapped back to the original text.
- Risk classification (`normal` / `suspicious` / `high_risk` / `blocked`)
  exposed as structured MCP metadata.
- Safety encapsulation: `source`, `trust_level`, per-item `security` metadata,
  batch summaries and a standing untrusted-content notice.
- Security modes `flag` (default), `redact` and `block`, with a configurable
  block threshold.
- Administrator-defined detection rules, and the ability to disable built-in
  ones. Both `custom_patterns = ["regex"]` and full rule tables are accepted.

**Server-side enforcement**

- Independent operation permissions: read, search, send, edit, delete, drafts,
  download, administrative.
- Chat-level access control with allow and deny lists, `-100` prefix
  equivalence, and resolution of usernames to peer IDs when needed.
- Search results are filtered to allowed chats, with a `withheld_count`.
- File-access policy for uploads and downloads, with symlink resolution and an
  always-denied session directory.
- Credential scrubbing in the security log, by literal value and by shape.

**Reliability**

- Per-class token-bucket rate limiter (read, search, write, media, admin).
- Shared asynchronous request scheduler with a concurrency guard and a
  configurable minimum request interval.
- FloodWait interception with a scheduler-wide cooldown, bounded retries and
  structured `rate_limited` responses.

**Configuration and operations**

- TOML configuration at `$XDG_CONFIG_HOME/mcp-telegram/config.toml` or
  `$TELEGRAM_MCP_CONFIG`, plus environment-variable overrides.
- Rotating JSON-lines security event log, message content excluded by default.
- New CLI commands `init-config` and `security`.
- New MCP tool `security_status`, reporting policy without revealing secrets.
- Startup logging of the effective policy, including a warning when chat access
  control is not configured.
- 244 automated tests covering detection, security modes, custom rules,
  permissions, chat access, bypass attempts, rate limiting, FloodWait handling,
  configuration, performance and upstream regression.

### Fixed

- **Installation was broken on current dependencies.** Upstream requires
  `mcp[cli]>=1.6.0` with no upper bound, but `mcp` 2.0 renamed `FastMCP` to
  `MCPServer` and `Tool.inputSchema` to `Tool.input_schema`, so a fresh install
  failed at import. A compatibility shim supports both generations; the test
  suite runs against `mcp` 1.29 and 2.1.
- **`get_messages(unread=True)` always returned an empty list**, because
  `Dialog.from_entity` reports an unread count of zero. The real unread state is
  now fetched when it is needed.
- **Structured errors were invisible to the model on `mcp` 2.x**, which
  withholds the text of unexpected exceptions. Refusals now derive from the
  SDK's `ToolError` so their payload reaches the agent.
- **Shutdown could mask a startup failure**: if the client was never created,
  the lifespan's `finally` raised `RuntimeError: Client not created!` over the
  original error.
- **`login` never awaited `disconnect()`**, leaving an un-awaited coroutine.

### Fixed before release

Found by reviewing this project's own code, and by an adversarial review of the
branch, after the layer was written:

- The detector's 50-match cap broke out of the whole rule loop rather than the
  current rule, so padding a message with cheap low-severity hits stopped later
  rules from running and could downgrade a `high_risk` message to `suspicious` —
  in `block` mode, the difference between withheld and delivered.
- A chat allowlist written as usernames denied access it had granted: search
  results were matched only on the numeric chat ID, and a bare peer ID was
  refused without resolution, so the ID the agent had just been given by
  `search_dialogs` was rejected.
- **`denied_chats` was bypassable by spelling.** An identifier was allowed
  before canonical resolution, so `denied_chats = ["-100123"]` still let
  `@victim` through when it resolved to that same chat. Resolution now happens
  whenever it could change the answer in *either* direction, and a denial is
  applied to the union of the raw and canonical identifiers.
- **Telethon absorbed most flood waits before this server saw them.** The client
  was created with Telethon's default `flood_sleep_threshold=60`, so every wait
  under a minute was slept off inside the library — bypassing the shared
  cooldown, the retry budget and the audit trail while holding a scheduler slot.
  It is now `0`. `_unread_state` also swallowed `FloodError` and reported "no
  unread messages", hiding the rate limit entirely.
- **`block` and `redact` modes returned hostile filenames and usernames
  verbatim.** The gateway computed the transformed text and then discarded it
  for media file names and dialog usernames, so the operator's chosen mode was
  not applied to those fields.
- **A flood wait arriving mid-sleep did not extend an existing waiter.** The
  cooldown was measured once, so a waiter woke at a stale deadline and
  dispatched into a wait that was still running.
- **Invisible characters outside category `Cf` defeated every rule.** A single
  U+034F or variation selector inside a keyword — invisible to any reader —
  made `I͏gnore all previous instructions` classify as `normal`. The whole
  Unicode default-ignorable set is now folded away, and underscores are treated
  as separators so an attack in a username cannot hide either.
- **One rate-limit token bought unbounded Telegram traffic.** `mark_as_read`
  issued a separate request per message, so a single read token could generate
  as many requests as the caller asked for messages. Acknowledgement is now one
  bulk request, reads are charged tokens in proportion to the pages they will
  fetch, and `limit` is capped by `max_messages_per_call`.

A second adversarial review of the fixed branch found six more, all reproduced
before being fixed:

- **Deletion was not scoped to the authorised chat.** For users and basic
  groups, MTProto's `messages.deleteMessages` carries no peer, so Telegram
  deletes by id alone and the `entity` argument does not constrain it. A caller
  could name an allowed chat and pass ids belonging to a denied one — and
  deletion is irreversible. Every id is now proven to belong to the authorised
  chat, the whole batch is refused on any mismatch, and batch size is capped.
- **A channel allowlist entry authorised the same-numbered user.** Numeric
  identifiers were expanded into `-100` variants before the peer type was
  known, so `allowed_chats = ["-1001234567890"]` also admitted user
  `1234567890`. Raw matching is now exact; the `-100` form is reconciled only
  after Telegram confirms the peer really is a channel.
- **Redact mode left later occurrences in place.** Only the first ten matches
  per rule were recorded, and redaction rewrites exactly the recorded spans, so
  the eleventh occurrence survived while the metadata said `redacted`. The span
  budget is now generous, and exhausting it withholds the field instead of
  rewriting part of it.
- **Blocked filenames survived in the download path.** The saved file name was
  built from the sender's, so hostile text reached the model through a field
  that cannot be rewritten — the path has to keep naming the real file. Local
  names are now built from server-controlled values and a validated extension,
  which also neutralises path traversal and markup in sender filenames.
- **Reads bounded returned messages but not scanned history.** Service and empty
  messages are skipped without counting toward `limit`, so a history full of
  them could page indefinitely even for `limit=1`. `max_messages_scanned` now
  bounds what one call examines.
- **A cooldown released queued requests as a burst.** Pacing was satisfied
  before the cooldown wait, so requests woke together and dispatched without
  spacing. Cooldown and minimum interval are now one dispatch gate under a
  single lock, re-checking both after every sleep.

A third review found three more:

- **Authorisation and execution could resolve different peers.** The middleware
  passed the raw identifier string to Telethon, which reads a numeric string as
  a phone number — `parse_phone` strips the sign, so `-1001234567890` was looked
  up as the phone `1001234567890` — while the tool body passed the integer peer
  id. Resolution now normalises exactly as execution does.
- **Structural findings were dropped silently.** Runs of invisible, bidi or tag
  characters were truncated to twenty before the scanner could notice, so
  redaction left the twenty-first in place while reporting `redacted`. Dropping
  a run now marks the result capped, which withholds the field.
- **One send could upload arbitrarily much.** `file_path` was unbounded and
  charged a single write token, and Telethon uploads a long list as several
  albums inside that one slot. Attachments are now capped by count and total
  bytes, and a send is charged one token per attachment.

A fourth review found two more, one of them a regression from the third round:

- **Zero-padded numeric ids bypassed `denied_chats`.** `-01001234567890` matched
  no list entry, so it was allowed without resolution — and then `parse_entity`
  turned it into exactly the denied chat for execution. Numeric identifiers are
  now canonicalised through `int` on both sides of the comparison. A leading `+`
  deliberately is not: `+15551234567` is a phone number to Telethon and
  `15551234567` is a peer id, and merging them would be a new conflation.
- **Failed downloads left partial files behind.** Telethon closes its output
  on failure but does not delete it, and every attempt picks a fresh UUID
  filename, so a flood wait part-way through a download left an orphan on each
  automatic retry — on the volume that also holds the Telegram session. The
  partial file is now removed before the retry.
- **An automatic retry could duplicate a partly delivered send.** Telethon
  sends more than ten attachments as several albums in sequence, so a flood wait
  on a later album made the retry re-deliver the earlier ones — the user would
  see the same photos twice. Attachments are now capped at Telegram's album size
  of ten, which cannot be raised, so a send is a single request that either
  happens or is refused. Retrying is only safe when the operation being repeated
  is.
- **A message of blank lines could freeze the server (ReDoS).** Found by
  fuzzing the detector rather than by review. Three adjacent unbounded
  whitespace groups in the system-impersonation rule let the regex engine
  partition a blank run exponentially many ways: 2,000 newlines took 43 seconds,
  and 50,000 exhausted memory. Scanning is synchronous, so one Telegram message
  would have taken the whole MCP server down. The whitespace quantifiers are
  bounded now, long blank runs are collapsed before any pattern sees them, and a
  test scans fourteen pathological inputs with a 250 ms ceiling. A second rule
  with the same shape was found and fixed by a structural check that now rejects
  the shape outright.
- **A decorated Saved Messages alias bypassed confirmation.** `me/` normalised
  to the same token as `me` and took the self exemption, but Telegram maps only
  the exact literals `me` and `self` to the account — `me/` goes to whatever
  peer is cached under that display name. So a Saved-Messages-only allowlist
  could admit an unrelated chat. The exemption is now judged on the exact
  identifier execution sends, and a test pins Telethon's real behaviour rather
  than this project's belief about it.
- **A matching name granted access without being confirmed.** `alice/`
  normalised to the same token as `@alice` and was allowed outright, while
  execution kept the string — and Telethon can resolve a decorated name through
  its cached display-name fallback to a peer that does not hold that username. A
  username rule is now always confirmed with Telegram, the peer that comes back
  has its own username checked verbatim, and the request goes to that peer. `me`
  is exempt: it resolves to the account itself and cannot be redirected.
- **A decorated number could pose as a peer id.** Normalisation stripped `@`,
  URL and trailing-slash decorations *before* deciding whether an identifier was
  a number, so `123/` produced the token `123` and matched a rule about peer 123
  — while Telethon kept the string and could resolve it by cached title to an
  entirely different chat. Whether something is a peer id is now decided by the
  parser execution uses, and tokens carry a type tag, so a chat *named* `123`
  can never satisfy a rule about the chat *with id* `123`.
- **`message_from_link` discarded its resolved peer.** Only tools with an
  `entity` argument had the authorised peer substituted; the link tool re-parsed
  its link and resolved it again. It now reads the peer that was authorised.
- **Execution now targets the peer that was authorised.** When an identifier
  had to be resolved, the raw identifier was still what reached Telegram, so the
  peer was resolved a second time and the check was only probably about the same
  chat as the action. The resolved peer id is substituted instead.
- **Policy and execution used three different "is this a number?" tests.**
  Four separate findings across three review rounds were all the same defect:
  the security layer decided what an identifier named using one rule, and
  execution used another. There is now a single shared parser, and a
  property-style test asserts the two layers read every adversarial spelling
  identically — whitespace-wrapped, zero-padded, `--123`, Arabic-Indic digits,
  phone-shaped and username forms alike. That test found the last instance
  itself: `--123` was allowed without resolution while Telethon would have
  resolved it as the phone number `123`.
- **Surrounding whitespace split policy from execution.** Found while auditing
  for the same class of defect rather than reported: `" -1001234567890 "` is a
  chat id to the policy layer, but unstripped it stayed a *string*, and Telethon
  reads a numeric string as a phone number. Authorisation would clear the chat
  while execution looked up a phone. Identifiers are stripped before parsing.
- **Resolution crashed on the integer id a private link yields.**
  `parse_telegram_url` returns an int for `t.me/c/…` links, and the third
  round's normalisation fix called a string-only parser on it, so authorising a
  permitted private link failed before Telegram was asked. The shared parser is
  now idempotent for ints.

All of the above were found by eleven rounds of adversarial review plus
targeted fuzzing, each reproduced before being fixed and each covered by a test
that fails against the previous code. The final round returned no material
findings.

- **Redacting one secret could expose another.** Scrubbing substituted pattern
  by pattern, so replacing a hash inside a session string severed the session
  alphabet and the session matcher no longer saw it — leaving the rest of the
  credential in place. Matches are now located against the original text, merged
  and replaced in one pass, so no substitution can hide another.
- **A session string beside a word character was not scrubbed at all.** The
  StringSession pattern kept the word boundary that had already been removed
  from the hash pattern, so `x` + session matched nothing and all 353 characters
  reached the log — including in untruncated fields, which rely on scrubbing
  alone. A session string grants the account outright. It is now anchored on the
  session alphabet.
- **A credential could survive the log excerpt as a fragment.** With content
  logging enabled, the excerpt was truncated *before* scrubbing, so an API hash
  straddling the 200-character cut lost one character — and a fragment matches
  neither the literal value nor the fixed-width shape pattern. Thirty-one of
  thirty-two characters reached the log, leaving sixteen guesses. Scrubbing now
  runs on the whole string first. The shape pattern was also anchored on "not
  more hex" rather than a word boundary, which had let `hash0123…` through.
- **`clear-session` reported success after a partial deletion.** It stopped at
  the first error — skipping the remaining companions, which is exactly where
  cached contact data survives — and exited zero regardless, so a script
  following the documented deletion procedure could treat an incomplete purge as
  done. It now attempts every file, names what is left, and exits non-zero.
- **`clear-session` left SQLite companion files behind.** The Telethon session
  is a rollback-journal SQLite database, so an interrupted write leaves a
  `session.session-journal` beside it holding pre-change pages — already
  committed contact rows, not protocol scratch. A clean shutdown tidies it away;
  a client killing the server does not. `clear-session` now removes the
  companions, `paths` reports any that exist, and PRIVACY.md accounts for them.

### Added after the first review pass

- **`explain` command.** `telegram-mcp-enhanced explain "<text>"` (or `--file`)
  reports the classification, every rule that matched with its span in context,
  and what each of the three security modes would return — so the consequence of
  changing `mode` is visible before changing it. The text is shown locally and
  never written to the security log, even with content logging enabled: a
  debugging tool must not become the leak.
- **`tool_surface_canary` detection rule.** Fires on an exact MCP tool
  identifier such as `send_message`. Nobody writes those underscored names in a
  chat by accident, so it is high-signal with near-zero false positives, while
  ordinary English like "send message" does not match.
- **Rate limits and cooldowns now survive a restart** — see below.

### Changed

- Logging defaults to `INFO` and is configurable, instead of unconditional
  `DEBUG`. Upstream wrote Telethon protocol detail, including message content,
  to the terminal of anyone running the server.
- The `security_status` tool and `security` command were added; existing tool
  names, the MCP server name, environment variables and the session location are
  unchanged.
- The distribution is published as `telegram-mcp-enhanced`. The import package
  stays `mcp_telegram` so upstream patches merge cleanly, and both
  `telegram-mcp-enhanced` and `mcp-telegram` console commands are installed.

### Breaking changes

- **`search_dialogs` returns a `Dialogs` envelope** (`{source, trust_level,
  notice, security, dialogs, withheld_count}`) instead of a bare list of
  dialogs. Chat titles are external content and need safety metadata.
- **`edit_message`, `delete_message` and administrative actions are denied by
  default.** Set `allow_edit`, `allow_delete` or `allow_admin` under
  `[permissions]` to restore upstream behaviour.
- **A malformed configuration file stops the server** instead of being ignored.
- **Installing both this project and upstream `mcp-telegram` into the same
  environment will conflict**, since both provide the `mcp_telegram` package and
  the `mcp-telegram` command. Install them into separate environments.

### Removed

- Upstream's PyPI publishing workflow, which targeted the upstream maintainer's
  release process, and the upstream project logo. Neither belongs to this
  project.
