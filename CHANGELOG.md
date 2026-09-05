# Changelog

All notable changes to Telegram MCP Enhanced are documented here. This project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **Resolution crashed on the integer id a private link yields.**
  `parse_telegram_url` returns an int for `t.me/c/…` links, and the third
  round's normalisation fix called a string-only parser on it, so authorising a
  permitted private link failed before Telegram was asked. The shared parser is
  now idempotent for ints.

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
