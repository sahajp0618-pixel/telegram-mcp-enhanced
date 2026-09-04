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

Found by review of this project's own code, after the layer was written:

- The detector's 50-match cap broke out of the whole rule loop rather than the
  current rule, so padding a message with cheap low-severity hits stopped later
  rules from running and could downgrade a `high_risk` message to `suspicious` —
  in `block` mode, the difference between withheld and delivered.
- A chat allowlist written as usernames denied access it had granted: search
  results were matched only on the numeric chat ID, and a bare peer ID was
  refused without resolution, so the ID the agent had just been given by
  `search_dialogs` was rejected.

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
