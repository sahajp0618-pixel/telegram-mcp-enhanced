# Configuration reference

Every setting the enhanced layer adds, with its default and effect. Upstream's
`API_ID` / `API_HASH` credentials are unchanged and are **not** part of this
file — they stay in the environment.

## Where configuration comes from

Sources, in increasing order of priority:

1. built-in defaults;
2. a TOML file;
3. environment variables.

The file is looked up at `$TELEGRAM_MCP_CONFIG`, and otherwise at
`$XDG_CONFIG_HOME/mcp-telegram/config.toml` (on macOS and Linux this is
usually `~/.config/mcp-telegram/config.toml`).

```bash
telegram-mcp-enhanced init-config    # write a commented starter file
telegram-mcp-enhanced security       # show what is currently in force
```

A file that cannot be parsed, contains an unknown section or key, or contains an
invalid regex is a **fatal error**: the server refuses to start rather than
running with a policy you did not choose. A misspelled `allow_delet = true` is
caught, not ignored.

---

## `[security.prompt_injection]`

| Setting | Type | Default | Effect |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Turn detection off entirely. Content is still encapsulated and marked untrusted, with `scanned: false`. |
| `mode` | `flag` \| `redact` \| `block` | `flag` | How detections are handled. See below. |
| `block_risk_threshold` | `suspicious` \| `high_risk` | `high_risk` | In `block` mode, the classification at which content is withheld. `normal` is rejected — it would block everything. |
| `custom_patterns` | list | `[]` | Your own rules. |
| `disabled_rules` | list of strings | `[]` | Built-in rule IDs to switch off. |
| `scan_dialog_titles` | bool | `true` | Scan chat titles and usernames. |
| `scan_media_filenames` | bool | `true` | Scan sender-supplied file names. |
| `max_scan_chars` | int | `20000` | Cap on characters scanned per item. Content beyond the cap is classified `suspicious` rather than silently cleared. |

### Modes

- **`flag`** (recommended default) — the original message is returned
  byte-for-byte with safety metadata attached. Nothing is hidden or rewritten.
- **`redact`** — matched spans are replaced with `[REDACTED:<rule_id>]`; the
  surrounding conversation survives. Hidden characters are stripped precisely.
- **`block`** — content at or above `block_risk_threshold` is replaced by a
  placeholder naming the rules that fired. Detections below the threshold are
  still flagged. Because detection has false positives, this is opt-in.

### Custom rules

Two spellings are accepted. A bare list of regexes:

```toml
[security.prompt_injection]
custom_patterns = [
    "ignore .* previous instructions",
    "reveal .* system prompt",
]
```

Or full rules, when you want to control the ID and severity:

```toml
[[security.prompt_injection.custom_patterns]]
id = "internal_codenames"
pattern = "project (bluebird|redwood)"
risk = "suspicious"          # normal | suspicious | high_risk
description = "Mentions an internal codename"
ignore_case = true
```

Patterns are compiled once at startup and are case-insensitive unless
`ignore_case = false`. An invalid expression is reported with its rule ID and
stops the server.

### Built-in rule IDs

Pass any of these to `disabled_rules`:

`instruction_override`, `instruction_override_broad`, `system_role_impersonation`,
`chat_template_markers`, `fake_tool_result`, `authority_claim`,
`prompt_extraction`, `credential_exfiltration`, `credential_reference`,
`cross_chat_access`, `data_exfiltration`, `tool_execution_request`,
`tool_name_invocation`, `agent_addressed_command`, `shell_command_injection`,
`restriction_bypass`, `jailbreak_persona`, `role_redefinition`,
`role_play_request`, `conceal_from_user`, `comment_smuggling`, `encoded_payload`.

Structural findings, which are not regex rules and cannot be disabled
individually: `unicode_tag_characters`, `bidi_control_characters`,
`invisible_characters`, `excessive_whitespace`, `content_truncated_for_scanning`.

---

## `[permissions]`

| Setting | Type | Default | Effect |
| --- | --- | --- | --- |
| `default_policy` | `allow` \| `deny` | inferred | Chat policy for chats not named in a list. See below. |
| `allowed_chats` | list | `[]` | Chats this server may touch. `"*"` means all. |
| `denied_chats` | list | `[]` | Chats it may never touch. Always wins. |
| `allow_read` | bool | `true` | `get_messages`, `message_from_link` |
| `allow_search` | bool | `true` | `search_dialogs` |
| `allow_send` | bool | `true` | `send_message` |
| `allow_edit` | bool | **`false`** | `edit_message` |
| `allow_delete` | bool | **`false`** | `delete_message` |
| `allow_drafts` | bool | `true` | `get_draft`, `set_draft` |
| `allow_download` | bool | `true` | `media_download` |
| `allow_admin` | bool | **`false`** | reserved for administrative operations |

Permissions are independent: granting read does not grant send, and granting
send does not grant delete.

A refusal names the operation, not the setting, so this is the mapping you need
when you see `"operation": "DELETE_MESSAGES"` in an error or in
`security_status`:

| Operation in errors and `security_status` | Setting |
| --- | --- |
| `READ_MESSAGES` | `allow_read` |
| `SEARCH_MESSAGES` | `allow_search` |
| `SEND_MESSAGES` | `allow_send` |
| `EDIT_MESSAGES` | `allow_edit` |
| `DELETE_MESSAGES` | `allow_delete` |
| `MANAGE_DRAFTS` | `allow_drafts` |
| `DOWNLOAD_MEDIA` | `allow_download` |
| `ADMINISTRATIVE_ACTIONS` | `allow_admin` |

### How `default_policy` is resolved

| Configuration | Effective policy |
| --- | --- |
| `default_policy` set explicitly | exactly that |
| `allowed_chats` non-empty, no explicit policy | `deny` — allowlist semantics |
| neither configured | `allow`, with a warning at startup |

The third row preserves upstream behaviour for people who have not configured
anything yet. Once you list a single allowed chat, everything else is denied.

### Writing chat identifiers

Accepted forms: numeric IDs (`-1001234567890`), usernames (`@alice`, `alice`),
`https://t.me/alice`, and `me`. Matching is case-insensitive.

Numeric IDs are canonicalised, so leading zeros and stray whitespace do not
change which chat an entry names. A leading `+` is significant: `+15551234567`
is a phone number and `15551234567` is a peer ID.

**Write IDs the way Telegram reports them.** Channel and supergroup IDs may be
written with or without the `-100` prefix, but the two forms are only reconciled
*after* Telegram confirms the peer is a channel — never by string arithmetic,
because `1234567890` is a user and `-1001234567890` is a channel and they are
different chats. A bare positive number therefore matches a user with that ID as
well as a channel with it, and the server warns at startup when it sees one. A
sign flip is never treated as equivalent: user `12345` and basic group `-12345`
are different chats.

Matching works in both directions, because the agent rarely uses the spelling
you wrote. An identifier that does not match textually is resolved with Telegram
and checked again against both its peer ID and its username, so `@alice` matches
an allowlist naming her numeric ID *and* the numeric ID that `search_dialogs`
hands the agent matches an allowlist naming `@alice`. Search results are matched
on both without any extra Telegram call.

A rule written as a **username is always confirmed with Telegram** before it
grants access, and the request then goes to the peer that came back. A textual
match is not proof: Telethon can resolve a decorated or malformed name through
its cached display-name fallback, so `alice/` matching an entry for `@alice`
could otherwise execute against an unrelated chat. Confirmation costs one lookup
per distinct identifier, served from Telethon's session cache thereafter, and
`me` is exempt because it resolves to the account itself and cannot be
redirected.

Otherwise resolution is only attempted when it could change the answer: an
unlisted ID against an allowlist made entirely of IDs is denied outright, and a
server with no chat rules at all never resolves anything. If resolution fails,
access is **denied**.

This applies to `denied_chats` too, and that is the point: without resolving,
a chat denied by its ID could still be reached by its username. Configuring any
`denied_chats` therefore costs one resolution per distinct identifier — served
from Telethon's session cache after the first time.

---

## `[security.files]`

| Setting | Type | Default | Effect |
| --- | --- | --- | --- |
| `protect_sensitive_paths` | bool | `true` | Refuse to upload credentials, keys, session files, browser and shell history, and files inside sensitive directories. |
| `max_files_per_message` | int | `10` | Ceiling on attachments in one send. **Cannot exceed 10.** Telegram groups albums of ten, and Telethon sends a longer list as several albums in sequence — a flood wait on the second would make the automatic retry re-deliver the first, and a send is not idempotent. Held to one album, a send either happens or is refused. |
| `max_upload_bytes` | int | `2147483648` | Ceiling on the combined size of one send's attachments. `0` disables the check. |
| `allowed_upload_dirs` | list | `[]` | If set, uploads must come from one of these directories — this **replaces** the pattern checks. |
| `allowed_download_dirs` | list | `[]` | If set, `media_download` may only write inside these directories. |
| `extra_denied_patterns` | list | `[]` | Extra `fnmatch` patterns, tested against the full path and the file name. |

Paths are resolved through symlinks before being judged. The Telegram session
and state directory is always refused, even if an allowlist names it.

Downloaded files are saved under a name built from the message id and a UUID,
never from the sender's filename: that path is returned to the model and written
to disk, so it must not carry text a stranger chose. The original name is still
reported as `media.file_name`, with safety metadata.

Denied by default: `.env`, `id_rsa*`, `id_ed25519*`, `*.pem`, `*.key`, `*.p12`,
`*.kdbx`, `*.session`, `credentials*`, `secrets*`, `.netrc`, `.pgpass`,
`.git-credentials`, `.npmrc`, `.pypirc`, `known_hosts`, `authorized_keys`,
`*_history`, `Cookies`, `Login Data`, and anything under `.ssh`, `.aws`,
`.gnupg`, `.kube`, `.docker`, `.password-store`, `.mozilla`, `Keychains`,
`gcloud` or `gh`.

---

## `[rate_limit]`

| Setting | Type | Default | Effect |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Turn all pacing off. Not recommended with an autonomous agent. |
| `minimum_interval_ms` | int | `500` | Minimum gap between dispatched Telegram operations. |
| `max_concurrent` | int | `2` | Operations in flight at once. |
| `max_retries` | int | `2` | Retries after a flood wait, per tool call. |
| `max_flood_wait_seconds` | float | `60` | Longest wait the server will sit through. Beyond it, a structured `rate_limited` response is returned immediately. |
| `queue_timeout_seconds` | float | `120` | How long a call waits for a slot before reporting `rate_limited`. |
| `max_messages_per_call` | int | `200` | Ceiling on `get_messages(limit=…)`. One call holds one slot but paginates, so an unbounded limit would let a single token generate unbounded Telegram traffic. |
| `messages_per_token` | int | `100` | How many messages one read token pays for. A 500-message read is charged 5 tokens, not 1. |
| `max_messages_scanned` | int | `500` | Ceiling on messages *examined* by one read. Service and empty messages are skipped without counting toward `limit`, so a history full of them would otherwise page indefinitely even for `limit=1`. |

### Per-class buckets

Operations are classed `read`, `search`, `write`, `media` and `admin`, each with
its own token bucket:

| Class | Capacity | Refill / minute | Tools |
| --- | --- | --- | --- |
| `read` | 20 | 60 | `get_messages`, `message_from_link`, entity resolution |
| `search` | 5 | 20 | `search_dialogs` |
| `write` | 5 | 20 | `send_message`, `edit_message`, `delete_message`, `set_draft` |
| `media` | 3 | 10 | `media_download` |
| `admin` | 2 | 5 | administrative operations |

Override individually; unnamed buckets keep their defaults:

```toml
[rate_limit.buckets.write]
capacity = 3
refill_per_minute = 10
```

---

## `[security.logging]`

| Setting | Type | Default | Effect |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Write security events. |
| `include_message_content` | bool | **`false`** | Include a 200-character excerpt of the offending message. Off by default. |
| `path` | string | `<state dir>/security.log` | Where to write. |
| `max_bytes` | int | `1000000` | Rotate at this size. |
| `backup_count` | int | `3` | Rotated files to keep. |

Records are JSON lines with `timestamp`, `event`, `tool`, `chat_id`,
`message_id`, `risk_level`, `classification`, `rule_triggered` and
`action_taken`. Credentials are removed from every field, both by literal value
(from the environment) and by shape (32-hex hashes, session strings).

Events: `server_start`, `server_stop`, `injection_detected`,
`permission_denied`, `rate_limited`, `flood_wait`, `file_access_denied`.

---

## Top level

| Setting | Type | Default | Effect |
| --- | --- | --- | --- |
| `log_level` | `DEBUG` … `CRITICAL` | `INFO` | Diagnostic logging on stderr. `DEBUG` includes Telethon protocol detail, which can contain message content. |

---

## Environment variables

Each overrides the corresponding file setting.

| Variable | Sets |
| --- | --- |
| `TELEGRAM_MCP_CONFIG` | path to the config file |
| `TELEGRAM_MCP_LOG_LEVEL` | `log_level` |
| `TELEGRAM_MCP_SECURITY_ENABLED` | `prompt_injection.enabled` |
| `TELEGRAM_MCP_SECURITY_MODE` | `prompt_injection.mode` |
| `TELEGRAM_MCP_DEFAULT_CHAT_POLICY` | `permissions.default_policy` |
| `TELEGRAM_MCP_ALLOWED_CHATS` | `permissions.allowed_chats` (comma-separated) |
| `TELEGRAM_MCP_DENIED_CHATS` | `permissions.denied_chats` (comma-separated) |
| `TELEGRAM_MCP_ALLOW_READ` … `_ADMIN` | the matching `allow_*` permission |
| `TELEGRAM_MCP_RATE_LIMIT_ENABLED` | `rate_limit.enabled` |
| `TELEGRAM_MCP_MIN_INTERVAL_MS` | `rate_limit.minimum_interval_ms` |
| `TELEGRAM_MCP_MAX_CONCURRENT` | `rate_limit.max_concurrent` |
| `TELEGRAM_MCP_MAX_RETRIES` | `rate_limit.max_retries` |
| `TELEGRAM_MCP_MAX_FLOOD_WAIT_SECONDS` | `rate_limit.max_flood_wait_seconds` |
| `TELEGRAM_MCP_SECURITY_LOG_ENABLED` | `security_logging.enabled` |
| `TELEGRAM_MCP_SECURITY_LOG_PATH` | `security_logging.path` |

Booleans accept `1/0`, `true/false`, `yes/no`, `on/off`. An unparseable value is
a fatal error, not a silent fallback.

---

## Recommended starting points

**Read-only assistant, one chat**

```toml
[permissions]
allowed_chats = ["-1001234567890"]
allow_send = false
allow_drafts = false
```

**Drafting assistant that never sends by itself**

```toml
[permissions]
allowed_chats = ["@alice", "-1001234567890"]
allow_send = false
allow_drafts = true
```

**Locked down, hostile environment**

```toml
[security.prompt_injection]
mode = "block"
block_risk_threshold = "high_risk"

[permissions]
default_policy = "deny"
allowed_chats = ["-1001234567890"]
allow_send = false
allow_download = false

[security.files]
allowed_upload_dirs = []

[rate_limit]
minimum_interval_ms = 1000
max_concurrent = 1
```
