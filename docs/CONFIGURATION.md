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
telegram-mcp-enhanced paths          # show every location it reads or writes
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

Two further options control the text a rule is matched against. Neither ever
changes what the model receives.

- `preserve_underscores = true` keeps `_` instead of reading it as a space, for
  rules about literal identifiers such as `send_message`.
- `script = "cyrillic"` is for rules written in Cyrillic. By default lookalike
  letters are folded *to Latin*, so `Іgnore` with a Cyrillic `І` reads as
  English — but that same folding turns half of a Russian word into Latin and
  your rule would never match. `cyrillic` folds the other way, Latin lookalikes
  into Cyrillic, so `игнopируй` with a Latin `o` and `p` still matches. Chinese,
  Japanese and other scripts without lookalikes need neither; just do not rely
  on `\b`, which never fires between two ideographs.

### Built-in rule IDs

Pass any of these to `disabled_rules`:

`instruction_override`, `instruction_override_broad`, `system_role_impersonation`,
`chat_template_markers`, `fake_tool_result`, `authority_claim`,
`prompt_extraction`, `credential_exfiltration`, `credential_reference`,
`cross_chat_access`, `data_exfiltration`, `tool_execution_request`,
`tool_name_invocation`, `tool_surface_canary`, `agent_addressed_command`, `shell_command_injection`,
`restriction_bypass`, `jailbreak_persona`, `role_redefinition`,
`role_play_request`, `conceal_from_user`, `comment_smuggling`, `encoded_payload`.

Non-English rules, each a translation of one of the highest-value English rules
written for that language's word order:

- Spanish: `es_instruction_override`, `es_prompt_extraction`,
  `es_credential_exfiltration`, `es_role_redefinition`, `es_conceal_from_user`.
- Portuguese: `pt_instruction_override`, `pt_credential_exfiltration`.
- French: `fr_instruction_override`, `fr_credential_exfiltration`.
- German: `de_instruction_override`, `de_credential_exfiltration`.
- Russian (matched with `script = "cyrillic"`): `ru_instruction_override`,
  `ru_prompt_extraction`, `ru_credential_exfiltration`, `ru_role_redefinition`,
  `ru_conceal_from_user`.
- Chinese, simplified and traditional: `zh_instruction_override`,
  `zh_prompt_extraction`, `zh_credential_exfiltration`, `zh_role_redefinition`,
  `zh_conceal_from_user`.

Coverage outside English is narrower: these catch the canonical phrasings of the
most common attacks, not the long tail the English rules have been tuned on.

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
| `allow_read` | permission | `true` | `get_messages`, `message_from_link`, `get_quarantined_message` |
| `allow_search` | permission | `true` | `search_dialogs` |
| `allow_send` | permission | `true` | `send_message` |
| `allow_edit` | permission | **`false`** | `edit_message` |
| `allow_delete` | permission | **`false`** | `delete_message` |
| `allow_drafts` | permission | `true` | `get_draft`, `set_draft` |
| `allow_download` | permission | `true` | `media_download` |
| `allow_admin` | permission | **`false`** | reserved for administrative operations |
| `profiles` | list of tables | `[]` | Per-chat permission overrides. See [Per-chat profiles](#per-chat-profiles). |
| `confirm_timeout_seconds` | float | `120` | How long to wait for the user to answer a confirmation before refusing. |

A *permission* is `true`, `false` or `"confirm"`. Anything else — including a
quoted `"true"` — is rejected at startup rather than guessed at.

Permissions are independent: granting read does not grant send, and granting
send does not grant delete.

### The confirmation tier

`"confirm"` allows an operation only after the person using the MCP client
approves that specific call:

```toml
[permissions]
allow_delete = "confirm"
allow_send = "confirm"
```

The server sends an MCP *elicitation* — a question the client shows to its user,
not to the model. It names the tool, the operation, the chat (and the peer id it
resolved to), the shape of the action, and for sends and drafts the first 1000
characters of the text. The user must tick an explicit *Approve* box; submitting
the form without ticking it is a refusal, so a client that auto-submits defaults
cannot approve anything.

**Anything other than an explicit approval refuses** with a
`confirmation_denied` error whose `reason` says which case it was:

- the user declined or cancelled;
- no answer arrived within `confirm_timeout_seconds`;
- the MCP client did not declare elicitation support (many do not yet);
- the installed MCP SDK is too old to send an elicitation (mcp < 1.9);
- the call did not arrive over an MCP session, or the request failed.

So `"confirm"` with a client that cannot ask behaves as `false`. Choose `true`
or `false` explicitly if your client lacks elicitation.

The question is asked after every other check has passed — chat access,
permissions, file and outbound policy, resolution — and before the call enters
the scheduler, so a refused request costs nothing and a user taking two minutes
to answer does not hold a tool slot. `confirm` can only narrow what policy
allows: a permission set to `false` is refused without asking.

In [`dry_run`](#dry_run) nothing is asked. A simulated write notes that it would
have asked for confirmation; a read that would need confirmation is refused with
`dry_run_unsupported`, since it would be real and a dry run does not interrupt
the user.

`get_quarantined_message` always asks, whatever its permission says, because it
exists to show content the security mode withheld.

### Per-chat profiles

Permissions apply to every chat unless a profile says otherwise for specific
chats:

```toml
[permissions]
allowed_chats = ["-1001234567890", "@alice", "@bob"]
allow_send = false            # the default everywhere

[[permissions.profiles]]
chats = ["-1001234567890"]    # the company channel: read only
allow_download = false

[[permissions.profiles]]
chats = ["@alice"]
allow_send = true             # send freely here
allow_delete = "confirm"      # delete, but ask first
```

Rules:

- **Profiles never grant access to a chat.** `allowed_chats`, `denied_chats` and
  `default_policy` still decide which chats are reachable; a chat named only in
  a profile is still refused if the chat policy refuses it.
- **First match wins.** Profiles are tried in order and the first one listing
  the chat decides. A setting it leaves out falls back to the global value — it
  does not fall through to a later profile.
- A profile may set `allow_read`, `allow_send`, `allow_edit`, `allow_delete`,
  `allow_drafts` and `allow_download`, each `true`, `false` or `"confirm"`.
  `allow_search` and `allow_admin` are refused in a profile: search spans every
  chat, and no admin tool is scoped to one.
- `chats` uses the same identifiers as `allowed_chats`, but not `"*"`.

A profile is matched against the chat **Telegram confirms**, never against the
text the agent wrote, for the same reason a username never grants chat access
textually. When the profiles and the global setting would give an operation the
same answer, nothing is resolved; when they disagree, the identifier is resolved
once (served from Telethon's cache after the first time), and both the chat
policy and the profile are checked against the resolved peer. If resolution
fails, the call is refused.

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

## `[security.outbound]`

| Setting | Type | Default | Effect |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Enable outbound checks; `false` bypasses the entire outbound policy. |
| `block_credentials` | bool | `true` | Refuse text matching the audit scrubber's credential literals or shapes. |
| `max_message_chars` | int | `4096` | Maximum outgoing Python Unicode characters, before Telegram formatting; `0` disables this limit. |
| `block_bulk_quotes` | bool | `true` | Refuse long messages dominated by explicitly marked quoted or forwarded lines. |
| `bulk_quote_min_chars` | int | `2000` | Apply the quote heuristic only above this total character count; must be at least `1`. |
| `bulk_quote_ratio` | float | `0.9` | Minimum quoted fraction to refuse, from greater than `0` through `1`. |

The middleware checks `send_message.message` (including attachment captions) and
`set_draft.message` before any Telegram call. It also automatically checks every
`message` argument on guarded tools, including `edit_message`; a tool using a
different text parameter declares it with `outbound_text_arg` in `@guarded(...)`.
Text that passes is sent untouched. Refusals are never silent redactions.

Credential detection shares `CredentialScrubber` with the audit log: API hash
shapes (32 hexadecimal characters), Telethon StringSession shapes, session-file
name shapes, and environment values of at least six characters whose variable
name contains `api_hash`, `api_id`, `token`, `secret`, `password` or `session`.
Environment literals are captured when the runtime is built. Shapes are
heuristics: an ordinary checksum may also be refused. This is not detection of
all possible secrets, encoded credentials, private keys or seed phrases.

For bulk quotes, each line is stripped of surrounding whitespace. Lines starting
with `>` or, case-insensitively, `Forwarded from ` or `Forwarded message:` count
as quoted. The ratio is their total stripped character count divided by that of
all lines; blank lines do not dilute it. A lone forward header does not mark the
rest of a message. This conservative heuristic cannot prove another chat was
the source, and misses unmarked transcripts and paraphrases. Lowering the
thresholds increases false positives for legitimate quotations.

Failures return `outbound_policy_denied`, marked `retryable: false`, with a fixed
reason code (`credentials`, `max_length`, `bulk_quotes`, or `check_failed`) and a
fixed `hint` explaining that reason and naming the setting that relaxes it. They
identify this server's policy, not a Telegram failure, and never include rejected
text. If checking raises internally, the message is refused without exposing the
exception text. These settings are configured through TOML; no new environment
overrides are added.

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
| `max_download_bytes` | int | `209715200` | Ceiling on one downloaded attachment (200 MiB). `0` disables it. |
| `allowed_download_extensions` | list | `[]` | If set, only attachments with one of these extensions download, e.g. `["pdf", "png", "jpg"]`. |
| `block_executables` | bool | `true` | Refuse executables, by extension or by their first bytes. |
| `verify_file_type` | bool | `true` | Compare a file's magic bytes with its declared type and flag `attachment_type_mismatch`. |
| `scan_text_attachments` | bool | `true` | Run injection detection over the contents of text-like attachments. |
| `text_scan_max_bytes` | int | `262144` | How much of a text attachment is read for scanning. A longer file is classified at least `suspicious`. |

Paths are resolved through symlinks before being judged. The Telegram session
and state directory is always refused, even if an allowlist names it.

Downloaded files are saved under a name built from the message id and a UUID,
never from the sender's filename: that path is returned to the model and written
to disk, so it must not carry text a stranger chose. The original name is still
reported as `media.file_name`, with safety metadata.

### Downloaded attachments

`media_download` inspects what it fetches in two steps.

**Before transferring anything**, it refuses an attachment whose sender file name
or saved name has an executable extension (`.exe`, `.bat`, `.ps1`, `.sh`,
`.apk`, `.jar`, `.dmg`, `.js` and the rest of `EXECUTABLE_EXTENSIONS` in
`security/files.py`), an extension outside `allowed_download_extensions` when
that is set, or a reported size over `max_download_bytes`.

**After writing the file**, it reads the actual bytes, because a sender controls
the name, the declared type and for some media the reported size:

- a file larger than `max_download_bytes` is deleted and refused;
- a file whose first bytes are an executable header — Windows `MZ`, ELF,
  Mach-O, Java class, or a `#!` script — is deleted and refused, whatever its
  name says;
- the magic bytes are compared with the declared type, and a contradiction
  (a "PNG" that is a PDF) is reported as `attachment_type_mismatch`, classified
  `suspicious`. Container formats are allowed their contents: a zip may be a
  `.docx`, an MP4 container may hold audio;
- a file that is valid UTF-8 text is read up to `text_scan_max_bytes` and run
  through the injection detector. Under `flag` or `redact` the findings are
  attached to the result's `security` metadata and the file is left untouched;
  under `block`, content at or above `block_risk_threshold` is deleted and
  refused, which is `block` mode's meaning for a message too.

The result carries an `inspection` object: `size_bytes`, `declared_type`,
`detected_type`, `type_mismatch` and `text_scanned`. A refusal is an
`attachment_rejected` error, and if the file could not be deleted the error says
where it is. Detection is by magic bytes, not by parsing: a PDF or Office
document carrying an injection in its text is not opened, only identified.

### Sensitive paths

Denied by default — the full set, which is `SENSITIVE_FILE_GLOBS` in
`security/files.py`:

`.env`, `.env.*`, `*.env`, `id_rsa*`, `id_dsa*`, `id_ecdsa*`, `id_ed25519*`,
`*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.ppk`, `*.kdbx`, `*.keychain*`,
`*.session`, `*.session-journal`, `*.sqlite-wal`, `credentials`,
`credentials.*`, `secrets`, `secrets.*`, `.netrc`, `.pgpass`,
`.git-credentials`, `.npmrc`, `.pypirc`, `known_hosts`, `authorized_keys`,
`shadow`, `*_history`, `Cookies`, `Login Data` — and anything under `.ssh`,
`.aws`, `.gnupg`, `.gpg`, `.kube`, `.docker`, `.password-store`, `.mozilla`,
`Keychains`, `gcloud` or `gh`.

Note that `credentials` and `credentials.*` are two patterns rather than one
`credentials*`: the wildcard form would also deny an unrelated
`credentialsReport.csv`, and the policy is meant to be precise about what it
refuses rather than merely broad.

---

## `[rate_limit]`

| Setting | Type | Default | Effect |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | When `false`, disable token charges, pacing, cooldown admission gates and tool concurrency limits; FloodWait reporting/retry bounds remain active. Not recommended with an autonomous agent. |
| `persist_state` | bool | `true` | Save buckets and the global FloodWait cooldown to `<state dir>/rate-limit.json` and restore them at startup. `false` disables reads and writes, leaving any existing snapshot untouched. |
| `minimum_interval_ms` | int | `500` | Minimum gap between RPC admissions at `TelegramClient._call`. |
| `max_concurrent` | int | `2` | Tool/resolution operations in flight at once; RPCs never reacquire this semaphore. |
| `max_retries` | int | `2` | Retries after a flood wait, per tool call. |
| `max_flood_wait_seconds` | float | `60` | Longest wait the server will sit through. Beyond it, a structured `rate_limited` response is returned immediately. |
| `queue_timeout_seconds` | float | `120` | How long a call waits for a slot before reporting `rate_limited`. |
| `max_messages_per_call` | int | `200` | Ceiling on `get_messages(limit=…)` to bound response size and time holding a tool slot. |
| `max_messages_scanned` | int | `500` | Ceiling on messages *examined* by one read. Service and empty messages are skipped without counting toward `limit`, so a history full of them would otherwise page indefinitely even for `limit=1`. |

Snapshots are replaced atomically after token charges and FloodWait updates.
Buckets refill for elapsed wall-clock time across restarts, capped at current
capacity; expired cooldowns are discarded. Invalid or unreadable snapshots cause
a warning and fresh limits. Write failures warn and retain in-memory enforcement.
This protects sequential restarts, not multiple servers running simultaneously
against the same state directory.

`messages_per_token` was removed: old configurations containing it now fail
validation as an unknown key; remove that line. Argument-based `cost_from`
estimates are also removed. Each RPC sent through `_call` costs one token in the
active tool/resolution class. Calls outside middleware default to `read`.
A cached operation or simulated write with no RPC costs no tokens. List requests
are dispatched sequentially with one admission per member; Telegram RPC errors
retain Telethon's `MultiError` partial-result contract. Admission refusals stop
the batch.
Every internal retry and download chunk (including exported/CDN senders) takes
a fresh admission immediately before `sender.send`, preserving request identity.
The shared scheduler owns flood cooldowns instead of Telethon's local flood cache.
Connection/sign-in retain the task-local `unmetered()` exemption; agent traffic
cannot select it. Admissions inherit `RPC_CLASS` and never take the tool semaphore.
Transport retransmissions and protocol housekeeping below `sender.send` are not
separately metered. `flood_sleep_threshold=0` also applies to CDN clients.

`security_status.scheduler.in_flight` counts active tool/resolution admissions,
including their RPC waits, even when limiting is disabled. `dispatched` counts
RPCs admitted immediately before `sender.send`, including attempts that fail and
calls made with limiting disabled. `deferred` counts admission refusals (queue timeout or an
excessive cooldown), not every FloodWait retry exhaustion. `tokens_available`
is the remaining per-class budget, including refill; a token charged before a
gate cancellation/refusal remains spent conservatively.

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
`permission_denied`, `rate_limited`, `flood_wait`, `file_access_denied`,
`dry_run_write`, `confirmation_requested`, `confirmation_granted`,
`confirmation_denied`, `quarantine_released` and `attachment_rejected`.

### Reading the log

```bash
telegram-mcp-enhanced log                          # the 50 most recent events
telegram-mcp-enhanced log --since 1h --event injection_detected
telegram-mcp-enhanced log --since 2026-10-01 --limit 0 --json > events.jsonl
telegram-mcp-enhanced log --since 7d --summary     # counts by event, tool, rule
```

`log` reads `security.log` and its rotated backups (`security.log.1` …) in
chronological order, so nothing is missed at a rotation boundary. `--since`
takes a duration (`90s`, `30m`, `6h`, `2d`, `1w`) or an ISO 8601 time, read as
UTC if it has no zone. `--event` can be repeated. `--limit` keeps the most
recent N matches; `0` keeps all. `--json` prints one JSON object per line —
the stored records unchanged — for SIEM ingestion, and with `--summary` prints
the summary as one JSON object. Lines that are not valid JSON (a write torn by a
crash) are skipped and counted on stderr. The command only reads.

---

## `[session]`

| Setting | Type | Default | Effect |
| --- | --- | --- | --- |
| `storage` | `file` \| `keyring` | `file` | Where the Telegram login is kept. |
| `keyring_service` | string | `telegram-mcp-enhanced` | Keyring service name used with `storage = "keyring"`. |
| `keyring_username` | string | `session` | Keyring account name used with `storage = "keyring"`. |

The session is a bearer credential for the whole account. With `file` storage
it is upstream's SQLite database in the state directory; the server now makes
that directory owner-only (`0700`) and the session and its SQLite companion
files owner-only (`0600`) whenever it creates, connects or signs in, since
upstream left them at the process umask — usually readable by every local
account. On a filesystem without POSIX permissions this is logged, not fatal.

With `keyring` storage the login is a Telethon `StringSession` held in the
operating system's credential store — Keychain on macOS, the Secret Service on
Linux, Credential Locker on Windows — and no session file is written. It needs
the optional extra:

```bash
pip install "telegram-mcp-enhanced[keyring]"
telegram-mcp-enhanced migrate-session --delete-file   # copy the file login over
```

then set `storage = "keyring"`. `migrate-session` copies the login, reads it
back from the keyring to confirm it was kept, and only then (with
`--delete-file`) removes the SQLite file and its companions. A `StringSession`
holds no entity cache, so the first few calls after switching may resolve chats
again. The session is written back to the keyring on shutdown, so a data-centre
migration is not lost. `clear-session` removes the keyring entry too.

A keyring protects the credential at rest from other users and from tools that
read files. It does not protect it from code running as you, which can ask the
keyring just as this server does.

---

## Top level

| Setting | Type | Default | Effect |
| --- | --- | --- | --- |
| `log_level` | `DEBUG` … `CRITICAL` | `INFO` | Diagnostic logging on stderr. `DEBUG` includes Telethon protocol detail, which can contain message content, and these messages do **not** pass through the security log's credential scrubber. Whatever launched the server decides whether they are kept — see [PRIVACY.md](../PRIVACY.md). |
| `dry_run` | bool | `false` | Run every check, then stop short of changing anything on Telegram. |

### `dry_run`

Sending, editing, deleting and drafting are simulated. Everything before the
Telegram call is real: chat authorization including the resolution round trip,
operation permissions, file and outbound checks and the tool scheduler all
run. Only real RPCs (including resolution) consume tokens and pacing; a
simulated write consumes neither. Excessive cooldowns still refuse admission. That is what makes a dry run informative — it tests the policy you
actually have, not a bypass around it.

The tool returns a string beginning `DRY RUN — nothing was sent`, describing the
write by shape (character counts, file and message-id counts) and never by
content, and instructing the model to tell the user nothing happened. The same
description is written to the security log as a `dry_run_write` event.

Reads and searches are **not** simulated. They still reach Telegram and return
real data, because an agent exercised against nothing tells you nothing about
how it behaves against your actual chats. `get_draft` is a read too, even though
it is charged against the write budget because it shares the drafts permission.

`get_messages(mark_as_read=True)` is refused, because acknowledging messages
changes unread state on Telegram. The read itself is fine — the error names the
option and tells the model to retry with `mark_as_read=false`. Whether an
operation mutates is declared per tool rather than inferred from its
rate-limiting class, which is a traffic budget and gets this wrong in both
directions.

`media_download` is refused, not simulated, with a `dry_run_unsupported` error:
its result is the file it wrote, so a simulated one would have to invent a path
and media metadata — and an operator who enabled `dry_run` to stop the agent
touching anything would least expect it to keep writing files.

A write whose permission is `"confirm"` is simulated without asking, and the
simulated result says it would have needed confirmation. A read that would need
confirmation — including `get_quarantined_message` — is refused, because it
would be real.

Dry run is a testing aid, not a security control. It is a single boolean the
operator sets; it does not restrict which chats are reachable and it stops no
reads. Use `[permissions]` for that.

---

## Environment variables

Each overrides the corresponding file setting.

| Variable | Sets |
| --- | --- |
| `TELEGRAM_MCP_CONFIG` | path to the config file |
| `TELEGRAM_MCP_LOG_LEVEL` | `log_level` |
| `TELEGRAM_MCP_DRY_RUN` | `dry_run` |
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

Booleans accept `1/0`, `true/false`, `yes/no`, `on/off`; the `allow_*`
variables also accept `confirm`. An unparseable value is a fatal error, not a
silent fallback. Profiles and the `[session]` table are set in the file only.

---

## Configuration presets

Choose a complete, commented starting policy before connecting a model:

```bash
telegram-mcp-enhanced init-config --preset read-only
telegram-mcp-enhanced init-config --preset assistant
telegram-mcp-enhanced init-config --preset locked-down --path custom.toml --force
```

`--path` chooses the output file; `--force` replaces an existing file. Without
`--force`, an existing file is left untouched. Without `--preset`, the original
starter template and its defaults are unchanged. To use a custom path, set
`TELEGRAM_MCP_CONFIG` to that file when starting the server.

| Setting | `read-only` | `assistant` | `locked-down` |
| --- | --- | --- | --- |
| `allow_read` | `true` | `true` | `true` |
| `allow_search` | `true` | `true` | `true` |
| `allow_send` | `false` | `false` | `false` |
| `allow_edit` | `false` | `false` | `false` |
| `allow_delete` | `false` | `false` | `false` |
| `allow_drafts` | `false` | `true` | `false` |
| `allow_download` | `true` | `true` | `false` |
| `allow_admin` | `false` | `false` | `false` |
| Chat access default | Allow every chat | Allow every chat | Deny every chat |
| Injection `mode` | `flag` | `flag` | `block` |
| `block_risk_threshold` | `high_risk` | `high_risk` | `high_risk` |
| `minimum_interval_ms` | `500` | `500` | `1000` |
| `max_concurrent` | `2` | `2` | `1` |

**read-only** permits reading, searching and downloading across every chat.
It cannot send, edit or delete messages, or manage drafts. Downloads still write
files to local disk. Add `allowed_chats` to limit which chats it can read.

**assistant** also enables drafts, so the agent can prepare a message for a
human to review and send in Telegram. It never sends on its own in this preset.
Sending, editing and deleting require deliberate permission changes by the
operator. Add `allowed_chats` to limit its reach.

**locked-down** sets `default_policy = "deny"` and leaves `allowed_chats` as a
commented-out placeholder. It grants access to no chats until you uncomment
that line and replace the example with your chat IDs. After that, only reading
and searching in those chats are permitted. High-risk injection content is
withheld, downloads are disabled, and tool operations run one at a time, with
RPC admissions at least 1000 ms apart.

All other settings retain their built-in defaults, including enabled scanning,
rate limiting, persisted rate-limit state and security logging without message
content. Environment variables still override the file; run
`telegram-mcp-enhanced security` to check the effective policy.


## Explaining a detection

Run `telegram-mcp-enhanced explain "text"` or
`telegram-mcp-enhanced explain --file message.txt` (UTF-8; choose one input).
The command reports classification, risk level, matched spans with context,
scanning truncation and span-budget exhaustion, and previews flag/redact/block
under the current settings, including disabled/custom rules and block threshold.
There is no numeric risk score; risk is a coarse level. Disabled scanning is
reported explicitly. Input is displayed locally and never written to the audit
log, even when message-content logging is enabled.

`tool_surface_canary` fires on an exact MCP tool identifier — `send_message`,
`get_messages`, `security_status` and the rest — without requiring a call.
Nobody writes those underscored names in a chat message by accident, so it is a
high-signal, near-zero-false-positive rule; ordinary English such as "send
message" does not match it. A parenthesised call is left to
`tool_name_invocation` so the two do not duplicate each other.

It is the one rule that reads a view where `_` survives, because the whole
signal is the underscore. Homoglyphs and invisible characters are still folded
for it, so `sеnd_message` written with a Cyrillic `е` is caught like any other
evasion. Technical discussion quoting these identifiers will be flagged too:
this is a signal, not proof.
When the span budget is exhausted, explain recovers one example for each omitted
rule; mode previews still use the original budget-limited result.

The canary alone scans literal text, preserving underscores that the shared
normalization converts to spaces; it does not detect obfuscated identifiers.
