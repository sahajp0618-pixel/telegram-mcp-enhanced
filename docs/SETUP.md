# Setup guide

A step-by-step walkthrough for installing Telegram MCP Enhanced, connecting it
to your own Telegram account, and choosing a security policy before you let an
AI assistant near it.

## Contents

- [What you are about to connect](#what-you-are-about-to-connect)
- [Prerequisites](#prerequisites)
- [Install it](#install-it)
- [Get Telegram API credentials](#get-telegram-api-credentials)
- [Log in](#log-in)
- [Write a security policy before connecting a model](#write-a-security-policy-before-connecting-a-model)
- [Connect a client](#connect-a-client)
- [Try dry run first](#try-dry-run-first)
- [Where your data lives](#where-your-data-lives)
- [Troubleshooting](#troubleshooting)

## What you are about to connect

Telegram MCP Enhanced is a local server that lets an AI assistant — Claude,
GPT, or anything else that speaks the
[Model Context Protocol](https://modelcontextprotocol.io/introduction) — read
and act on your personal Telegram account: read messages, search your chats,
send messages, and manage drafts, within whatever limits you configure.

Be clear-eyed about that before continuing: once this is connected, an AI
assistant can read your Telegram messages and, if you allow it, send them. The
rest of this guide is about installing the software and choosing those limits
deliberately, rather than accepting what it does by default. Read
[why this project exists](../README.md#why-this-exists) and
[DISCLAIMER.md](../DISCLAIMER.md) before you point it at an account you care
about.

## Prerequisites

- Python 3.10 or newer.
- [`uv`](https://github.com/astral-sh/uv) (recommended) or `pip`.

## Install it

```bash
uv tool install git+https://github.com/sahajp0618-pixel/telegram-mcp-enhanced
```

or, with pip:

```bash
pip install git+https://github.com/sahajp0618-pixel/telegram-mcp-enhanced
```

Either way, this installs two equivalent commands: `telegram-mcp-enhanced` and
`mcp-telegram` (the second matches the name existing MCP client configuration
may already expect). This guide uses `telegram-mcp-enhanced`; the two are
interchangeable.

> [!IMPORTANT]
> Read [DISCLAIMER.md](../DISCLAIMER.md) before going further. Automating a
> personal account can get it limited or banned — that is Telegram's decision,
> not this software's, and no setting described below prevents it. Do not
> point this at an account you cannot afford to lose.

## Get Telegram API credentials

This is the step most people get stuck on, so take it slowly. You need an
`api_id` and an `api_hash` — a pair of values that identify an *application* to
Telegram's API. Every Telegram client has a pair like this; you are about to
get your own.

1. Go to [my.telegram.org](https://my.telegram.org) in a browser.
2. Log in with your **phone number**, in international format (for example
   `+1234567890`). There is no username or password on this site: Telegram
   sends a login code to your Telegram app, and you type that in.
3. Once logged in, choose **API development tools**.
4. If you have not created an application before, you land on a
   **Create new application** form. If you have, the page shows your existing
   `api_id` and `api_hash` directly and you can skip to step 6. Otherwise, fill
   in the form:
   - **App title** — any name; it is shown only to you.
   - **Short name** — alphanumeric, 5 to 32 characters.
   - **URL** — can be left blank.
   - **Platform** — choose **Other**. This is a desktop command-line tool, not
     a phone or web app.
   - **Description** — optional.
5. Submit the form.
6. The page now shows two values: `api_id` (a short number) and `api_hash` (a
   32-character string). **Save both somewhere safe now** — a password manager
   is a good choice. You can return to this same page later to see them again,
   but that means repeating the phone-number login from step 2, so saving them
   now is easier than retrieving them later.

Two things worth being explicit about, because the names invite confusion:

- **`api_id` and `api_hash` are not your Telegram username and password.**
  They identify the application, not you. Your own login — phone number, the
  code Telegram sends you, and a two-factor password if you have set one —
  happens separately, in [Log in](#log-in) below.
- **Keep `api_hash` private.** Do not paste it into a chat, a GitHub issue, a
  screenshot, or a support request — treat it like a password.
  [Where your data lives](#where-your-data-lives) covers where it ends up on
  your own machine.

> [!WARNING]
> Never share your `api_hash`. Anyone who has it together with your `api_id`
> can impersonate this application, and combined with your session file they
> can act as your Telegram account entirely. If you ever paste one somewhere
> by mistake, treat it as compromised.

## Log in

```bash
telegram-mcp-enhanced login
```

This prompts you for, in order: your API ID, your API hash, your phone number
(international format), the verification code Telegram sends you, and your
two-factor password if your account has one set. The API ID, API hash, and
two-factor password prompts are masked as you type; the phone number and code
are not.

On success, the session is saved locally so you do not log in again on every
run — by default at `~/.local/state/mcp-telegram/session.session`. See
[Where your data lives](#where-your-data-lives) for what that file contains
and how to remove it.

`telegram-mcp-enhanced logout` prints the steps to end the session from inside
the Telegram app itself (Settings → Privacy and Security → Active Sessions);
running it does not change anything on this machine. To remove the local
session file, see `clear-session` later in this guide.

## Write a security policy before connecting a model

Do this before you connect any AI client, not after.

> [!IMPORTANT]
> **Without a configuration file, the server runs on its built-in defaults,
> which allow reading, searching, sending, and drafts across every chat on the
> account.** The `security` command below will say so plainly if you run it
> before writing one.

Write a starting policy:

```bash
telegram-mcp-enhanced init-config
```

This writes a complete, commented configuration file to the standard location
(`~/.config/mcp-telegram/config.toml` by default). Three presets are also
available as complete starting points:

```bash
telegram-mcp-enhanced init-config --preset read-only
telegram-mcp-enhanced init-config --preset assistant
telegram-mcp-enhanced init-config --preset locked-down
```

- **`read-only`** — can read, search and download; cannot send, edit, delete
  or draft. Every chat is reachable until you add `allowed_chats`.
- **`assistant`** — the same, plus drafts: the agent can prepare a message for
  you to review and send yourself in Telegram. It never sends on its own.
- **`locked-down`** — denies every chat until you edit the file and list which
  ones it may reach; even then, only reading and searching are permitted.

`--path` writes to a location other than the default; `--force` overwrites a
file that already exists (without it, an existing file is left alone).
Omitting `--preset` writes the original starter template instead of one of the
three above. The full breakdown of exactly what each preset sets is in
[docs/CONFIGURATION.md](CONFIGURATION.md#configuration-presets).

Whichever you start from, set `allowed_chats` to the chats you actually want
reachable — once it is non-empty, everything not listed is denied.

Then check what the server will actually enforce:

```bash
telegram-mcp-enhanced security
```

This prints which config file is in use, every operation permission (read,
search, send, edit, delete, drafts, download, admin), chat access control,
injection detection settings and rate limiting — and warns you explicitly if
the server can still reach every chat on the account.

Every setting, its default, and every environment variable that can override
it, is in [docs/CONFIGURATION.md](CONFIGURATION.md).

## Connect a client

MCP is a client protocol: what matters is whether the AI application you use
can start a local process, not which model is behind it.
[docs/CLIENTS.md](CLIENTS.md) covers setup for Claude Desktop, Claude Code,
Codex CLI, the ChatGPT desktop app, Qwen Code, Grok CLI, Cursor, Cline and
Continue — and explains why ChatGPT on the web is the one common surface that
cannot reach this server at all.

Every client needs the same two things: the command to run, and your two
credentials as environment variables. The JSON shape most clients (Claude
Desktop, Claude Code, Cursor, Cline, Continue) use is:

```json
{
  "mcpServers": {
    "telegram": {
      "command": "telegram-mcp-enhanced",
      "args": ["start"],
      "env": {
        "API_ID": "<your_api_id>",
        "API_HASH": "<your_api_hash>"
      }
    }
  }
}
```

If your client cannot find the command, use its full path — run `which
telegram-mcp-enhanced` to get it (a `uv tool install` typically places it
under `~/.local/bin`, which a GUI-launched application does not always have on
its `PATH`).

See [docs/CLIENTS.md](CLIENTS.md) for client-specific commands, and for how to
keep `API_ID`/`API_HASH` out of a plaintext config file where your client
supports it.

## Try dry run first

Before you trust a new setup — a new client, a new model, or a config you just
changed — turn on dry run. In your config file:

```toml
dry_run = true
```

or, equivalently, `TELEGRAM_MCP_DRY_RUN=true` in the environment. Then use the
assistant as you normally would.

Be precise about what this does and does not do. Every check still runs in
full — chat access, permissions, the file policy, the outbound content
policy, rate limiting — and only the final write is simulated: sends, edits,
deletions and drafts return a description of what *would* have happened,
starting `DRY RUN — nothing was sent`, instead of reaching Telegram.

What it does **not** do:

- **It is not an offline mode.** If the agent resolves a chat by username,
  that lookup still contacts Telegram.
- **Reads and searches are real.** `get_messages` and `search_dialogs` return
  your actual messages and chats, unsimulated. A dry run tests the agent
  against real data; it stops the agent from changing anything, not from
  seeing anything.
- **Downloads are refused, not simulated** — `media_download` returns a
  `dry_run_unsupported` error rather than pretending to write a file, since a
  download's entire result is the file itself.
- **`get_messages(mark_as_read=True)` is refused too**, since marking messages
  read is itself a change on Telegram; retry with `mark_as_read=false`.

Use it to see what a new policy or a new agent would do before it can do
anything — not as a way to test with no exposure at all. The full behaviour is
under [`dry_run` in docs/CONFIGURATION.md](CONFIGURATION.md#dry_run).

## Where your data lives

```bash
telegram-mcp-enhanced paths
```

prints every location the server actually reads or writes on your machine.
Use this rather than guessing: by default, your session lives under
`~/.local/state/mcp-telegram/`, downloaded media under
`~/.local/state/mcp-telegram/downloads/`, the security log at
`~/.local/state/mcp-telegram/security.log`, and your configuration at
`~/.config/mcp-telegram/config.toml` — but each of these can be moved, and
`paths` reports where they actually are.

The session file is worth understanding before you decide how to handle it:
beyond your login, it is a database that accumulates other people's
usernames, phone numbers and display names as your account interacts with
them. To remove it:

```bash
telegram-mcp-enhanced clear-session
```

This deletes the session file and any leftover companion files — which a
server that was killed rather than shut down cleanly can leave behind, and
which can hold cached contact data of their own.

Deleting local files does not delete your messages from Telegram, and does
not reach anything your AI client or its model provider separately retained.
[PRIVACY.md](../PRIVACY.md) is the full picture — what each file contains,
what reaches the model, and exactly what local deletion does and does not
cover.

## Troubleshooting

**"Command not found," or your client cannot start the server.** It cannot
find `telegram-mcp-enhanced` on its `PATH` — common for GUI-launched apps,
which do not always inherit your shell's environment. Run `which
telegram-mcp-enhanced` and use the full path it prints instead of the bare
command.

**The assistant says something is "not permitted."** This is usually the
policy working as intended, not a bug. `edit_message`, `delete_message` and
administrative operations are denied by default, and once `allowed_chats` is
set, anything not on that list is denied too. Run `telegram-mcp-enhanced
security` and check it matches what you meant to configure.

**"Rate limited."** Telegram asked for a wait, and the server is honouring it
across every queued operation rather than continuing to send requests until
Telegram restricts the account. This is the reliability layer working as
designed, not a failure — `max_flood_wait_seconds` controls how long it waits
before reporting back instead of continuing to hold the request.

**A send was refused.** The outbound content policy checks message text
before anything reaches Telegram, and refuses credential-shaped text,
over-length messages, and heavily quoted bulk text. The refusal names which
check fired; see [`[security.outbound]`](CONFIGURATION.md#securityoutbound)
for what each one does and how to relax it.

**The server will not start, or reports the configuration is invalid.** A
config file that cannot be parsed, has an unknown key, or contains an invalid
pattern stops the server on purpose, rather than quietly starting with
defaults you did not choose. The error names the key at fault — fix or remove
it and try again.

Anything else — including how to write a report that is actually actionable,
and what to do about a message wrongly flagged as an injection — is covered
in [SUPPORT.md](../SUPPORT.md).

---

Related reading: [README.md](../README.md) for the full feature list,
[SECURITY.md](../SECURITY.md) for the threat model behind these defaults,
[PRIVACY.md](../PRIVACY.md) for what is stored and where,
[DISCLAIMER.md](../DISCLAIMER.md) for the terms of using this at all, and
[SUPPORT.md](../SUPPORT.md) if something goes wrong that this guide does not
cover.
