# Connecting a client

## How compatibility actually works

MCP is a **client** protocol. A model does not "support MCP" — the application
hosting the model does. So the question is never "does Claude/GPT/Qwen work with
this?" but "does the app I am running it in spawn local MCP servers?"

Two facts decide everything below:

1. **This is a local stdio server.** It runs as a subprocess on your machine and
   speaks MCP over standard input and output. It does not listen on a port and
   has no HTTP endpoint.
2. **Every client gets the same enforcement.** Permissions, chat access control,
   the file policy, the outbound policy, the rate limiter and the content gateway
   live in the server. A client that behaves badly, or a weaker model that
   follows instructions poorly, cannot widen what it is allowed to do. That is
   the point of the design — see [SECURITY.md](../SECURITY.md).

| Client | Works | Transport |
| --- | --- | --- |
| Claude Desktop / Claude Code | ✅ directly | stdio |
| **OpenAI Codex CLI** | ✅ directly | stdio |
| Qwen Code CLI | ✅ directly | stdio |
| Grok CLI | ✅ directly | stdio |
| Cursor / Cline / Continue / VS Code agent mode | ✅ directly | stdio |
| ChatGPT (web and desktop) | ⚠️ not directly | remote HTTPS only |

Anything in the "directly" rows can run whichever model it supports — so GPT,
DeepSeek, Kimi or a local Llama all reach this server fine through a client that
speaks stdio, even where that vendor's own first-party app does not.

---

## OpenAI Codex CLI

**Verified working. No API key required** — Codex authenticates with your
ChatGPT account, and the Telegram credentials below are your own Telegram API
credentials, not an OpenAI key.

Check you are signed in with a ChatGPT account rather than an API key:

```bash
codex login status     # -> "Logged in using ChatGPT"
```

Add the server:

```bash
codex mcp add telegram \
  --env API_ID=<your_api_id> \
  --env API_HASH=<your_api_hash> \
  -- telegram-mcp-enhanced start
```

Confirm it registered, then check it from inside Codex:

```bash
codex mcp list
codex mcp get telegram
```

That writes a block to `~/.codex/config.toml`, which you can also edit directly:

```toml
[mcp_servers.telegram]
command = "telegram-mcp-enhanced"
args = ["start"]
startup_timeout_sec = 30

[mcp_servers.telegram.env]
API_ID = "<your_api_id>"
API_HASH = "<your_api_hash>"
```

### Things worth knowing

- **Use the full path if Codex cannot find the command.** `which
  telegram-mcp-enhanced` — a `uv tool install` typically puts it in
  `~/.local/bin`, which a GUI-launched process may not have on its `PATH`.
- **Startup takes a couple of seconds**, because the server connects to Telegram
  during its lifespan. Measured at 1–3 seconds on a normal connection. Codex's
  default startup timeout is comfortably above that, but if you are on a slow or
  filtered network, raise `startup_timeout_sec`.
- **Credentials in `config.toml` sit on disk in plaintext.** That file is
  readable by anything running as you. If you would rather not put them there,
  leave the `env` block out and export `API_ID` and `API_HASH` in the shell you
  launch `codex` from — Codex passes its own environment down to stdio servers.
- **`codex mcp logout` / `login` are for OAuth-protected remote servers.** They
  do not apply here; this server's authentication is your Telegram session.
- **Diagnostics go to stderr.** Codex captures it. Keep the default `INFO` level:
  at `DEBUG`, Telethon logs message content, and it would land in Codex's logs.
  [PRIVACY.md](../PRIVACY.md) covers this.

Remove it again with:

```bash
codex mcp remove telegram
```

---

## Claude Desktop, Claude Code, Cursor, Cline, Continue

All of these read the same JSON shape. Put it in the client's MCP configuration
file:

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

For Claude Code you can skip the file:

```bash
claude mcp add telegram --env API_ID=<id> --env API_HASH=<hash> \
  -- telegram-mcp-enhanced start
```

Cursor, Cline, Continue and VS Code agent mode let you choose the backing model,
so this is the route to using **GPT or DeepSeek** with this server.

---

## Qwen Code CLI

Qwen Code supports stdio, SSE and streamable HTTP. Use the stdio form:

```bash
qwen mcp add telegram \
  --env API_ID=<your_api_id> \
  --env API_HASH=<your_api_hash> \
  -- telegram-mcp-enhanced start
```

---

## Grok CLI

```bash
grok mcp add telegram -- telegram-mcp-enhanced start
```

Export `API_ID` and `API_HASH` in the launching shell if the CLI's version does
not take `--env`. If it starts but will not connect, Grok writes the server's
stderr to `~/.grok/logs/mcp/telegram.stderr.log`, which is the first place to
look.

Note that xAI's **API-side** remote MCP tools accept HTTP and SSE only; that is a
different feature from the CLI's local server support, and this server does not
apply to it.

---

## ChatGPT (web and desktop)

**Not directly compatible.** ChatGPT's Developer Mode connectors accept only
remote MCP servers at a public HTTPS URL speaking SSE or streamable HTTP. There
is no stdio option, so ChatGPT cannot spawn a server on your laptop. Developer
Mode also requires a paid plan.

Three ways to use GPT with this server anyway, best first:

1. **Use the Codex CLI** (above). Same OpenAI account, no API key, works today.
2. **Use a stdio client and pick a GPT model** — Cursor, Cline, Continue.
3. **Put it behind HTTPS yourself.** Technically possible and **not
   recommended**: it would expose a server that can read and send your Telegram
   messages to the public internet, and this project has no authentication layer
   of its own because it was never designed to be reachable remotely. If you do
   it anyway, the exposure is yours — see [DISCLAIMER.md](../DISCLAIMER.md).

---

## After connecting, before trusting

```bash
telegram-mcp-enhanced security      # what the server will actually enforce
```

Without a config file the defaults permit reading, searching, sending and drafts
across **every chat on the account**. Write a policy first:

```bash
telegram-mcp-enhanced init-config --preset assistant
```

Then set `dry_run = true` and exercise the agent once. Every check runs and the
writes are simulated, so you can see what it would have done before it can do
it. Note what that does *not* cover: the chat is still resolved against
Telegram, and reads are still real, so the agent genuinely reads your messages
during a dry run. It stops the agent changing anything; it does not stop it
seeing anything.

[docs/CONFIGURATION.md](CONFIGURATION.md) has the full reference.
