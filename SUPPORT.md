# Support

**Set expectations first: this is an unpaid, single-maintainer open-source
project.** There is no service-level agreement, no guaranteed response time and
no commercial support. Issues are read and answered when there is time. See
[DISCLAIMER.md](DISCLAIMER.md) — nothing here is owed to you.

That said, a good report gets a much better answer than a bad one, so here is
how to write one.

## Before opening anything

Work through these first; they resolve most reports.

```bash
telegram-mcp-enhanced security      # what the server is actually enforcing
telegram-mcp-enhanced paths         # every location it reads or writes
telegram-mcp-enhanced version       # what you are running
```

- **"The agent says it is not permitted."** That is usually correct behaviour.
  `edit`, `delete` and admin operations are **off by default**, and a chat
  allowlist denies everything it does not name. `security` prints the policy in
  force.
- **"It refuses to send my message."** The outbound content policy refuses
  credential-shaped text, messages over 4096 characters, and heavily quoted bulk
  text. The refusal names which check fired. See
  [docs/CONFIGURATION.md](docs/CONFIGURATION.md#securityoutbound).
- **"It says rate limited."** Telegram asked for a wait, and the server is
  honouring it across every queued operation. That is the feature working.
  `max_flood_wait_seconds` controls when it reports rather than waits.
- **"My client cannot find the command."** Use the full path from `which
  telegram-mcp-enhanced`. See [docs/CLIENTS.md](docs/CLIENTS.md).
- **"It will not start."** A malformed config **stops the server on purpose**
  rather than running with defaults you did not choose. The error names the key.
- **"An ordinary message was flagged as an injection."** Probably a known false
  positive. `telegram-mcp-enhanced explain "<text>"` shows which rule fired, and
  [docs/DETECTION.md](docs/DETECTION.md) lists the cases the detector is known to
  get wrong.

## Where to go

| What you have | Where |
| --- | --- |
| A bug | [Open a bug report](../../issues/new?template=bug_report.yml) |
| A message the detector got wrong, either way | [Open a detection report](../../issues/new?template=detection_report.yml) |
| **A security vulnerability** | **Not an issue** — use the private route in [SECURITY.md](SECURITY.md) |
| A question about configuration | Read [docs/CONFIGURATION.md](docs/CONFIGURATION.md) first, then open an issue |
| A feature idea | Check [docs/ROADMAP.md](docs/ROADMAP.md) — it may already be ranked, with reasoning |
| Something in the Telegram/MCP foundation | Upstream: [dryeab/mcp-telegram](https://github.com/dryeab/mcp-telegram) |
| Wanting to contribute | [CONTRIBUTING.md](CONTRIBUTING.md) |

## What makes a report actionable

Include:

- the output of `telegram-mcp-enhanced version` and `security`;
- your MCP client and which model;
- your Python version and operating system;
- what you expected, and what happened;
- the smallest reproduction you can manage.

**Never paste** your `API_ID`, `API_HASH`, session file or its contents, or a
whole security log. The log excludes message content by default, but it is still
about your account. Redact chat IDs and usernames unless they matter.

`dry_run = true` helps, but **it is not an offline mode.** It suppresses the
final write -- sends, edits, deletions and drafts -- and nothing else. Chat
authorisation still resolves the chat against Telegram, and reads are still
real: `get_messages` fetches live messages and hands them to your model. Use it
to reproduce a *refusal* safely; do not use it expecting no traffic and no
exposure. The test suite is the genuinely offline route, since every test runs
against a fake client.

## What is out of scope

- **Getting a Telegram account unbanned.** Only Telegram can do that. See
  [DISCLAIMER.md](DISCLAIMER.md) section 6.
- **Help using this for spam, scraping or surveillance.** See the acceptable-use
  policy in [DISCLAIMER.md](DISCLAIMER.md) section 5.
- **Legal or compliance advice** about your deployment.
- **Making the detector catch everything.** It cannot, by construction, which is
  why permissions and chat access control exist.
