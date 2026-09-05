# Privacy Policy

**Last updated:** 5 September 2026
**Applies to:** Telegram MCP Enhanced, the software in this repository.

## The short version

This is software you download and run yourself. It is not a service.

- The maintainers operate no servers and **receive no data from you** — not your
  messages, not your credentials, not usage statistics, not crash reports.
- There is **no telemetry, no analytics and no phone-home** of any kind.
- Everything the software stores stays on your own machine.
- The only network destination it contacts is **Telegram**, using credentials
  you supply, on your behalf — exactly as any Telegram client does.

If you run this, **you** decide what data it touches and you are responsible for
that. The maintainers cannot see it, cannot retrieve it, and are not responsible
for it.

## 1. Who is who

| Role | Who | Responsibility |
| --- | --- | --- |
| **Maintainers** | The authors of this repository | Publish source code. Operate nothing, receive nothing, store nothing. |
| **Operator** | You, running the software | Control all data it touches, and are the data controller for it under any applicable law. |
| **Third party** | Telegram (Telegram FZ-LLC / Telegram Messenger Inc.) | Provide the messaging service. Their own privacy policy governs your account and messages. |

Because the maintainers never receive your data, there is no maintainer-side
collection, sharing, sale, transfer or retention to describe. This policy exists
to tell you what the software does on **your** machine, so you can meet your own
obligations.

## 2. What the software processes

Running it, the software reads and processes:

- **Telegram messages and metadata** you ask it to retrieve — text, sender IDs,
  timestamps, chat titles, usernames, attachment names and MIME types.
- **Your Telegram API credentials** (`API_ID`, `API_HASH`), supplied by you
  through environment variables, and the Telethon session created from them.
- **Local file paths** you ask it to send, and the media it downloads.
- **Its own configuration.**

All of this is processed in memory on your machine, and none of it is
transmitted anywhere except to Telegram in the course of the request you asked
for.

## 3. What is stored on your machine, and where

The software writes only to these locations. Paths follow the XDG base directory
specification and may differ if you set `XDG_STATE_HOME` or `XDG_CONFIG_HOME`.

| What | Where | Contains | Written when |
| --- | --- | --- | --- |
| Telethon session | `~/.local/state/mcp-telegram/session.session` | Authentication material for your Telegram account | You log in |
| Downloaded media | `~/.local/state/mcp-telegram/downloads/` | Files you asked to download | You call `media_download` without a path |
| Security log | `~/.local/state/mcp-telegram/security.log` | Security events — see section 4 | A security event occurs, if logging is enabled |
| Configuration | `~/.config/mcp-telegram/config.toml` | Your policy settings | You create it |

Nothing else is written. Messages are **not** cached, mirrored or persisted by
this software: they are read from Telegram, returned to your MCP client, and
forgotten. (Your MCP client and the model behind it are separate systems with
their own retention behaviour — see section 6.)

### Treat the session file as a credential

`session.session` can be used to act as your Telegram account. Protect it as you
would a password. The software refuses to upload anything from its own state
directory for exactly this reason, but it cannot protect the file from anything
else on your machine.

## 4. The security log

Disabled by setting `enabled = false` under `[security.logging]`.

**It records:** a timestamp, the event type, which tool ran, the chat and message
IDs involved, the risk classification, which detection rules matched, and what
action was taken.

**It does not record message content.** Content is only ever written if you
explicitly set `include_message_content = true`, and even then it is truncated
to 200 characters.

**Credentials are removed** from every field before writing, both by literal
value and by shape — a 32-character hex string or a Telethon session string is
replaced with `[redacted]` wherever it appears, including inside error messages.

The log rotates at 1 MB, keeping three files by default. Delete it whenever you
like; nothing depends on it.

## 5. What leaves your machine

**Telegram, and nothing else.** The connection is made by
[Telethon](https://github.com/LonamiWebs/Telethon) over Telegram's MTProto
protocol using your credentials. What you send and read is governed by
[Telegram's privacy policy](https://telegram.org/privacy) and terms.

Specifically, this software makes **no** other outbound connection. Its security
analysis — prompt-injection detection, classification, redaction — runs entirely
locally, with no API call and no model inference. No content is sent to any
third-party service for scanning, and there is no mechanism in the code to do
so.

## 6. Systems this software talks to but does not control

Two of them, and this is the part people most often overlook:

- **Your MCP client and its model.** The whole point of this software is to hand
  Telegram content to an AI client. Whatever that client is — a desktop app, an
  IDE, your own agent — it receives message content, and *its* provider's
  retention and training policies then apply. This software cannot control or
  see that. If your chats are sensitive, the model provider's policy matters as
  much as this one.
- **Telegram**, as above.

Restricting what reaches the model is precisely what the permission settings and
chat allowlist are for. Use them.

## 7. Other people's data

Telegram conversations involve people who did not choose to run this software.
When you point an AI client at your account, you are processing their messages
too.

That is your decision and your responsibility. Depending on where you and they
are, you may have obligations under laws such as the GDPR or the CCPA — for
example if you use this for anything beyond a purely personal or household
activity. The maintainers are not a party to that processing and cannot advise
on it.

## 8. Deleting everything

```bash
telegram-mcp-enhanced logout          # how to end the Telegram-side session
telegram-mcp-enhanced clear-session   # delete the local session file
rm -rf ~/.local/state/mcp-telegram    # session, downloads and security log
rm -rf ~/.config/mcp-telegram         # configuration
```

That removes everything this software has stored. There is nothing held
anywhere else, because there is nowhere else.

## 9. No warranty and no liability

This software is provided under the MIT License. That disclaimer applies in full
and is repeated here because it matters:

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
> CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
> OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
> OR OTHER DEALINGS IN THE SOFTWARE.

In particular, and without limiting the above, the maintainers are not
responsible for:

- how you use the software, or what you use it for;
- any consequence of connecting an AI system to a Telegram account, including
  messages sent, edited or deleted by a model;
- action taken against your Telegram account, including restriction or
  termination, whether or not related to Telegram's terms of service;
- data disclosed to your MCP client, its model provider, or any other system you
  connect;
- the security defences failing to detect or prevent an attack. They are
  documented in [SECURITY.md](SECURITY.md) as incomplete by design, and they
  reduce risk rather than eliminate it;
- your compliance, or non-compliance, with any law that applies to your use.

Nothing here excludes liability that cannot lawfully be excluded.

## 10. Children

This software is not directed at children and has no interface of its own for
anyone to use. Telegram's own minimum-age terms apply to the account you connect.

## 11. Changes

This policy describes the behaviour of the version of the software you have. If
the behaviour changes, this file changes with it in the same commit, and the
change is recorded in [CHANGELOG.md](CHANGELOG.md). There is no remote copy that
can be revised behind your back — check `git log PRIVACY.md` for its full
history.

## 12. Verification, not assurance

Every factual claim in this policy is asserted by the test suite, in
`tests/test_privacy_claims.py`. If a change made one of them untrue, the tests
fail. You do not have to take any of this on trust: the source is here, and so
are the tests.

## 13. Contact

Open an issue on the repository. For anything security-sensitive, use the
private reporting route in [SECURITY.md](SECURITY.md) instead of a public issue.
