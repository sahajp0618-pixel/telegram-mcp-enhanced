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
| **Operator** | You, running the software | Decide what data it touches, and hold whatever legal role your deployment gives you — see below. |
| **Third party** | Telegram (Telegram FZ-LLC / Telegram Messenger Inc.) | Provide the messaging service. Their own privacy policy governs your account and messages. |

Because the maintainers never receive your data, there is no maintainer-side
collection, sharing, sale, transfer or retention to describe. This policy exists
to tell you what the software does on **your** machine, so you can meet your own
obligations.

**Your legal role depends on your deployment, and this document cannot assign
it.** Running the software for your own purposes generally makes you the
controller of the data it processes; running it on an employer's or a client's
behalf may make them the controller and you a processor, because
[GDPR Article 4](https://eur-lex.europa.eu/eli/reg/2016/679/art_4/par_1/oj)
distinguishes the two by who determines the purposes and means of processing,
not by who runs the program. Purely personal or household use may fall outside
the GDPR altogether.

This is a notice about what a piece of software does. It is **not** a privacy
notice you can hand to data subjects, and it does not carry out your lawful-basis
assessment, your records of processing, your data-subject rights handling, or any
processor agreement you may need. If you deploy this inside an organisation, you
still owe those separately.

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
| Telethon session | `~/.local/state/mcp-telegram/session.session` | Authentication material **and cached personal data about other people** — see below | You log in, and continuously as it runs |
| Downloaded media | `~/.local/state/mcp-telegram/downloads/` | Files you asked to download | You call `media_download` without a path |
| Security log | `~/.local/state/mcp-telegram/security.log` | Security events — see section 4 | A security event occurs, if logging is enabled |
| Configuration | `~/.config/mcp-telegram/config.toml` | Your policy settings | You create it |

No other **files** are written. Messages are **not** cached, mirrored or
persisted by this software: they are read from Telegram, returned to your MCP
client, and forgotten. (Your MCP client and the model behind it are separate
systems with their own retention behaviour — see section 6.)

To see the locations as the running program resolves them, rather than guessing:

```bash
telegram-mcp-enhanced paths
```

Use that rather than expanding `XDG_STATE_HOME` yourself. The XDG specification
requires a relative value to be ignored in favour of the default, so a shell
command that expands it literally can both miss real data and delete an
unrelated directory.

### Diagnostics on stderr, which are not files

Separately from the files above, the server writes diagnostic logging to
**standard error**. It is not stored by this software — but whatever launched
the server decides what happens to it, and MCP clients commonly capture a
server's stderr into their own log files.

- The default level is `INFO`, which records startup, policy decisions and
  errors — not message content.
- At `DEBUG` (`TELEGRAM_MCP_LOG_LEVEL=DEBUG`, or `log_level` in the config file)
  Telethon's own logging is included, and **that can contain message content and
  request payloads**. Upstream logged at `DEBUG` unconditionally; this project
  changed the default to `INFO` for exactly this reason.
- These messages do **not** pass through the security log's credential scrubber,
  which only applies to the security log. `include_message_content` does not
  govern them either.

Treat raising the log level as a decision about where message content may end up,
and check what your MCP client does with a server's stderr before you do it.

### The session file holds more than a credential

This is the most privacy-relevant file on disk, and describing it as "your
login" would understate it. It is an unencrypted SQLite database created and
managed by Telethon, not by this project, with four tables:

| Table | Holds |
| --- | --- |
| `sessions` | Your authorisation key, data-centre address and port |
| `entities` | For every user, group and channel the client encounters: numeric ID, access hash, **username, phone number and display name** |
| `sent_files` | An upload cache — MD5 digest, size and Telegram file ID of files you have sent |
| `update_state` | Sequence markers for Telegram's update stream |
| `version` | Telethon's schema version number, and nothing else |

The `entities` table is the part worth understanding: **it accumulates other
people's phone numbers, usernames and names**, in plaintext, as a side effect of
normal use, and it persists until you delete the file. Telethon caches them so
it can address peers without asking Telegram again. This project does not add to
that behaviour and does not read those columns, but it does inherit it, and you
are storing that data.

Two consequences:

- Treat `session.session` as both a credential *and* a personal-data store. It
  can be used to act as your Telegram account, and it is a file of contact
  details. The software refuses to upload anything from its own state directory
  for exactly that reason, but it cannot protect the file from anything else on
  your machine. Encrypt the volume it sits on.
- If you are subject to a regime with erasure or minimisation duties, this file
  is in scope, and deleting it is the only way to purge it — there is no
  selective removal.

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

## 8. Deleting what is stored locally

**Stop the server first**, or it will rewrite files as you remove them.

The commands below cover the **default** locations. They are not a complete
purge on their own, because several locations are configurable and this software
honours whatever you set.

```bash
telegram-mcp-enhanced paths           # print the locations actually in use
telegram-mcp-enhanced logout          # how to end the Telegram-side session
telegram-mcp-enhanced clear-session   # delete the local session file
```

Then remove the paths that command printed. Ask the program rather than
expanding the XDG variables in a shell: a relative `XDG_STATE_HOME` must be
ignored in favour of the default, so `${XDG_STATE_HOME:-$HOME/.local/state}`
resolves somewhere the server never wrote — leaving the real data behind, and
pointing `rm -rf` at a directory that may belong to something else.

Then remove anything you moved elsewhere. Each of these is a supported setting,
and none is covered above:

| If you set | Also delete |
| --- | --- |
| `media_download(path=…)` | Every directory you passed — downloads go where the caller asks |
| `security.logging.path` | That file **and its rotated copies** (`…log.1`, `.2`, `.3`) |
| `security.files.allowed_download_dirs` | Anything written into those directories |
| `TELEGRAM_MCP_CONFIG`, or `init-config --path` | The configuration file at that path |
| `XDG_STATE_HOME` / `XDG_CONFIG_HOME` | Whatever they pointed at *when the data was written*, which `paths` cannot tell you if you have since changed them |

If you ever set `include_message_content = true`, the security log and its
rotated copies contain excerpts of message text, so they deserve particular
attention.

### What local deletion cannot reach

Deleting local files removes only local files. It does **not** remove:

- **your messages from Telegram**, which are stored on Telegram's servers under
  their policy, and are unaffected by anything you do here;
- **anything your MCP client or its model provider retained** — see section 6.
  That is the copy most people forget, and this software has no way to reach it;
- **anything you already sent** to another chat;
- **diagnostic output captured by whatever launched the server**. If your MCP
  client keeps its own log of the server's stderr, that copy is in its hands,
  not this software's — and at `DEBUG` it may contain message content.

There is nothing held by the maintainers, because there is nowhere else — but
"the maintainers hold nothing" is not the same as "nothing exists anywhere".

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

## 12. What is verified, and what is not

`tests/test_privacy_claims.py` checks this policy against the code, so that the
two cannot drift apart silently. It is worth being precise about how far that
goes, rather than gesturing at a test suite and leaving you to assume it covers
everything.

**Checked behaviourally** — these fail the build if the behaviour changes:

- the storage locations named in section 3 are the ones the code uses;
- the session database contains the tables and columns section 3 documents;
- the security log's fields, rotation size and backup count are as described;
- message content is not written to the log by default, and is truncated when
  you opt in;
- credentials are removed from log records by literal value and by shape;
- no socket is opened while security analysis runs;
- this policy contains no absolute security claim.

**Checked statically, as a heuristic** — good at catching an accidental change,
not a proof:

- no telemetry or analytics dependency is declared;
- no HTTP client is imported anywhere in the package;
- no non-Telegram URL appears in executable code.

**Not covered by tests at all.** Whether Telegram, your MCP client or its model
provider does what *its* policy says; whether your deployment complies with any
law; and the completeness of the deletion instructions on your particular
machine. Read the source: it is 5,700 lines, and this is the file that tells you
where to look.

## 13. Contact

Open an issue on the repository. For anything security-sensitive, use the
private reporting route in [SECURITY.md](SECURITY.md) instead of a public issue.
