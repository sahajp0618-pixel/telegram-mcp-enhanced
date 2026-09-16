# Disclaimer and terms of use

**Last updated:** 16 September 2026
**Applies to:** Telegram MCP Enhanced, the software in this repository.

Read this before you run the software.

**The [MIT License](LICENSE) governs, and its grant is unconditional.** Nothing
here takes back a right it gives you. That matters for reading the rest of this
document, because the four things below are doing four different jobs and only
one of them is contractual:

| Section | What it is |
| --- | --- |
| **2 and 3** — no warranty, no liability | The MIT disclaimer, restated. Part of the licence you already accepted; binding on the same terms. |
| **5** — acceptable use | A statement of what the software is and is not intended for, and an explicit refusal of responsibility for uses outside that. **Not a restriction on the MIT grant** — it does not, and could not, revoke your right to use the code. |
| **6, 7, 8, 9** — Telegram, AI risk, dependencies, export | Notice. Things you are responsible for knowing, which the maintainers are telling you rather than assuming. |
| **4** — indemnity | The one genuinely contractual term, offered separately from the licence. Section 4 says plainly what that does and does not mean. |

Stating this plainly is deliberate. A document that grants unrestricted use in
one file and forbids it in another is not stronger protection — it is a
contradiction that a reader is entitled to resolve against whoever wrote it.

> **This is not legal advice, and the maintainers are not your lawyers.** If
> your use of this software carries real commercial or regulatory exposure, have
> somebody qualified in your jurisdiction read it.

## 1. What this software is

An open-source tool you download and run yourself, which connects an AI system
to a Telegram account through the Model Context Protocol. It is **not a
service**. The maintainers operate no servers, receive no data, and have no
visibility into or control over any installation. See [PRIVACY.md](PRIVACY.md).

It is an independent, unofficial project:

- **Not affiliated with, endorsed by, or connected to Telegram** (Telegram
  FZ-LLC, Telegram Messenger Inc., or any related entity). "Telegram" is used
  only to identify the service the software interoperates with.
- **Not affiliated with or endorsed by the upstream author.** It is a downstream
  fork of [dryeab/mcp-telegram](https://github.com/dryeab/mcp-telegram), whose
  author wrote the Telegram/MCP foundation and is not responsible for anything
  added here or for how you use it.
- **Not affiliated with or endorsed by any AI model or client vendor.** Any
  product names elsewhere in this documentation describe compatibility only.

## 2. No warranty

Restating the licence, because it governs and because it is easy to miss:

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

In plain terms: nobody promises it works, that it is secure, that it is fit for
your purpose, that it will keep working, or that it will be maintained. It may
contain defects. It may stop working when Telegram, Telethon, the MCP SDK or
your AI client changes. No support, updates or fixes are owed to you.

## 3. No liability

> IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
> DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
> OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
> OR OTHER DEALINGS IN THE SOFTWARE.

To the fullest extent the law allows, the maintainers are not liable for any
direct, indirect, incidental, special, consequential, punitive or exemplary
damages, or for lost profits, lost data, lost business, reputational harm or
account loss, even if advised that such damage was possible.

Specifically — and this list adds to rather than limits the above — the
maintainers are not responsible for:

- **What an AI system does with your account.** Messages sent, edited or deleted
  by a model; messages sent to the wrong person; content a model composed; the
  contents of anything it read, forwarded or summarised. An autonomous agent
  acting on a personal messaging account is the entire risk of this software, and
  it is a risk you take on knowingly.
- **Action taken against your Telegram account**, including rate limiting, flood
  waits, feature restriction, suspension or permanent termination, whether or not
  connected to Telegram's terms.
- **Any security defence failing.** The prompt-injection detection, permission
  enforcement, chat access control, file policy and outbound content policy
  reduce risk. They do not eliminate it, they are incomplete by design, and
  [SECURITY.md](SECURITY.md) documents exactly where they fall short. Treating
  them as a guarantee is a misuse of them.
- **Data disclosed to systems you connect** — your MCP client, its model
  provider, or anything else downstream. Their retention, training and disclosure
  policies are theirs, and this software cannot see or control them.
- **Other people's data.** Your conversations involve people who did not install
  this. Processing their messages is your decision.
- **Loss or exposure of credentials or session data** held on your own machine.
- **Your compliance, or non-compliance, with any law, regulation or contract.**
- **Anything a modified copy does.** If you change the code, what you changed is
  yours.

## 4. Indemnification

**This is the clause that addresses what the licence does not: a third party
bringing a claim against the maintainers because of something you did.**

Be clear about its standing. MIT does **not** condition your licence on this,
and this document does not add that condition — so this is a term offered
alongside the licence rather than a restriction inside it, and how far a court
would enforce it against someone who simply downloaded the code and never
signed anything varies by jurisdiction and by circumstance. It is stated here
because the expectation should be on the record either way, and because a
maintainer who publishes source code has no other way to say it.

Subject to that, you agree to indemnify, defend and hold harmless the
maintainers, contributors and copyright holders of this software from and
against any claim, demand, action, investigation, loss, liability, damage, cost
or expense — including reasonable legal fees — brought by any third party and
arising out of or connected with:

- your use, misuse, deployment, modification or distribution of the software;
- anything an AI system did while connected through it;
- your breach of these terms, of the MIT Licence, or of section 5 below;
- your violation of Telegram's terms of service or acceptable use policy;
- your violation of any law or regulation, including data protection, privacy,
  anti-spam, communications interception and computer misuse law;
- your infringement of anyone's rights, including privacy, publicity and
  intellectual property rights.

The maintainers publish source code. They do not operate your deployment, choose
your configuration, select your model, or see your data. If a third party brings
a claim because of how *you* ran it, that claim is yours to answer.

## 5. Acceptable use

This software is intended for one thing: letting someone give an AI assistant
controlled, policy-limited access to **their own** Telegram account.

The uses below are outside that intent. The MIT licence does not stop you — no
open-source licence meaningfully could, and this document does not pretend to
add a restriction it cannot enforce. What this section does is put on the record
that these uses are unintended, unsupported, and disclaimed: if you pursue one,
you do it against the documented purpose of the software, section 4 applies, and
the consequences are yours.

- **Spam, bulk unsolicited messaging, or mass automated outreach.**
- **Harassment, stalking, threats, or abuse** of anyone.
- **Surveillance of people without their knowledge or a lawful basis**, including
  monitoring a partner's, employee's or child's conversations where doing so is
  unlawful where you are.
- **Scraping, harvesting or bulk-exporting** messages, contact details, phone
  numbers or group membership, whether for resale, for training data, or at all
  where it breaches Telegram's terms or applicable law.
- **Impersonating** any person or organisation.
- **Evading Telegram's rate limits, anti-abuse systems or account restrictions.**
  The reliability layer in this project exists to keep an agent within Telegram's
  limits, not to help anyone slip past them.
- **Accessing an account you are not authorised to use.**
- **Distributing malware, phishing, fraud or other illegal content.**
- **Anything unlawful** where you are, where your account is, or where the people
  you are messaging are.

Do not use it where a failure would be dangerous. It is not designed, tested or
suitable for safety-critical, medical, emergency-response, life-support,
industrial-control or similar uses, and connecting a probabilistic system to a
messaging account is unsuitable for any of them.

**None of this is technically enforced, and it is not meant to be.** The
software cannot tell what you intend and will not stop you. Its permission
system limits what a *model* can do within a configuration *you* chose; it has
never constrained the operator, and a security control that claimed to would be
lying about what it is.

So treat this section as what it is: the maintainers stating, in advance and in
public, what this tool is for. Use it otherwise and you are outside the
documented purpose — on your own, without support, and squarely within section
4.

## 6. Telegram's terms are yours to satisfy

The software connects to Telegram using your credentials, as your account,
through the unofficial MTProto client library [Telethon](https://github.com/LonamiWebs/Telethon).

- Your use is governed by [Telegram's Terms of Service](https://telegram.org/tos),
  their [Privacy Policy](https://telegram.org/privacy) and their
  [API Terms of Service](https://core.telegram.org/api/terms). Read them.
- **Automating a personal account can get it limited or banned.** Telegram
  decides that, not this software, and no configuration here prevents it.
- Your API credentials come from [my.telegram.org](https://my.telegram.org/apps)
  under Telegram's terms, and remain subject to them.
- If Telegram's terms and this document ever conflict for your use, Telegram's
  terms govern your relationship with Telegram. Nothing here grants you
  permission Telegram has not.

**Strong recommendation: do not point this at an account you cannot afford to
lose.** Use a secondary account for anything experimental.

## 7. AI-specific risks you are accepting

Worth stating separately, because they are new enough that people underestimate
them.

- **Models are not deterministic.** The same instruction can produce different
  actions on different runs. Testing does not establish what it will do next
  time.
- **Models act on content written by strangers.** Anyone who can message your
  account can put text in front of your agent. This project's entire threat model
  is built around that, and it still cannot catch everything —
  [docs/DETECTION.md](docs/DETECTION.md) publishes the measured miss rate and the
  cases it is known to get wrong.
- **Permission you grant, a model can use.** If you allow sending, a sufficiently
  convincing injection can cause a send. Grant the narrowest permission set that
  does your job, and use [`dry_run`](docs/CONFIGURATION.md) before trusting a new
  configuration.
- **Actions can be irreversible.** A deleted Telegram message is gone. A sent
  message has been read. There is no undo, and no confirmation step unless your
  client provides one.
- **Anyone who can edit your config or environment controls every protection
  here.** The security layer defends against hostile *content*, not against
  someone with access to your machine.

## 8. Third-party components

The software depends on third-party open-source packages — Telethon, the MCP
SDK, Pydantic, Typer, Rich and others — each under its own licence and its own
disclaimer. The maintainers of this project do not warrant them, are not
responsible for their defects, and do not control their release decisions. See
`pyproject.toml` and `uv.lock` for the full set.

## 9. Export control and sanctions

You are responsible for complying with any export control, economic sanctions
and trade restriction laws that apply to you, including obtaining any licence you
need. Do not use or re-export the software where doing so is prohibited.

## 10. Changes, severability, and what cannot be excluded

- This document describes the version you have. It changes in the same commit as
  any behaviour it describes, and its full history is in `git log DISCLAIMER.md`.
  There is no remote copy that can be revised behind your back.
- If any provision is held unenforceable, the rest stays in force and the
  unenforceable part is limited to the minimum extent necessary.
- **Nothing here excludes or limits liability that cannot lawfully be excluded
  or limited** — including, in many jurisdictions, liability for death or
  personal injury caused by negligence, or for fraud. Some jurisdictions do not
  allow the exclusion of implied warranties or of incidental or consequential
  damages, so parts of sections 2 and 3 may not apply to you. You may have
  statutory rights this document cannot affect, and it does not try to.
- Nothing here creates any agency, partnership, employment or joint venture, and
  no maintainer owes you a duty of support.

## 11. Related documents

| Document | What it covers |
| --- | --- |
| [LICENSE](LICENSE) | The MIT grant, and the warranty and liability disclaimer |
| [PRIVACY.md](PRIVACY.md) | What is stored, what leaves your machine, who is responsible |
| [SECURITY.md](SECURITY.md) | Threat model, what is enforced, and what is not protected |
| [docs/DETECTION.md](docs/DETECTION.md) | Measured detection quality, and its known failures |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Known gaps, ranked |

---

**In short:** the licence gives you the code with no warranty and no liability,
and that much is settled. Beyond it, this document asks you to take
responsibility for what you do with it and tells you honestly which parts of
that request are binding and which are the maintainers stating an expectation.
If that trade is not one you want, the honest answer is not to run it — not
because a clause forbids you, but because the software hands an AI system real
control of a real messaging account, and everything that follows from that is
yours.
