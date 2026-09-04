# Contributing to Telegram MCP Enhanced

Thanks for your interest. This document covers the workflow for the enhanced
downstream project. For the original Telegram/MCP foundation, see
[dryeab/mcp-telegram](https://github.com/dryeab/mcp-telegram).

## Development setup

1. **Clone and add the upstream remote**

   ```bash
   git clone https://github.com/sahajp0618-pixel/telegram-mcp-enhanced.git
   cd telegram-mcp-enhanced
   git remote add upstream https://github.com/dryeab/mcp-telegram.git
   ```

2. **Set up the environment** — Python 3.10 or newer, with
   [`uv`](https://docs.astral.sh/uv/):

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh   # if you don't have it
   uv sync
   ```

3. **Install the pre-commit hooks**

   ```bash
   uv run pre-commit install
   ```

## Running the checks

```bash
uv run pytest                      # no network, no Telegram account
uv run ruff check src tests
uv run ruff format --check src tests
uv run pyright                     # optional, strict on src/
```

The test suite never touches the network or a real session: `tests/conftest.py`
redirects the XDG state directory and `tests/fakes.py` stands in for Telethon.

If you change a dependency, refresh the lockfile with `uv lock` — a pre-commit
hook checks it is current.

## Working on the security layer

Two rules matter more than style here:

1. **Enforcement belongs in the middleware, not in tools.** Every Telegram-facing
   tool goes through one `@guarded(...)` decorator. If you add a tool without
   one, it bypasses chat access control, permissions, the file policy, the rate
   limiter and the content gateway. See
   [docs/UPSTREAM_SYNC.md](docs/UPSTREAM_SYNC.md) for the checklist.

2. **Fail safe.** When a check cannot be completed — a chat that will not
   resolve, a config that will not parse, a gateway that raises — the outcome is
   a refusal, never an unchecked success.

New detection rules need tests on both sides: an attack that must be caught, and
an ordinary message that must not be. False positives are a real cost;
`ORDINARY_MESSAGES` in `tests/security/test_injection_detection.py` is the guard
against them.

## Keeping upstream merges cheap

Prefer adding new modules over editing upstream ones. When you must edit an
upstream file, keep the change as small as it can be and note it in
[docs/UPSTREAM_SYNC.md](docs/UPSTREAM_SYNC.md). Mark added code with a short
"Added by Telegram MCP Enhanced" note in the module or field docstring so the
provenance stays clear.

## Workflow

1. Branch: `git checkout -b feat/your-feature-name`
2. Commit in focused, present-tense steps ("Add …", "Fix …").
3. Update `CHANGELOG.md` under *Unreleased* for anything user-visible.
4. Update the docs for anything configurable.
5. Open a pull request describing the change and the security reasoning behind
   it, if any.

## Code style

- [PEP 8](https://peps.python.org/pep-0008/), enforced by ruff (88 columns).
- Type hints on every public function; `src/` is checked in pyright strict mode.
- Docstrings on public functions, classes and modules — say *why*, not just
  *what*, where the reason is not obvious.
- Keep functions focused; keep security decisions in one place.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

Contributions are licensed under the MIT License, the same as the upstream
project. The original copyright notice must remain intact.
