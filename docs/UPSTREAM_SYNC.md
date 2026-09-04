# Staying in sync with upstream

This project keeps the full Git history of
[dryeab/mcp-telegram](https://github.com/dryeab/mcp-telegram) and is designed so
that upstream improvements can still be merged.

## Remotes

```
origin    → https://github.com/sahajp0618-pixel/telegram-mcp-enhanced   (this project)
upstream  → https://github.com/dryeab/mcp-telegram                (original)
```

If you cloned this repository, add the upstream remote once:

```bash
git remote add upstream https://github.com/dryeab/mcp-telegram.git
git fetch upstream
```

`git log upstream/main` should show the original project's commits — they are
ancestors of this project's history, not a squashed import.

## Pulling in upstream changes

```bash
git fetch upstream
git log --oneline HEAD..upstream/main      # what is new
git checkout -b sync/upstream-YYYY-MM-DD
git merge upstream/main
```

Then, before merging the sync branch:

```bash
uv run pytest              # the regression suite is the safety net
uv run ruff check src tests
```

`tests/regression/test_upstream_tools.py` exercises every upstream tool through
the MCP layer with a fake Telegram backend. If an upstream change alters a tool's
behaviour, that suite is where it shows up.

## Why conflicts should be rare

The enhanced layer was built to stay out of upstream's way:

- **New code lives in new files.** `config.py`, `runtime.py`, `middleware.py`,
  `errors.py`, `_compat.py`, `security/` and `reliability/` have no upstream
  counterpart and cannot conflict.
- **The import package keeps upstream's name** (`mcp_telegram`) and upstream's
  file layout, so upstream patches apply against the same paths.
- **Security logic is centralised, not sprinkled.** Tools declare what they do
  with one `@guarded(...)` decorator; the checks themselves live in the
  middleware. A tool's body stays close to upstream's.
- **Upstream files were changed as little as possible.** As of v1.0.0:

  | File | Change |
  | --- | --- |
  | `server.py` | one decorator and one gateway hook per tool, `MCPServer` import, security notes in docstrings, lifespan startup |
  | `types.py` | additive fields only (`source`, `trust_level`, `chat_id`, `security`) plus the `Dialogs` model |
  | `telegram.py` | three added methods (`is_connected`, `resolve_peer_id`, `_unread_state`) and the unread fix |
  | `cli.py` | logging setup, SDK compatibility, two new commands |
  | `utils.py` | unchanged |

## Where conflicts are likely

- **`server.py` tool signatures.** If upstream adds an argument, take their
  version of the function body and keep the `@guarded(...)` decorator above it.
  If upstream adds a *new tool*, give it a decorator too — a tool without one
  bypasses every check.
- **`pyproject.toml` metadata.** Project name, version, authors and URLs are
  intentionally different; take this project's version of those keys and
  upstream's version of dependency changes.
- **`README.md`, `CHANGELOG.md`, `LICENSE`.** This project maintains its own.
  The upstream copyright notice in `LICENSE` must stay intact.

## Checklist for a new upstream tool

1. Add `@guarded(...)` under `@mcp.tool()` with the right `Operation`.
2. Name the chat argument with `entity_arg=` (or `entity_from=`) so chat access
   control applies.
3. If it returns Telegram-authored content, add a `postprocess=` gateway hook.
4. If it takes a local path, declare `upload_paths_arg=` or `download_path_arg=`.
5. Add a regression test in `tests/regression/`.
