# Publishing and releasing

This project is prepared for publication at
`https://github.com/sahajp0618-pixel/telegram-mcp-enhanced`. Keep the enhanced
work on `feat/security-reliability-layer` until it has been reviewed and is
ready to become the repository's default branch.

## GitHub publication

1. Create the GitHub repository without an initial README, licence, or
   `.gitignore`.
2. Confirm the configured remotes:

   ```bash
   git remote -v
   # origin   https://github.com/sahajp0618-pixel/telegram-mcp-enhanced.git
   # upstream https://github.com/dryeab/mcp-telegram.git
   ```

3. Review the exact refs before sending anything:

   ```bash
   git status --short --branch
   git log --oneline upstream/main..feat/security-reliability-layer
   git push --dry-run origin feat/security-reliability-layer
   ```

4. Push only the reviewed branch. Do not use `git push --all` or `git push
   --mirror`; local recovery refs and development state are intentionally not
   publication refs.

   ```bash
   git push -u origin feat/security-reliability-layer
   ```

When the branch is accepted as the default branch, set the repository's default
branch in GitHub and update local tracking deliberately. The project retains
`upstream` so future changes from `dryeab/mcp-telegram` can be reviewed and
merged normally.

## Installation and configuration

The supported installation and client-configuration instructions are in
[SETUP.md](SETUP.md), [CLIENTS.md](CLIENTS.md), and the repository README. Do
not commit Telegram credentials, sessions, `.env` files, or local configuration
while preparing a release.

## Versioning and releases

The version in `pyproject.toml` is the release version. Update it and the
corresponding section in `CHANGELOG.md` together, then create a matching tag:

```bash
git tag -a v<version> -m "Telegram MCP Enhanced <version>"
git push origin v<version>
```

The release workflow checks that the tag and package version agree, runs the
project checks, builds the wheel and source distribution, and performs a clean
installation check before publishing.

## PyPI trusted publishing

Before the first release, register a pending trusted publisher in PyPI for:

| Field | Value |
| --- | --- |
| PyPI project name | `telegram-mcp-enhanced` |
| GitHub owner | `sahajp0618-pixel` |
| Repository name | `telegram-mcp-enhanced` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

Create the matching `pypi` GitHub environment and consider requiring a reviewer
for it. Trusted publishing uses GitHub's identity token; no PyPI API token
should be added to the repository.

To check packaging locally without publishing:

```bash
uv build
```

## Upstream synchronization

Fetch and review upstream changes before integrating them:

```bash
git fetch upstream
git log --oneline HEAD..upstream/main
```

See [UPSTREAM_SYNC.md](UPSTREAM_SYNC.md) for the integration workflow. Always
run the project checks after resolving an upstream update.
