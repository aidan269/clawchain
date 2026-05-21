# /cantinasec:clawchain

Surface dependency warnings across the three vectors most exposed by AI tooling: **pip packages**, **VS Code extensions**, and **MCP servers**.

Inspired by [@DarshanSays](https://x.com/DarshanSays) — "We're in a supply chain security crisis accelerated by AI tooling. Every VS Code extension, pip package, and MCP server is a potential entry point."

> **Clawchain is a heads-up tool, not a security audit.** It surfaces patterns in your dependencies that may be worth a closer look. It does not issue findings, verdicts, or audit conclusions. The judgment about whether each warning is a real problem stays with you. For a managed assessment, consider AgentSight.

## What gets scanned

| Vector | Sources | Examples of patterns it surfaces |
|--------|---------|----------------------------------|
| pip packages | `requirements*.txt`, `Pipfile*`, `pyproject.toml`, live `pip list` | Unpinned versions, typosquat-shaped names, OSV advisories, post-install scripts, direct-from-git installs |
| VS Code extensions | `~/.vscode/extensions/`, `~/.cursor/extensions/` | Unverified publishers, display-name impersonation, broad workspace-trust capabilities, bundled vulnerable deps |
| MCP servers | `~/.claude.json`, `claude_desktop_config.json`, project `.mcp.json` | Unpinned `npx`/`uvx`, curl-pipe-shell installers, credential-shaped strings in `env`, HTTP (non-HTTPS) URLs |

## Concern levels

Each warning is ranked by how much it's worth a closer look:

- **High** — worth checking soon
- **Medium** — worth checking
- **Low** — minor pattern to note

There is no "critical" level, and there is no overall verdict. The reader investigates and decides.

## Usage

```
/cantinasec:clawchain                    # scan cwd + global VS Code + MCP configs
/cantinasec:clawchain ./path/to/project  # scope the project scan to a specific dir
```
