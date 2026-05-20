# /cantinasec:clawchain

Audit a developer's environment for supply-chain attack surface across the three vectors most exposed by AI tooling: **pip packages**, **VS Code extensions**, and **MCP servers**.

Inspired by [@DarshanSays](https://x.com/DarshanSays) — "We're in a supply chain security crisis accelerated by AI tooling. Every VS Code extension, pip package, and MCP server is a potential entry point."

Returns a CRITICAL / HIGH / MEDIUM / LOW finding list with concrete remediation for each. Final verdict: **PASS**, **REVIEW REQUIRED**, or **BLOCK**.

## What gets scanned

| Vector | Sources | Examples of what's flagged |
|--------|---------|----------------------------|
| pip packages | `requirements*.txt`, `Pipfile*`, `pyproject.toml`, live `pip list` | Unpinned versions, typosquats, OSV advisories, post-install scripts, git installs |
| VS Code extensions | `~/.vscode/extensions/`, `~/.cursor/extensions/` | Unverified publishers, impersonation, broad workspace trust, bundled bad deps |
| MCP servers | `~/.claude.json`, `claude_desktop_config.json`, project `.mcp.json` | Unpinned `npx`/`uvx`, curl-pipe-shell installers, hardcoded credentials, HTTP URLs |

## Verdict thresholds

- **PASS** — no CRITICAL or HIGH findings
- **REVIEW REQUIRED** — 1–3 HIGH, no CRITICAL
- **BLOCK** — any CRITICAL, or 4+ HIGH

## Usage

```
/cantinasec:clawchain                    # audit cwd + global VS Code + MCP configs
/cantinasec:clawchain ./path/to/project  # scope the project audit to a specific dir
```
