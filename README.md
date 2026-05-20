# clawchain

A `/cantinasec:` plugin that audits a developer's environment for **supply-chain attack surface** across the three entry points AI tooling has made most dangerous: pip packages, VS Code extensions, and MCP servers.

> "We're in a supply chain security crisis accelerated by AI tooling. Every VS Code extension, pip package, and MCP server is a potential entry point. Breach cost is dropping, breach frequency is rising. The threat model for dev environments has changed."
> — [Darshan Yadav, 2026-05-20](https://x.com/DarshanSays/status/2057098732873908503)

## Install

Copy the command shim and skill into your Claude config:

```bash
mkdir -p ~/.claude/commands/cantinasec ~/.claude/skills/clawchain
cp commands/clawchain.md ~/.claude/commands/cantinasec/clawchain.md
cp skills/clawchain/SKILL.md ~/.claude/skills/clawchain/SKILL.md
```

Then in Claude Code:

```
/cantinasec:clawchain
```

## What it checks

### Vector 1 — Pip packages
- Unpinned versions (`requests` instead of `requests==2.32.3`) → MEDIUM
- Typosquats of common packages (Levenshtein ≤ 2) → varies
- Active OSV / PyPI advisories → HIGH (CRITICAL for RCE-class)
- Suspicious post-install scripts in `site-packages/` → MEDIUM/CRITICAL
- `pip install git+https://...` from unknown orgs → HIGH

### Vector 2 — VS Code extensions
- Unverified publishers → MEDIUM (HIGH for single-author with broad scope)
- Display-name impersonation (e.g. "ESLint" not from `dbaeumer`) → CRITICAL
- Broad `untrustedWorkspaces` / `virtualWorkspaces` capabilities → HIGH
- Bundled `node_modules` with OSV hits → HIGH
- Custom `updateUrl` outside the Marketplace → HIGH

### Vector 3 — MCP servers
- Unpinned `npx <pkg>` / `uvx <pkg>` (no `@version`) → HIGH
- `curl ... | sh` / `wget ... | bash` / `iex (irm ...)` installers → CRITICAL
- Hardcoded API keys (`sk-*`, `sk_live_*`, `ghp_*`, `AKIA*`, …) in `env` → CRITICAL
- HTTP (non-HTTPS) server URLs outside localhost → HIGH
- Unknown npm scopes → MEDIUM
- `gmail`/`gdrive`/`slack`/`stripe` MCPs at global scope → MEDIUM
- Destructive tools in `alwaysAllow` (`bash`, `write_file`, `execute_sql`) → HIGH

## Output

```
CLAWCHAIN SUPPLY-CHAIN AUDIT
============================
Project: <path>
Pip manifests scanned: N     | findings: N
VS Code extensions scanned: N | findings: N
MCP servers scanned: N       | findings: N

CRITICAL: N | HIGH: N | MEDIUM: N | LOW: N

[CRITICAL] <vector> — <name>
  Evidence: <file:line or config path>
  Why: <one-sentence explanation>
  Fix: <concrete command or config change>

…

OVERALL: PASS | REVIEW REQUIRED | BLOCK
```

## Layout

```
clawchain/
├── README.md
├── clawchain.md              ← user-facing usage doc
├── commands/
│   └── clawchain.md          ← Claude Code slash-command shim
└── skills/
    └── clawchain/
        └── SKILL.md          ← full audit spec (3 vectors, 19 checks)
```

## Source

Built from two tweets by [Darshan Yadav (@DarshanSays)](https://x.com/DarshanSays) on 2026-05-20:

- [Supply chain crisis tweet](https://x.com/DarshanSays/status/2057098732873908503) — the threat model for dev environments has changed
- [Agentic attack surface tweet](https://x.com/DarshanSays/status/2057029849550856375) — 24/7 agents amplify the blast radius of any compromised dep

## License

MIT
