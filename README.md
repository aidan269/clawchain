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

After the terminal output, the skill renders a Cantina-branded HTML report (orange-on-black, glass panels, severity-coded findings) and opens it in your default browser. Reports are timestamped self-contained HTML in your system temp dir — no internet roundtrip and nothing leaves your machine.

### Optional: AI-generated remediation

If `ANTHROPIC_API_KEY` is exported in your shell, the skill also calls Claude Haiku 4.5 once per finding to attach a 2-part remediation block on top of the static `fix` already on the finding:

- **Root cause** — the process gap or workflow oversight that allowed the finding in this codebase
- **Prevention** — a specific, automated control (named pre-commit hook, CI check, lint rule, or repo policy) that would have caught it without anyone remembering to check

The two fields are deliberately scoped to what only an LLM can produce — the static `fix` already covers the immediate command or config edit. The script (`scripts/enrich_remediation.py`) caches the system prompt, so a typical 30-finding audit runs in cents. The key is read from `os.environ['ANTHROPIC_API_KEY']` only — never accepted via argv or chat input, in keeping with the credential-handling rules clawchain itself audits for. If the key is unset, the report falls back to the static `fix` strings.

## Layout

```
clawchain/
├── README.md
├── clawchain.md              ← user-facing usage doc
├── commands/
│   └── clawchain.md          ← Claude Code slash-command shim
└── skills/
    └── clawchain/
        ├── SKILL.md          ← full audit spec (3 vectors, 19 checks)
        └── scripts/
            └── render_report.py  ← Cantina-branded HTML report renderer
```

## Source

Built from two tweets by [Darshan Yadav (@DarshanSays)](https://x.com/DarshanSays) on 2026-05-20:

- [Supply chain crisis tweet](https://x.com/DarshanSays/status/2057098732873908503) — the threat model for dev environments has changed
- [Agentic attack surface tweet](https://x.com/DarshanSays/status/2057029849550856375) — 24/7 agents amplify the blast radius of any compromised dep

## License

MIT
