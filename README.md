# clawchain

A `/cantinasec:` plugin that surfaces **dependency warnings** across the three entry points AI tooling has made most exposed: pip packages, VS Code extensions, and MCP servers.

> **Clawchain is a heads-up tool, not a security audit.** It surfaces patterns in your dependencies that may be worth a closer look. It does not issue findings, verdicts, or audit conclusions. The judgment about whether each warning is a real problem stays with you. If something in the breakdown looks worth a closer conversation, the breakdown itself includes an email link to talk to us.

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

## What patterns it surfaces

### Vector 1 — Pip packages
- Unpinned versions (`requests` instead of `requests==2.32.3`) → **medium**
- Typosquat-shaped names against a common-target list (Levenshtein ≤ 2) → **high**
- Active OSV / PyPI advisories → **high**
- Suspicious post-install scripts in `site-packages/` → **medium** / **high** (if hitting non-PyPI domain)
- `pip install git+https://...` from unknown orgs → **high**
- Missing hash pinning → **low**

### Vector 2 — VS Code extensions
- Unverified publishers → **medium** (high for single-author with broad scope)
- Display-name impersonation (e.g. "ESLint" not from `dbaeumer`) → **high**
- Broad `untrustedWorkspaces` / `virtualWorkspaces` capabilities → **high**
- Bundled `node_modules` with OSV hits → **high**
- Custom `updateUrl` outside the Marketplace → **high**

### Vector 3 — MCP servers
- Unpinned `npx <pkg>` / `uvx <pkg>` (no `@version`) → **high**
- `curl ... | sh` / `wget ... | bash` / `iex (irm ...)` installers → **high**
- Credential-shaped strings in `env` (`sk-*`, `sk_live_*`, `ghp_*`, `AKIA*`, …) → **high** (worth checking and rotating if confirmed)
- HTTP (non-HTTPS) server URLs outside localhost → **high**
- Unknown npm scopes → **medium**
- `gmail`/`gdrive`/`slack`/`stripe` MCPs at global scope → **medium**
- Destructive tools in `alwaysAllow` (`bash`, `write_file`, `execute_sql`) → **high**

## Output

```
CLAWCHAIN DEPENDENCY WARNINGS
=============================
Project: <path>
Pip manifests scanned: N     | warnings: N
VS Code extensions scanned: N | warnings: N
MCP servers scanned: N       | warnings: N

High: N | Medium: N | Low: N

[HIGH] <vector> — <name>
  What we saw: <file:line or config path>
  Why it caught our eye: <one-sentence explanation>
  One thing you could do: <concrete command or config change>

…

Clawchain is a heads-up tool, not a security audit. These are patterns
worth a closer look — the judgment about whether each one is a real
problem is yours.
```

After the terminal output, the skill renders a Cantina-branded HTML **breakdown** (orange-on-black, glass panels, concern-coded warning cards) and opens it in your default browser. Files are timestamped self-contained HTML in your system temp dir — no internet roundtrip and nothing leaves your machine. The page includes:

- **Print / Save as PDF** — opens the browser print dialog; the page has print-friendly CSS that strips the toolbar, CTA, and decorative backgrounds for clean PDFs
- **Download JSON** — the raw warnings data, embedded as a data URI so it works offline
- **Email us** — a low-friction CTA if you want to talk through anything in the breakdown

### Optional: AI-generated suggested context

If `ANTHROPIC_API_KEY` is exported in your shell, the skill also calls Claude Haiku 4.5 once per warning to attach a suggested-context block on top of the static `suggested_fix` already on each warning:

- **Possible reason this slipped in** — a plausible workflow story for how this pattern might have ended up in this codebase. Suggestive, not authoritative.
- **Something that might prevent it next time** — one named, automated control (pre-commit hook, CI check, lint rule, or repo policy) that might catch this pattern.

The two fields are deliberately scoped to what only an LLM can usefully add — the static `suggested_fix` already covers the immediate command or config edit. The script (`scripts/enrich_remediation.py`) caches the system prompt, so a typical 30-warning scan runs in cents. The key is read from `os.environ['ANTHROPIC_API_KEY']` only — never accepted via argv or chat input, in keeping with the credential-handling patterns clawchain itself warns about. If the key is unset, the summary falls back to the static `suggested_fix` strings.

## Run it directly (without Claude Code)

The scanner is a deterministic Python script — usable from a terminal, pre-commit hook, or CI:

```bash
python3 skills/clawchain/scripts/scan.py <project_path> --out warnings.json
python3 skills/clawchain/scripts/render_report.py warnings.json
```

Flags:
- `--no-osv` — skip OSV.dev queries (offline / fast mode)
- `--no-env` — skip global VS Code + MCP scans (project-only)
- `--quiet` — suppress per-vector progress

Stdlib-only, no install step. Works on Python 3.9+ (uses `tomllib` when available, falls back to a regex extractor for older Pythons). Optional: `export ANTHROPIC_API_KEY=...` and run `enrich_remediation.py` in between for AI-suggested context cards.

## Layout

```
clawchain/
├── README.md
├── clawchain.md              ← user-facing usage doc
├── commands/
│   └── clawchain.md          ← Claude Code slash-command shim
└── skills/
    └── clawchain/
        ├── SKILL.md          ← skill spec for Claude Code
        └── scripts/
            ├── scan.py                ← deterministic scanner (3 vectors, 19 checks)
            ├── enrich_remediation.py  ← optional Claude Haiku enrichment
            └── render_report.py       ← Cantina-branded HTML breakdown renderer
```

## Source

Built from two tweets by [Darshan Yadav (@DarshanSays)](https://x.com/DarshanSays) on 2026-05-20:

- [Supply chain crisis tweet](https://x.com/DarshanSays/status/2057098732873908503) — the threat model for dev environments has changed
- [Agentic attack surface tweet](https://x.com/DarshanSays/status/2057029849550856375) — 24/7 agents amplify the blast radius of any compromised dep

## License

MIT
