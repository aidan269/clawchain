---
name: clawchain
description: Audits a developer environment for supply-chain attack surface across the three vectors AI tooling has made most dangerous — pip packages, VS Code extensions, and MCP servers. Use when a user wants to audit dependencies, check for typosquats or malicious packages, audit MCP server configs, assess VS Code extension trust, scan for hardcoded credentials in agent configs, or estimate supply-chain risk in their dev environment. Scans the project plus the developer's global VS Code and MCP configs, queries OSV for known vulns, and returns a severity-ranked finding list (CRITICAL / HIGH / MEDIUM / LOW) with one concrete remediation per finding. Final verdict is PASS, REVIEW REQUIRED, or BLOCK.
---

# Clawchain — Dev Environment Supply-Chain Audit

## Overview

The developer environment is now a primary attack surface. Every pip package, VS Code extension, and MCP server in a developer's setup is a potential entry point for code execution, secret exfiltration, and silent agent hijack. AI tooling has accelerated this — long-running agents with broad data scopes turn a single compromised dependency into immediate, attacker-visible damage.

`clawchain` audits a project plus the developer's local environment across the three vectors and returns a severity-ranked finding list.

## Source

Built from two tweets by Darshan Yadav ([@DarshanSays](https://x.com/DarshanSays)) on 2026-05-20:

> "We're in a supply chain security crisis accelerated by AI tooling. Every VS Code extension, pip package, and MCP server is a potential entry point. Breach cost is dropping, breach frequency is rising. The threat model for dev environments has changed."
> — [2057098732873908503](https://x.com/DarshanSays/status/2057098732873908503)

> "A 24/7 agent with Gmail, Docs, and MCP-connected apps is a massive attack surface expansion. Prompt injection through a malicious email can instruct the agent to act silently — no device needed by the attacker."
> — [2057029849550856375](https://x.com/DarshanSays/status/2057029849550856375)

## Trigger

Use this skill when the user asks to:
- "audit my dependencies"
- "check supply chain risk"
- "scan for typosquats / malicious packages"
- "audit my MCP servers"
- "check what VS Code extensions could leak data"
- runs `/cantinasec:clawchain`

## Scope Resolution

1. **Project scope** — if `$ARGUMENTS` provides a path, audit only that directory. Otherwise default to the current working directory.
2. **Environment scope** — always audit the developer's local config paths:
   - VS Code extensions: `~/.vscode/extensions/`, `~/.cursor/extensions/`, `~/.vscode-insiders/extensions/`
   - Claude Code MCP config: `~/.claude.json`, `~/.claude/settings.json`, `~/.claude/mcp.json`, project `.mcp.json`
   - Claude Desktop MCP config: `~/Library/Application Support/Claude/claude_desktop_config.json`

Skip any path that does not exist — note it as "not present" rather than failing.

---

## Audit Procedure

Run the three vector audits in order. For each finding, record: vector, severity, evidence (file path + line / package name + version), and remediation.

### Vector 1 — Pip Packages

Manifests to inspect:
- `requirements*.txt`, `requirements/*.txt`
- `Pipfile`, `Pipfile.lock`
- `pyproject.toml` (poetry / pdm / hatch)
- `setup.py`, `setup.cfg`
- `environment.yml` (conda)

Live install state:
```bash
pip list --format=json 2>/dev/null
pip --version
```

**Checks:**

1. **Unpinned versions** — any dependency without `==` or hash pin is MEDIUM. Floating versions (`>=`, `~=`, no operator) let an attacker compromise the next install.
2. **Known typosquats** — compare against this short list of common targets and flag near-matches (Levenshtein ≤ 2):
   `requests`, `urllib3`, `numpy`, `pandas`, `pillow`, `cryptography`, `pyyaml`, `boto3`, `flask`, `django`, `fastapi`, `pytest`, `setuptools`, `tensorflow`, `torch`, `transformers`, `openai`, `anthropic`, `langchain`.
   Examples to flag: `requessts`, `python-requests`, `numpyy`, `crypt0graphy`.
3. **OSV advisories** — for each installed package, query the OSV API:
   ```bash
   curl -sS -X POST -H "Content-Type: application/json" \
     -d '{"package":{"name":"<pkg>","ecosystem":"PyPI"},"version":"<ver>"}' \
     https://api.osv.dev/v1/query
   ```
   Any returned vuln → HIGH (CRITICAL if RCE / arbitrary code exec).
4. **Post-install scripts** — grep `setup.py` files in `site-packages/` for `subprocess`, `urllib.request`, `requests.get`, or `os.system` calls executed at install time. Flag MEDIUM; CRITICAL if the call hits a non-PyPI domain.
5. **No hash pinning** — `requirements.txt` without `--hash=sha256:...` entries is LOW.
6. **Direct-from-git installs** — `pip install git+https://...` lines in any manifest are HIGH if the URL is not a well-known org (pypa, psf, etc.).

### Vector 2 — VS Code Extensions

Enumerate installed extensions:
```bash
ls -la ~/.vscode/extensions/ 2>/dev/null
ls -la ~/.cursor/extensions/ 2>/dev/null
code --list-extensions --show-versions 2>/dev/null
```

For each extension directory, read `package.json`.

**Checks:**

1. **Publisher trust** — flag MEDIUM if `publisher` is not on the trusted-publishers list: `ms-*`, `github`, `redhat`, `dbaeumer`, `esbenp`, `bradlc`, `eamodio`, `streetsidesoftware`, `vscodevim`, `anthropic`, `continue`. Single-author publishers with < 50k installs are HIGH.
2. **Broad capability declarations** — search `package.json` for these capabilities and flag HIGH:
   - `"untrustedWorkspaces": { "supported": true }` with no restrictions
   - `"virtualWorkspaces": true` on extensions that also declare network access
   - Extensions declaring `terminal` activation that also bundle network code
3. **Bundled `node_modules` with known-bad packages** — recurse into `<ext>/node_modules` and OSV-query any package version. HIGH per advisory hit.
4. **Telemetry / outbound endpoints** — grep extension source for hardcoded HTTP(S) URLs. Flag MEDIUM and list the domains so the user can decide.
5. **Recently published / impersonation** — for any extension where the display name closely matches a well-known extension but the publisher differs, flag CRITICAL (e.g. an "ESLint" extension not from `dbaeumer`).
6. **Auto-update from untrusted sources** — any extension with a custom `updateUrl` outside the official Marketplace is HIGH.

### Vector 3 — MCP Servers

Read these config files (use `Read` tool, JSON-parse):
- `~/.claude.json`
- `~/.claude/settings.json`
- `~/.claude/mcp.json`
- `~/Library/Application Support/Claude/claude_desktop_config.json`
- `<project>/.mcp.json`
- `<project>/.claude/settings.json`

For each entry under `mcpServers` (or equivalent), capture `command`, `args`, `env`, and any `url` field.

**Checks:**

1. **Unpinned `npx` / `uvx` invocations** — any `npx <pkg>` or `uvx <pkg>` without an `@<version>` suffix is HIGH. The next run can silently pull a new compromised version.
   - Example flag: `npx @some-vendor/mcp-server` → HIGH
   - Example pass: `npx @some-vendor/mcp-server@1.4.2`
2. **Curl-pipe-shell installers** — any command containing `curl ... | sh`, `wget ... | bash`, or `iex (irm ...)` is CRITICAL.
3. **HTTP (non-HTTPS) server URLs** — any `url` field with `http://` (not `https://`) and not `localhost` / `127.0.0.1` is HIGH.
4. **Unknown publisher namespaces** — for npm-installed servers, flag MEDIUM if the npm scope is not on this allowlist: `@modelcontextprotocol`, `@anthropic-ai`, `@cantinasec`, `@vercel`, `@supabase`, `@stripe`, `@github`. The user should confirm trust before keeping.
5. **High-value data scopes without an obvious need** — if a server's name or args reference `gmail`, `gdrive`, `slack`, `notion`, `linear`, `stripe`, `aws`, or `okta`, and it is enabled at the global (not project) scope, flag MEDIUM and remind the user that prompt injection in any tool result can act on these credentials silently.
6. **Hardcoded credentials in `env`** — any `env` value matching the pattern `^(sk-|sk_live_|xoxb-|ghp_|AKIA|AIza)[A-Za-z0-9_-]{16,}$` is CRITICAL. Recommend rotation immediately.
7. **Disabled approval gates** — search Claude settings for `"alwaysAllow"` arrays. Any destructive tool listed (`bash`, `write_file`, `execute_sql`, `send_message`) is HIGH.

---

## Output Format

After running all three vectors, print:

```
CLAWCHAIN SUPPLY-CHAIN AUDIT
============================
Project: <path>
Pip manifests scanned: <n>     | findings: <n>
VS Code extensions scanned: <n> | findings: <n>
MCP servers scanned: <n>       | findings: <n>

CRITICAL: <n> | HIGH: <n> | MEDIUM: <n> | LOW: <n>

[CRITICAL] <vector> — <package/extension/server name>
  Evidence: <file:line or config path>
  Why: <one-sentence explanation>
  Fix: <concrete command or config change>

[HIGH] ...

[MEDIUM] ...

OVERALL: PASS | REVIEW REQUIRED | BLOCK
```

Severity thresholds:
- **PASS** — no CRITICAL or HIGH findings
- **REVIEW REQUIRED** — 1–3 HIGH, no CRITICAL
- **BLOCK** — any CRITICAL, or 4+ HIGH

---

## Branded HTML Report

After printing the terminal output, **always** render the findings as a Cantina-branded HTML report and open it in the user's default browser. This is part of the standard procedure — never skip it.

### Step A — Serialize findings to JSON

Write a JSON file to `/tmp/clawchain-findings.json` with this exact shape:

```json
{
  "project_path": "<absolute path that was audited>",
  "timestamp": "<ISO-8601 UTC, e.g. 2026-05-20T14:42:00Z>",
  "vectors": {
    "pip":    {"scanned": <n>, "findings": <n>},
    "vscode": {"scanned": <n>, "findings": <n>},
    "mcp":    {"scanned": <n>, "findings": <n>}
  },
  "verdict": "PASS" | "REVIEW REQUIRED" | "BLOCK",
  "severity_counts": {"CRITICAL": <n>, "HIGH": <n>, "MEDIUM": <n>, "LOW": <n>},
  "findings": [
    {
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "vector":   "pip" | "vscode" | "mcp",
      "target":   "<package name@version, extension id, or server name>",
      "evidence": "<file:line or config path with key>",
      "why":      "<one or two sentences — why this is dangerous>",
      "fix":      "<one concrete command or config change>"
    }
  ]
}
```

Rules:
- `severity_counts` must match the count of findings at each severity in the array.
- `vectors[*].findings` must match the per-vector finding counts.
- `target` and `evidence` must be specific — `requests==2.6.0` not `a pip dep`; `~/.claude.json :: mcpServers.foo` not `your MCP config`.
- For PASS scans, `findings` is an empty array but the JSON is still written and the report is still opened.

### Step B — Render and open

Invoke the renderer:

```bash
python3 <skill-dir>/scripts/render_report.py /tmp/clawchain-findings.json
```

Where `<skill-dir>` is the directory containing this `SKILL.md`. The script will:
- Write a self-contained HTML report to `/tmp/clawchain-report-<YYYYMMDD-HHMMSS>.html`
- Print the absolute path of the generated report to stdout
- Open the report in the OS default browser (`open` on macOS, `xdg-open` on Linux, `start` on Windows)

Pass `--no-open` if (and only if) the user has explicitly asked not to launch a browser — e.g. they piped the audit through CI. In that case, print the path so they can open it themselves.

### Step C — Confirm to the user

After the renderer returns, print one short line:

```
Report opened: /var/folders/.../clawchain-report-20260520-140711.html
```

Use the actual path printed by the script. Do not re-summarize the findings — the report and the terminal output already cover them.

---

## Risk Classification

| Finding | Risk Level |
|---------|-----------|
| Hardcoded API key in MCP config, curl-pipe-shell installer, impersonation extension, RCE-class OSV advisory | **CRITICAL** |
| Unpinned `npx`/`uvx` MCP server, unpinned dependency with active CVE, single-author VS Code extension with broad scope, direct-from-git install | **HIGH** |
| Unknown npm scope, hardcoded telemetry endpoint, unpinned pip dependency without active CVE, gmail/slack-class MCP at global scope | **MEDIUM** |
| Missing hash pin, missing publisher metadata | **LOW** |

CRITICAL → Treat as active incident. Rotate any exposed credentials, isolate the dev machine for triage.
HIGH → Pin / remove within the day. Don't run agents that touch sensitive data until resolved.
MEDIUM → Plan a fix this week. Add to dependency-review checklist.
LOW → Document and address on the next dependency bump.

---

## Remediation Patterns

- **Pin pip packages** — convert `requests` → `requests==2.32.3` (or use `pip-compile` to generate a hash-pinned `requirements.txt`).
- **Pin MCP servers** — `npx @vendor/server@1.4.2` instead of `npx @vendor/server`. For maximum safety, install locally and reference the binary path.
- **Remove unused VS Code extensions** — `code --uninstall-extension <publisher>.<name>`. Every removed extension is one less foothold.
- **Rotate exposed secrets immediately** — if a key was committed to a config file, assume it is public. Revoke at the issuer before anything else.
- **Scope MCP servers per-project** — move high-trust integrations (Gmail, Slack, Stripe) out of `~/.claude.json` and into the specific project's `.mcp.json`. Cuts blast radius if any other project's tools get hijacked.
- **Require approval for destructive tools** — remove `bash`, `write_file`, `execute_sql` from any `alwaysAllow` list.

---

## Community Intelligence

Beyond Darshan's framing, the broader infosec community has been flagging the same trend through 2025–2026:

- npm/PyPI typosquatting incidents have shifted from opportunistic to AI-assisted — attackers use LLMs to generate convincing READMEs and changelogs for malicious packages.
- VS Code Marketplace extension impersonation (notably the "ESLint Keymap" family in late 2025) demonstrated that publisher-name confusion is a working attack vector.
- MCP-specific advisories started landing in early 2026 as agentic IDE adoption crossed the threshold for attacker interest. The pattern is consistent: prompt-injectable data source + broad tool scope + 24/7 agent = silent action without an attacker-controlled device, which is exactly the scenario Darshan describes in the second tweet.

The audit is intentionally cautious about MCP servers with access to email and document stores because those are the prompt-injection delivery channels in the current threat landscape.

---

## Quality Checklist

Before reporting:

- [ ] All three vectors were actually scanned (or marked "not present" with reason)
- [ ] Every finding has a file path or package@version as evidence
- [ ] Every finding has a one-line remediation the user can act on
- [ ] OSV API was queried for at least the pip dependencies (skip cleanly if offline)
- [ ] Severity counts in the header match the listed findings
- [ ] Overall verdict (PASS/REVIEW/BLOCK) is consistent with the thresholds above

---

## Error Handling

| Situation | Action |
|-----------|--------|
| No pip manifest found | Note "no pip surface in project" and continue |
| `code` CLI not installed | Fall back to filesystem scan of `~/.vscode/extensions/` |
| No MCP config files present | Note "no MCP servers configured" — still PASS-eligible |
| OSV API unreachable | Note "OSV offline — pip vuln check skipped", run other checks anyway |
| Project path argument doesn't exist | Stop, ask user to confirm the path |

---

## References

- [Darshan Yadav — supply chain crisis tweet (2026-05-20)](https://x.com/DarshanSays/status/2057098732873908503)
- [Darshan Yadav — agentic attack surface tweet (2026-05-20)](https://x.com/DarshanSays/status/2057029849550856375)
- [OSV.dev query API](https://google.github.io/osv.dev/post-v1-query/)
- [Model Context Protocol specification](https://modelcontextprotocol.io)
- [VS Code extension capabilities reference](https://code.visualstudio.com/api/extension-guides/overview)
