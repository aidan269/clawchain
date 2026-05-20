#!/usr/bin/env python3
"""
clawchain report renderer.

Reads a findings JSON file, renders a self-contained Cantina-branded HTML
report, writes it to a timestamped path under the system temp dir, and
opens it in the default browser.

Usage:
    python3 render_report.py <findings.json> [--no-open]
    cat findings.json | python3 render_report.py - [--no-open]

Findings JSON shape:
{
  "project_path": "/path/audited",
  "timestamp": "2026-05-20T14:15:30Z",   # optional; auto-filled if missing
  "vectors": {
    "pip":    {"scanned": N, "findings": N},
    "vscode": {"scanned": N, "findings": N},
    "mcp":    {"scanned": N, "findings": N}
  },
  "verdict": "PASS" | "REVIEW REQUIRED" | "BLOCK",
  "severity_counts": {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N},
  "findings": [
    {"severity": "...", "vector": "pip|vscode|mcp",
     "target": "...", "evidence": "...", "why": "...", "fix": "..."}
  ]
}
"""
from __future__ import annotations

import argparse
import datetime as _dt
import html
import json
import pathlib
import subprocess
import sys
import tempfile


SEVERITY_COLORS = {
    "CRITICAL": "#ff3b30",
    "HIGH":     "#ff9500",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#8e8e93",
}

VERDICT_COLORS = {
    "PASS":            "#34c759",
    "REVIEW REQUIRED": "#ff9500",
    "BLOCK":           "#ff3b30",
}

VECTOR_LABELS = {
    "pip":    "pip packages",
    "vscode": "VS Code extensions",
    "mcp":    "MCP servers",
}


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _badge(label: str, color: str, size: str = "md") -> str:
    pad = "4px 10px" if size == "sm" else "6px 14px"
    fs = "11px" if size == "sm" else "13px"
    return (
        f'<span style="display:inline-block;padding:{pad};border-radius:999px;'
        f'background:{color};color:#06060a;font-weight:700;font-size:{fs};'
        f'letter-spacing:0.04em;">{_esc(label)}</span>'
    )


def _vector_card(key: str, data: dict) -> str:
    scanned = data.get("scanned", 0)
    findings = data.get("findings", 0)
    label = VECTOR_LABELS.get(key, key)
    return f"""
      <div class="vector-card">
        <div class="vector-label">{_esc(label)}</div>
        <div class="vector-numbers">
          <div><span class="num">{scanned}</span><span class="unit">scanned</span></div>
          <div><span class="num">{findings}</span><span class="unit">findings</span></div>
        </div>
      </div>
    """


def _remediation_block(rem: dict | None) -> str:
    if not rem:
        return ""
    return f"""
        <div class="remediation">
          <div class="rem-tag">AI remediation</div>
          <div class="rem-card rem-root">
            <div class="rem-label">Root cause</div>
            <div class="rem-text">{_esc(rem.get('root_cause', '—'))}</div>
          </div>
          <div class="rem-card rem-prevent">
            <div class="rem-label">Prevention</div>
            <div class="rem-text">{_esc(rem.get('prevention', '—'))}</div>
          </div>
        </div>
    """


def _finding_card(f: dict) -> str:
    sev = (f.get("severity") or "LOW").upper()
    color = SEVERITY_COLORS.get(sev, "#8e8e93")
    vector_label = VECTOR_LABELS.get(f.get("vector", ""), f.get("vector", "—"))
    return f"""
      <article class="finding" style="border-left-color:{color};">
        <header class="finding-head">
          {_badge(sev, color)}
          <span class="finding-vector">{_esc(vector_label)}</span>
          <span class="finding-target">{_esc(f.get('target', '—'))}</span>
        </header>
        <dl class="finding-body">
          <dt>Evidence</dt><dd><code>{_esc(f.get('evidence', '—'))}</code></dd>
          <dt>Why</dt><dd>{_esc(f.get('why', '—'))}</dd>
          <dt>Fix</dt><dd>{_esc(f.get('fix', '—'))}</dd>
        </dl>
        {_remediation_block(f.get('remediation'))}
      </article>
    """


def render(findings: dict) -> str:
    ts = findings.get("timestamp") or _dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    project = findings.get("project_path", "—")
    verdict = (findings.get("verdict") or "PASS").upper()
    verdict_color = VERDICT_COLORS.get(verdict, "#8e8e93")
    vectors = findings.get("vectors", {})
    counts = findings.get("severity_counts", {})
    items = findings.get("findings", []) or []

    # Sort findings: CRITICAL → HIGH → MEDIUM → LOW
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    items_sorted = sorted(items, key=lambda x: order.get((x.get("severity") or "LOW").upper(), 4))

    findings_html = (
        "\n".join(_finding_card(f) for f in items_sorted)
        if items_sorted
        else '<div class="empty">No findings. Supply chain looks clean for this scope.</div>'
    )

    sev_pills = "".join(
        f'<div class="sev-pill"><span class="sev-num" style="color:{SEVERITY_COLORS[s]}">{counts.get(s, 0)}</span>'
        f'<span class="sev-label">{s}</span></div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>clawchain report — {_esc(project)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root {{
    --brand:    #F05E00;
    --bg:       #06060a;
    --surface:  rgba(255,255,255,0.06);
    --border:   rgba(255,255,255,0.11);
    --text:     #f4f4f5;
    --muted:    #a1a1aa;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{
    margin: 0;
    background:
      radial-gradient(ellipse 80% 60% at 85% 0%, rgba(240,94,0,0.18) 0%, transparent 65%),
      radial-gradient(ellipse 60% 50% at 10% 95%, rgba(100,80,220,0.10) 0%, transparent 60%),
      var(--bg);
    background-attachment: fixed;
    color: var(--text);
    font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    -webkit-font-smoothing: antialiased;
  }}
  .wrap {{ max-width: 980px; margin: 0 auto; padding: 48px 24px 64px; }}

  header.brandbar {{
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 28px;
  }}
  .brand {{ display: flex; align-items: baseline; gap: 12px; }}
  .brand-mark {{
    font-size: 18px; font-weight: 800; color: var(--brand); letter-spacing: 0.08em;
  }}
  .brand-sub {{ color: var(--muted); font-size: 13px; letter-spacing: 0.04em; }}
  .ts {{ color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums; }}

  .hero {{
    background: var(--surface); border: 1px solid var(--border); border-radius: 18px;
    padding: 32px; margin-bottom: 28px;
    backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
    box-shadow: 0 4px 32px rgba(0,0,0,0.45), inset 0 1px 0 rgba(255,255,255,0.06);
  }}
  .hero-row {{ display: flex; align-items: center; justify-content: space-between; gap: 24px; flex-wrap: wrap; }}
  .hero-title {{ font-size: 28px; font-weight: 700; margin: 0 0 4px; }}
  .hero-project {{ color: var(--muted); font-size: 14px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }}
  .verdict {{
    display: inline-flex; align-items: center; gap: 10px;
    padding: 12px 22px; border-radius: 14px;
    background: {verdict_color}; color: #06060a;
    font-weight: 800; font-size: 18px; letter-spacing: 0.06em;
    box-shadow: 0 6px 20px rgba(0,0,0,0.35);
  }}

  .sev-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 24px; }}
  .sev-pill {{
    background: rgba(0,0,0,0.35); border: 1px solid var(--border); border-radius: 12px;
    padding: 14px 16px; display: flex; flex-direction: column; gap: 4px;
  }}
  .sev-num {{ font-size: 28px; font-weight: 800; font-variant-numeric: tabular-nums; line-height: 1; }}
  .sev-label {{ font-size: 11px; color: var(--muted); letter-spacing: 0.08em; }}

  .vectors {{
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 28px;
  }}
  .vector-card {{
    background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
    padding: 18px 20px;
    backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
  }}
  .vector-label {{ font-size: 11px; color: var(--muted); letter-spacing: 0.10em; text-transform: uppercase; margin-bottom: 10px; }}
  .vector-numbers {{ display: flex; gap: 24px; }}
  .vector-numbers .num {{ font-size: 22px; font-weight: 700; font-variant-numeric: tabular-nums; }}
  .vector-numbers .unit {{ display: block; font-size: 11px; color: var(--muted); }}

  h2.section {{
    font-size: 13px; color: var(--muted); letter-spacing: 0.12em; text-transform: uppercase;
    margin: 0 0 12px;
  }}

  .finding {{
    background: var(--surface); border: 1px solid var(--border);
    border-left: 4px solid var(--brand); border-radius: 12px;
    padding: 18px 22px; margin-bottom: 12px;
    backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
  }}
  .finding-head {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }}
  .finding-vector {{ color: var(--muted); font-size: 12px; letter-spacing: 0.04em; text-transform: uppercase; }}
  .finding-target {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 14px; word-break: break-all; }}
  .finding-body {{ margin: 0; display: grid; grid-template-columns: 80px 1fr; gap: 6px 16px; }}
  .finding-body dt {{ color: var(--muted); font-size: 12px; padding-top: 2px; }}
  .finding-body dd {{ margin: 0; font-size: 14px; line-height: 1.5; }}
  .finding-body code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px;
    background: rgba(0,0,0,0.4); padding: 2px 6px; border-radius: 4px;
  }}

  .empty {{
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 28px; text-align: center; color: var(--muted);
  }}

  .remediation {{
    margin-top: 16px; padding-top: 14px;
    border-top: 1px solid var(--border);
    display: grid; gap: 8px;
  }}
  .rem-tag {{
    font-size: 10px; color: var(--brand); letter-spacing: 0.14em;
    text-transform: uppercase; font-weight: 700;
    display: inline-flex; align-items: center; gap: 6px;
    margin-bottom: 2px;
  }}
  .rem-tag::before {{
    content: ""; width: 6px; height: 6px; border-radius: 50%;
    background: var(--brand);
    box-shadow: 0 0 12px var(--brand);
  }}
  .rem-card {{
    background: rgba(0,0,0,0.32);
    border: 1px solid var(--border); border-radius: 10px;
    border-left: 3px solid var(--border);
    padding: 12px 14px;
  }}
  .rem-root      {{ border-left-color: #5e5cff; }}
  .rem-prevent   {{ border-left-color: #34c759; }}
  .rem-label {{
    font-size: 10px; color: var(--muted); letter-spacing: 0.10em;
    text-transform: uppercase; font-weight: 700; margin-bottom: 4px;
  }}
  .rem-text {{
    font-size: 13.5px; line-height: 1.55; color: var(--text);
  }}
  .rem-text code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
    background: rgba(0,0,0,0.4); padding: 1px 5px; border-radius: 3px;
  }}

  footer {{
    margin-top: 32px; padding-top: 24px;
    border-top: 1px solid var(--border);
    color: var(--muted); font-size: 12px; line-height: 1.6;
  }}
  footer a {{ color: var(--brand); text-decoration: none; }}
  footer a:hover {{ text-decoration: underline; }}

  @media (max-width: 720px) {{
    .sev-row {{ grid-template-columns: repeat(2, 1fr); }}
    .vectors {{ grid-template-columns: 1fr; }}
    .hero-row {{ flex-direction: column; align-items: flex-start; }}
  }}
</style>
</head>
<body>
<div class="wrap">

  <header class="brandbar">
    <div class="brand">
      <span class="brand-mark">CANTINA · SECURITY</span>
      <span class="brand-sub">clawchain · supply-chain audit</span>
    </div>
    <span class="ts">{_esc(ts)}</span>
  </header>

  <section class="hero">
    <div class="hero-row">
      <div>
        <h1 class="hero-title">Supply-Chain Audit</h1>
        <div class="hero-project">{_esc(project)}</div>
      </div>
      <div class="verdict">{_esc(verdict)}</div>
    </div>
    <div class="sev-row">
      {sev_pills}
    </div>
  </section>

  <h2 class="section">Vectors scanned</h2>
  <div class="vectors">
    {_vector_card("pip", vectors.get("pip", {}))}
    {_vector_card("vscode", vectors.get("vscode", {}))}
    {_vector_card("mcp", vectors.get("mcp", {}))}
  </div>

  <h2 class="section">Findings ({len(items_sorted)})</h2>
  {findings_html}

  <footer>
    Generated by <strong style="color:var(--brand);">clawchain</strong> ·
    <a href="https://github.com/aidan269/clawchain">github.com/aidan269/clawchain</a><br>
    Built from <a href="https://x.com/DarshanSays/status/2057098732873908503">@DarshanSays · 2026-05-20</a>:
    "Every VS Code extension, pip package, and MCP server is a potential entry point."
  </footer>

</div>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("findings_path", help="Path to findings JSON, or '-' for stdin")
    parser.add_argument("--out", help="Output HTML path (default: temp file)", default=None)
    parser.add_argument("--no-open", action="store_true", help="Skip launching the browser")
    args = parser.parse_args()

    if args.findings_path == "-":
        findings = json.load(sys.stdin)
    else:
        findings = json.loads(pathlib.Path(args.findings_path).read_text())

    html_doc = render(findings)

    if args.out:
        out = pathlib.Path(args.out)
    else:
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        out = pathlib.Path(tempfile.gettempdir()) / f"clawchain-report-{stamp}.html"
    out.write_text(html_doc, encoding="utf-8")

    print(str(out))

    if not args.no_open:
        if sys.platform == "darwin":
            subprocess.run(["open", str(out)], check=False)
        elif sys.platform.startswith("linux"):
            subprocess.run(["xdg-open", str(out)], check=False)
        elif sys.platform == "win32":
            subprocess.run(["cmd", "/c", "start", "", str(out)], check=False, shell=False)


if __name__ == "__main__":
    main()
