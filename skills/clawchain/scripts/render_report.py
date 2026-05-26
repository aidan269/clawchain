#!/usr/bin/env python3
"""
clawchain breakdown renderer.

Reads a warnings JSON file, renders a self-contained Cantina-branded HTML
breakdown, writes it to a timestamped path under the system temp dir, and
opens it in the default browser.

Clawchain is a heads-up tool, not a security audit. The output surfaces
patterns in dependencies that may be worth a closer look; it does not
issue findings, verdicts, or audit conclusions.

The generated HTML includes:
- A "Print / Save as PDF" button (calls window.print() — print CSS strips
  the toolbar, CTA, and decorative backgrounds for clean PDFs)
- A "Download JSON" button (embeds the raw warnings JSON as a data URI
  so the user can re-feed it to another tool)

Usage:
    python3 render_report.py <warnings.json> [--no-open]
    cat warnings.json | python3 render_report.py - [--no-open]

Warnings JSON shape:
{
  "project_path": "/path/scanned",
  "timestamp": "2026-05-20T14:15:30Z",   # optional; auto-filled if missing
  "vectors": {
    "pip":    {"scanned": N, "warnings": N},
    "vscode": {"scanned": N, "warnings": N},
    "mcp":    {"scanned": N, "warnings": N}
  },
  "concern_counts": {"high": N, "medium": N, "low": N},
  "warnings": [
    {"concern": "high|medium|low", "vector": "pip|vscode|mcp",
     "target": "...", "evidence": "...", "why": "...", "suggested_fix": "..."}
  ]
}
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import html
import json
import pathlib
import subprocess
import sys
import tempfile


# Atlas catalog + BD email funnel hooks. Replace when contact preferences
# or the Atlas catalog change.
ATLAS_BASE_URL = "https://atlas.cantinasec.com/mcp"
CONTACT_EMAIL = "aidan@spearbit.com"


CONCERN_COLORS = {
    "high":   "#ff9500",
    "medium": "#ffcc00",
    "low":    "#8e8e93",
}

CONCERN_LABELS = {
    "high":   "Worth checking soon",
    "medium": "Worth checking",
    "low":    "Minor pattern to note",
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
    # Accept both new ("warnings") and legacy ("findings") keys for safety.
    warnings = data.get("warnings", data.get("findings", 0))
    label = VECTOR_LABELS.get(key, key)
    return f"""
      <div class="vector-card">
        <div class="vector-label">{_esc(label)}</div>
        <div class="vector-numbers">
          <div><span class="num">{scanned}</span><span class="unit">scanned</span></div>
          <div><span class="num">{warnings}</span><span class="unit">warnings</span></div>
        </div>
      </div>
    """


def _context_block(rem: dict | None) -> str:
    if not rem:
        return ""
    return f"""
        <div class="remediation">
          <div class="rem-tag">Suggested context</div>
          <div class="rem-card rem-root">
            <div class="rem-label">Possible reason this slipped in</div>
            <div class="rem-text">{_esc(rem.get('root_cause', '—'))}</div>
          </div>
          <div class="rem-card rem-prevent">
            <div class="rem-label">Something that might prevent it next time</div>
            <div class="rem-text">{_esc(rem.get('prevention', '—'))}</div>
          </div>
        </div>
    """


def _atlas_link(f: dict) -> str:
    """Render an Atlas catalog link for MCP warnings if atlas_url is present."""
    if f.get("vector") != "mcp":
        return ""
    url = f.get("atlas_url")
    if not url:
        return ""
    return f"""
        <a class="atlas-link" href="{_esc(url)}" target="_blank" rel="noopener">
          <span class="atlas-icon">◎</span>
          <span>Read the Atlas entry</span>
          <span class="atlas-arrow">→</span>
        </a>
    """


def _warning_card(f: dict) -> str:
    # Accept the new "concern" field; fall back to legacy "severity" if older
    # producers emit it. Map legacy CRITICAL down to high — we no longer
    # distinguish the two.
    concern_raw = (f.get("concern") or f.get("severity") or "low").lower()
    if concern_raw == "critical":
        concern_raw = "high"
    concern = concern_raw if concern_raw in CONCERN_COLORS else "low"
    color = CONCERN_COLORS[concern]
    concern_label = CONCERN_LABELS[concern]
    vector_label = VECTOR_LABELS.get(f.get("vector", ""), f.get("vector", "—"))
    fix_text = f.get("suggested_fix") or f.get("fix", "—")
    return f"""
      <article class="finding" style="border-left-color:{color};">
        <header class="finding-head">
          {_badge(concern_label, color)}
          <span class="finding-vector">{_esc(vector_label)}</span>
          <span class="finding-target">{_esc(f.get('target', '—'))}</span>
        </header>
        <dl class="finding-body">
          <dt>What we saw</dt><dd><code>{_esc(f.get('evidence', '—'))}</code></dd>
          <dt>Why it caught our eye</dt><dd>{_esc(f.get('why', '—'))}</dd>
          <dt>One thing you could do</dt><dd>{_esc(fix_text)}</dd>
        </dl>
        {_context_block(f.get('remediation'))}
        {_atlas_link(f)}
      </article>
    """


def render(findings: dict) -> str:
    ts = findings.get("timestamp") or _dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    project = findings.get("project_path", "—")
    vectors = findings.get("vectors", {})

    # Embed a copy of the JSON as a data: URI so the "Download JSON" button
    # works offline with no server roundtrip.
    json_blob = json.dumps(findings, indent=2)
    json_b64 = base64.b64encode(json_blob.encode("utf-8")).decode("ascii")
    json_data_uri = f"data:application/json;base64,{json_b64}"
    download_stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")

    # Accept new keys (concern_counts, warnings) and fall back to legacy ones
    # (severity_counts, findings) so older producers still render.
    counts_raw = findings.get("concern_counts") or findings.get("severity_counts") or {}
    counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for k, v in counts_raw.items():
        kl = k.lower()
        if kl == "critical":
            counts["high"] = counts.get("high", 0) + int(v or 0)
        elif kl in counts:
            counts[kl] = counts.get(kl, 0) + int(v or 0)

    items = findings.get("warnings") or findings.get("findings") or []

    def _concern_key(x: dict) -> str:
        raw = (x.get("concern") or x.get("severity") or "low").lower()
        if raw == "critical":
            raw = "high"
        return raw if raw in CONCERN_COLORS else "low"

    order = {"high": 0, "medium": 1, "low": 2}
    items_sorted = sorted(items, key=lambda x: order.get(_concern_key(x), 3))
    total = len(items_sorted)

    findings_html = (
        "\n".join(_warning_card(f) for f in items_sorted)
        if items_sorted
        else '<div class="empty">Nothing unusual surfaced in this scope. That doesn\'t mean everything is safe — just that clawchain didn\'t spot any of the patterns it watches for.</div>'
    )

    sev_pills = "".join(
        f'<div class="sev-pill"><span class="sev-num" style="color:{CONCERN_COLORS[s]}">{counts.get(s, 0)}</span>'
        f'<span class="sev-label">{s.capitalize()}</span></div>'
        for s in ("high", "medium", "low")
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>clawchain breakdown — {_esc(project)}</title>
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
  .totals {{
    display: inline-flex; align-items: baseline; gap: 8px;
    color: var(--muted); font-size: 14px;
  }}
  .totals strong {{
    color: var(--text); font-size: 22px; font-weight: 700;
    font-variant-numeric: tabular-nums;
  }}

  .sev-row {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 24px; }}
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

  .atlas-link {{
    display: inline-flex; align-items: center; gap: 8px;
    margin-top: 14px; padding: 8px 14px;
    background: rgba(240,94,0,0.08);
    border: 1px solid rgba(240,94,0,0.28);
    border-radius: 999px;
    color: var(--brand); text-decoration: none;
    font-size: 12px; font-weight: 600; letter-spacing: 0.04em;
    transition: background 0.15s, border-color 0.15s;
  }}
  .atlas-link:hover {{
    background: rgba(240,94,0,0.15);
    border-color: rgba(240,94,0,0.45);
  }}
  .atlas-icon {{ font-size: 13px; line-height: 1; }}
  .atlas-arrow {{ font-size: 14px; line-height: 1; }}

  .cta {{
    margin: 32px 0 16px;
    background: linear-gradient(135deg, rgba(240,94,0,0.10), rgba(100,80,220,0.06));
    border: 1px solid rgba(240,94,0,0.25);
    border-radius: 14px;
    padding: 20px 24px;
    display: flex; align-items: center; justify-content: space-between; gap: 18px; flex-wrap: wrap;
  }}
  .cta-text {{ flex: 1; min-width: 260px; }}
  .cta-title {{
    font-size: 15px; font-weight: 700; color: var(--text);
    margin: 0 0 4px;
  }}
  .cta-sub {{ font-size: 13px; color: var(--muted); line-height: 1.5; }}
  .cta-btn {{
    display: inline-flex; align-items: center; gap: 8px;
    background: var(--brand); color: #06060a;
    padding: 10px 18px; border-radius: 10px;
    font-size: 13px; font-weight: 700; letter-spacing: 0.04em;
    text-decoration: none;
    transition: transform 0.15s, box-shadow 0.15s;
  }}
  .cta-btn:hover {{
    transform: translateY(-1px);
    box-shadow: 0 6px 16px rgba(240,94,0,0.35);
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

  /* Toolbar (Print + Download JSON) */
  .toolbar {{
    display: flex; gap: 8px; flex-wrap: wrap;
    margin-bottom: 16px;
  }}
  .toolbar a, .toolbar button {{
    display: inline-flex; align-items: center; gap: 6px;
    background: rgba(255,255,255,0.04);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 7px 14px;
    border-radius: 8px;
    font-size: 12px; font-weight: 600; letter-spacing: 0.04em;
    text-decoration: none; cursor: pointer;
    font-family: inherit;
    transition: background 0.15s, border-color 0.15s;
  }}
  .toolbar a:hover, .toolbar button:hover {{
    background: rgba(240,94,0,0.10);
    border-color: rgba(240,94,0,0.32);
  }}

  /* Print rules — strip toolbar, CTA, and decorative backgrounds for clean PDFs */
  @media print {{
    html, body {{
      background: white !important;
      color: #06060a !important;
    }}
    .wrap {{ padding: 16px 0 0; max-width: none; }}
    .toolbar, .cta {{ display: none !important; }}
    .brandbar {{ margin-bottom: 12px; }}
    .brand-mark {{ color: #F05E00 !important; }}
    .brand-sub, .ts {{ color: #555 !important; }}
    .hero, .vector-card, .finding, .rem-card, .empty {{
      background: white !important;
      border-color: #d0d0d0 !important;
      box-shadow: none !important;
      backdrop-filter: none !important;
      -webkit-backdrop-filter: none !important;
    }}
    .hero-title, .hero-project, .finding-target, .finding-body dd,
    .rem-text, .vector-numbers .num {{
      color: #06060a !important;
    }}
    .vector-label, .finding-vector, .finding-body dt, .vector-numbers .unit,
    .rem-label, .sev-label {{
      color: #555 !important;
    }}
    .finding-body code, .rem-text code {{
      background: #f3f3f3 !important;
      color: #06060a !important;
      border: 1px solid #e0e0e0;
    }}
    .totals strong {{ color: #06060a !important; }}
    .atlas-link {{
      background: white !important;
      color: #F05E00 !important;
      border: 1px solid rgba(240,94,0,0.5) !important;
    }}
    .finding, .vector-card {{
      page-break-inside: avoid;
    }}
    footer {{
      color: #555 !important;
      border-top: 1px solid #d0d0d0 !important;
    }}
    footer a {{ color: #F05E00 !important; }}
  }}
</style>
</head>
<body>
<div class="wrap">

  <header class="brandbar">
    <div class="brand">
      <span class="brand-mark">CANTINA · SECURITY</span>
      <span class="brand-sub">clawchain · dependency breakdown</span>
    </div>
    <span class="ts">{_esc(ts)}</span>
  </header>

  <div class="toolbar">
    <button type="button" onclick="window.print()">⎙ Print / Save as PDF</button>
    <a href="{json_data_uri}" download="clawchain-breakdown-{download_stamp}.json">⤓ Download JSON</a>
  </div>

  <section class="hero">
    <div class="hero-row">
      <div>
        <h1 class="hero-title">Dependency breakdown</h1>
        <div class="hero-project">{_esc(project)}</div>
      </div>
      <div class="totals"><strong>{total}</strong> {('thing' if total == 1 else 'things')} worth a closer look</div>
    </div>
    <div class="sev-row">
      {sev_pills}
    </div>
  </section>

  <h2 class="section">Where we looked</h2>
  <div class="vectors">
    {_vector_card("pip", vectors.get("pip", {}))}
    {_vector_card("vscode", vectors.get("vscode", {}))}
    {_vector_card("mcp", vectors.get("mcp", {}))}
  </div>

  <h2 class="section">What's worth a closer look ({total})</h2>
  {findings_html}

  <div class="cta">
    <div class="cta-text">
      <div class="cta-title">Want to talk through anything you saw here?</div>
      <div class="cta-sub">Clawchain is a heads-up tool — it points at patterns, you decide what to do. If something in this breakdown looks worth a closer conversation, drop us a line. We can help you triage. No commitment.</div>
    </div>
    <a class="cta-btn" href="mailto:{CONTACT_EMAIL}?subject=clawchain%20breakdown" rel="noopener">
      Email us <span>→</span>
    </a>
  </div>

  <footer>
    <p style="margin: 0 0 14px; color: var(--text); font-size: 13px; line-height: 1.6;">
      <strong style="color: var(--brand);">Clawchain is a heads-up tool, not a security audit.</strong>
      It surfaces patterns in your dependencies that may be worth a closer look — it doesn't issue findings,
      verdicts, or audit conclusions. The judgment about whether each pattern is actually a problem is yours.
      For a managed assessment, consider AgentSight.
    </p>
    Generated by <strong style="color:var(--brand);">clawchain</strong> ·
    <a href="https://github.com/aidan269/clawchain">github.com/aidan269/clawchain</a><br>
    Inspired by <a href="https://x.com/DarshanSays/status/2057098732873908503">@DarshanSays · 2026-05-20</a>:
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
        out = pathlib.Path(tempfile.gettempdir()) / f"clawchain-breakdown-{stamp}.html"
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
