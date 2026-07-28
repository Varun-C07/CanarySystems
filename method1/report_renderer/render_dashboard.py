"""
render_dashboard.py

Renders a single self-contained HTML dashboard combining:
  - output/machine_report.json (required) -- failed_rules, top_attack_targets, full_graph
  - output/verdict.json (optional) -- Method 2's PROVEN exfiltration results
  - output/ai_remediation.md (optional) -- Remediation advice

Reuses graph_builder/render_graph.py's node-annotation logic and categorical
color palette directly (imported, not duplicated) rather than rebuilding the
blast-radius graph from scratch; the D3 force-simulation approach mirrors
render_graph.py's too, restyled with crisp, compact nodes, legible labels,
interactive controls, animated flow links, and search filters.

Usage:
    python render_dashboard.py [/path/to/output/dir]
Output:
    <output_dir>/dashboard.html  (defaults to <project_root>/output)
"""

import html
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from method1.graph_builder.render_graph import TYPE_COLORS, _annotate_nodes, _safe_json_for_script
from method2.attack_payloads.payloads import ALL_PAYLOAD_TYPES

PRODUCT_NAME = "CanarySystems"
TAGLINE = "Prove it, don't guess it"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_ACRONYM_WORDS = {"dns", "http"}


def _prettify_snake_case(s: str) -> str:
    words = s.lower().split("_")
    parts = []
    for i, w in enumerate(words):
        if w in _ACRONYM_WORDS:
            parts.append(w.upper())
        elif i == 0:
            parts.append(w.capitalize())
        else:
            parts.append(w)
    return " ".join(parts)


ATTACK_TYPE_LABELS = {key: _prettify_snake_case(key) for key in ALL_PAYLOAD_TYPES}
ATTACK_TYPE_LABELS["unknown"] = "Unknown"

CHANNEL_LABELS = {}
for _attack_type, _payload_fn in ALL_PAYLOAD_TYPES.items():
    _channel = _payload_fn("DUMMY_KEY").get("exfil_channel")
    if _channel and _channel not in CHANNEL_LABELS:
        CHANNEL_LABELS[_channel] = _prettify_snake_case(_channel)


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _load_json_or_exit(path: Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[dashboard] ERROR: {path} contains invalid JSON ({e}).")
        print(f"[dashboard] It may be corrupted or from an interrupted run -- "
              f"re-run the step that produces it.")
        sys.exit(1)


def _warn_if_stale(reference_path: Path, dependent_path: Path, dependent_label: str, tool_hint: str):
    try:
        if dependent_path.stat().st_mtime < reference_path.stat().st_mtime:
            print(f"[dashboard] WARNING: {dependent_label} ({dependent_path}) is OLDER than "
                  f"{reference_path.name} -- it may be from a previous scan run and not "
                  f"correspond to the findings in this report. Consider re-running '{tool_hint}'.")
    except OSError:
        pass


def _prettify_rule_name(rule: str) -> str:
    return rule.replace("_", " ").title()


def _highest_severity(failed_rules: list) -> str:
    present = {f.get("severity") for f in failed_rules}
    for sev in SEVERITY_ORDER:
        if sev in present:
            return sev
    return "info"


def _risk_badge_html(highest_sev: str, has_findings: bool) -> str:
    if not has_findings:
        return '<span class="risk-badge risk-low"><span class="badge-dot"></span>No findings</span>'
    label = f"{highest_sev.capitalize()} Exposure"
    return f'<span class="risk-badge risk-{_esc(highest_sev)}"><span class="badge-dot"></span>{_esc(label)}</span>'


def _severity_badge_html(sev: str) -> str:
    return f'<span class="badge badge-{_esc(sev)}">{_esc(sev.upper())}</span>'


def _render_stat_cards(failed_rules: list, verdict: dict) -> str:
    total = len(failed_rules)
    critical = sum(1 for f in failed_rules if f.get("severity") == "critical")
    high = sum(1 for f in failed_rules if f.get("severity") == "high")

    if verdict:
        leaked = verdict.get("summary", {}).get("leaked", 0)
        tested = verdict.get("summary", {}).get("total_credentials_tested", 0)
        creds_value = f"{leaked} / {tested}"
        leaked_card_class = "stat-critical" if leaked > 0 else "stat-safe"
    else:
        creds_value = "N/A"
        leaked_card_class = ""

    return f"""
    <section class="stats-row">
      <div class="stat-card">
        <div class="stat-header">
          <span class="stat-label">Static Findings</span>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <div class="stat-value">{total}</div>
        <div class="stat-sub">Rule checks failed</div>
      </div>
      <div class="stat-card stat-critical">
        <div class="stat-header">
          <span class="stat-label">Critical Risks</span>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        </div>
        <div class="stat-value">{critical}</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card stat-high">
        <div class="stat-header">
          <span class="stat-label">High Severity</span>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        </div>
        <div class="stat-value">{high}</div>
        <div class="stat-sub">High vulnerability impact</div>
      </div>
      <div class="stat-card {leaked_card_class}">
        <div class="stat-header">
          <span class="stat-label">Credentials Leaked</span>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        </div>
        <div class="stat-value">{_esc(creds_value)}</div>
        <div class="stat-sub">Proven exfiltrated in sandbox</div>
      </div>
    </section>
    """


def _render_findings_list(failed_rules: list) -> str:
    if not failed_rules:
        return '<p class="empty-state">No failed checks — every static rule passed cleanly.</p>'

    ordered = sorted(
        failed_rules,
        key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f.get("severity") in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )

    cards = []
    for idx, f in enumerate(ordered):
        cards.append(f"""
        <div class="finding-card border-sev-{_esc(f.get('severity', 'info'))}">
          <div class="finding-head">
            {_severity_badge_html(f.get('severity', 'info'))}
            <span class="finding-title">{_esc(_prettify_rule_name(f.get('rule', 'unknown')))}</span>
            <span class="finding-cat">{_esc(f.get('category', 'general'))}</span>
          </div>
          <p class="finding-desc">{_esc(f.get('finding', ''))}</p>
          <details class="finding-fix">
            <summary>
              <span>Remediation Fix</span>
              <svg class="chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 9 6 6 6-6"/></svg>
            </summary>
            <div class="fix-content">
              <code>{_esc(f.get('fix') or 'No fix text available.')}</code>
              <button class="copy-btn" onclick="copyText('{_esc(f.get('fix') or '').replace("'", "\\'")}', this)">Copy Fix</button>
            </div>
          </details>
        </div>
        """)
    return '<div class="findings-list">' + "".join(cards) + "</div>"


def _render_attack_table(verdict: dict) -> str:
    results = verdict.get("results", [])
    if not results:
        return '<p class="empty-state">No credentials were tested in this run.</p>'

    rows = []
    for r in results:
        cred = r.get("credential", "unknown")
        fired = r.get("fired", False)
        ev = r.get("evidence") or {}
        attack_type_raw = ev.get("attack_type", "")
        channel_raw = ev.get("leak_channel", "")
        attack_type = ATTACK_TYPE_LABELS.get(attack_type_raw, attack_type_raw.replace("_", " ").capitalize() if attack_type_raw else "—")
        channel = CHANNEL_LABELS.get(channel_raw, channel_raw.replace("_", " ").capitalize() if channel_raw else "—")
        status_badge = (
            '<span class="badge badge-critical pulse-glow"><span class="badge-dot"></span>LEAKED</span>' if fired
            else '<span class="badge badge-low"><span class="badge-dot"></span>SAFE</span>'
        )
        rows.append(f"""
        <tr>
          <td class="mono font-bold">{_esc(cred)}</td>
          <td><span class="pill-tag">{_esc(attack_type)}</span></td>
          <td><span class="pill-tag channel-tag">{_esc(channel)}</span></td>
          <td>{status_badge}</td>
        </tr>
        """)

    return f"""
    <div class="table-scroll">
      <table class="attack-table">
        <thead>
          <tr><th>Target Credential</th><th>Attack Vector</th><th>Exfiltration Channel</th><th>Sandbox Result</th></tr>
        </thead>
        <tbody>
          {"".join(rows)}
        </tbody>
      </table>
    </div>
    """


_GRAPH_MIN_HEIGHT_PX = 520
_GRAPH_MAX_HEIGHT_PX = 760
_GRAPH_HEIGHT_BASELINE_NODES = 12
_GRAPH_HEIGHT_PER_NODE_PX = 14


def _graph_height_px(node_count: int) -> int:
    if node_count <= _GRAPH_HEIGHT_BASELINE_NODES:
        return _GRAPH_MIN_HEIGHT_PX
    grown = _GRAPH_MIN_HEIGHT_PX + (node_count - _GRAPH_HEIGHT_BASELINE_NODES) * _GRAPH_HEIGHT_PER_NODE_PX
    return min(_GRAPH_MAX_HEIGHT_PX, grown)


def _render_graph_section(full_graph: dict, top_attack_targets: list) -> tuple:
    nodes = _annotate_nodes(full_graph, top_attack_targets)
    data = {"nodes": nodes, "edges": full_graph.get("edges", [])}
    height_px = _graph_height_px(len(nodes))
    return _safe_json_for_script(data), _safe_json_for_script(TYPE_COLORS), height_px


BRAND_ICON_SVG = """<svg class="brand-icon" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>"""

SPARKLE_ICON_SVG = """<svg class="sparkle-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>"""


PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__PRODUCT_NAME__ // Security Audit Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://d3js.org/d3.v7.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
  :root {
    --bg: #090a0f;
    --card-bg: #11131c;
    --card-bg-alt: #0d0e17;
    --card-border: #1e2235;
    
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --mono: "Fira Code", monospace;
    --sans: "Inter", -apple-system, BlinkMacSystemFont, sans-serif;

    --red-bg: rgba(239, 68, 68, 0.1);   --red-fg: #f87171;   --red-border: rgba(239, 68, 68, 0.3);
    --amber-bg: rgba(245, 158, 11, 0.1); --amber-fg: #fbbf24; --amber-border: rgba(245, 158, 11, 0.3);
    --blue-bg: rgba(59, 130, 246, 0.1);  --blue-fg: #60a5fa;  --blue-border: rgba(59, 130, 246, 0.3);
    --green-bg: rgba(16, 185, 129, 0.1); --green-fg: #34d399; --green-border: rgba(16, 185, 129, 0.3);
  }

  * { box-sizing: border-box; }
  html, body {
    margin: 0; padding: 0;
    min-height: 100vh;
    background: var(--bg);
    color: var(--text-primary);
    font-family: var(--sans);
    -webkit-font-smoothing: antialiased;
  }

  .page {
    max-width: 1140px;
    margin: 0 auto;
    padding: 36px 24px 80px;
  }

  /* ---------- Header ---------- */
  .page-header { margin-bottom: 28px; }
  .header-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand-icon-box {
    width: 40px; height: 40px;
    border-radius: 10px;
    background: rgba(59, 130, 246, 0.15);
    border: 1px solid rgba(59, 130, 246, 0.3);
    display: flex; align-items: center; justify-content: center;
    color: #60a5fa;
  }
  .brand-title-wrap { display: flex; flex-direction: column; }
  .brand-name { font-size: 22px; font-weight: 800; letter-spacing: -0.02em; color: #ffffff; }
  .brand-tag { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); }
  
  .tagline {
    margin: 10px 0 0;
    color: var(--text-secondary);
    font-size: 14px;
  }
  .tagline code {
    font-family: var(--mono);
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid var(--card-border);
    padding: 2px 8px;
    border-radius: 6px;
    color: #cbd5e1;
    font-size: 13px;
  }

  /* Badges */
  .risk-badge, .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 14px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.03em;
    border: 1px solid transparent;
    white-space: nowrap;
  }
  .badge-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: currentColor;
  }

  .risk-critical, .badge-critical { background: var(--red-bg);   color: var(--red-fg);   border-color: var(--red-border); }
  .risk-high,     .badge-high     { background: var(--amber-bg); color: var(--amber-fg); border-color: var(--amber-border); }
  .risk-medium,   .badge-medium   { background: var(--blue-bg);  color: var(--blue-fg);  border-color: var(--blue-border); }
  .risk-low,      .badge-low      { background: var(--green-bg); color: var(--green-fg); border-color: var(--green-border); }
  .risk-info,     .badge-info     { background: rgba(148, 163, 184, 0.1); color: #cbd5e1; border-color: rgba(148, 163, 184, 0.2); }

  /* ---------- Stat cards ---------- */
  .stats-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }
  .stat-card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 14px;
    padding: 20px 22px;
    position: relative;
    overflow: hidden;
  }
  .stat-card::before {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0; height: 3px;
    background: rgba(255, 255, 255, 0.1);
  }
  .stat-card.stat-critical::before { background: var(--red-fg); }
  .stat-card.stat-high::before     { background: var(--amber-fg); }
  .stat-card.stat-safe::before     { background: var(--green-fg); }
  
  .stat-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 10px;
    color: var(--text-secondary);
  }
  .stat-label { font-size: 13px; font-weight: 600; }
  .stat-value { font-size: 30px; font-weight: 800; letter-spacing: -0.02em; margin-bottom: 4px; }
  .stat-card.stat-critical .stat-value { color: var(--red-fg); }
  .stat-card.stat-high .stat-value { color: var(--amber-fg); }
  .stat-card.stat-safe .stat-value { color: var(--green-fg); }
  .stat-sub { font-size: 12px; color: var(--text-muted); }

  /* ---------- Panels ---------- */
  .panel {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 16px;
    padding: 24px;
    margin-bottom: 24px;
  }
  .panel-header-wrap {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 18px;
    flex-wrap: wrap;
  }
  .panel-title {
    font-size: 16px;
    font-weight: 700;
    color: #ffffff;
    margin: 0;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .panel-subtitle { font-size: 13px; color: var(--text-muted); margin: 4px 0 0; }
  .empty-state { color: var(--text-muted); font-size: 14px; padding: 12px 0; }

  /* ---------- Blast Radius Graph Wrapper & Controls ---------- */
  #chart-wrap {
    position: relative;
    background: #06070a;
    border: 1px solid var(--card-border);
    border-radius: 12px;
    overflow: hidden;
  }
  #graph-svg { width: 100%; height: 100%; display: block; cursor: grab; }
  #graph-svg:active { cursor: grabbing; }

  /* Graph controls toolbar */
  .graph-controls {
    position: absolute;
    top: 14px;
    right: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    background: rgba(17, 19, 28, 0.9);
    border: 1px solid var(--card-border);
    padding: 6px 10px;
    border-radius: 8px;
    z-index: 10;
  }
  .control-btn {
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.1);
    color: var(--text-secondary);
    border-radius: 6px;
    width: 28px; height: 28px;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer;
    font-weight: 700;
    transition: all 0.15s;
  }
  .control-btn:hover { background: rgba(255, 255, 255, 0.15); color: #ffffff; }
  .graph-search {
    background: rgba(0, 0, 0, 0.4);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 6px;
    color: var(--text-primary);
    padding: 4px 10px;
    font-size: 12px;
    font-family: var(--mono);
    outline: none;
    width: 140px;
  }
  .graph-search:focus { border-color: var(--blue-fg); }

  /* Legend */
  #legend {
    position: absolute;
    bottom: 14px;
    left: 14px;
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    background: rgba(17, 19, 28, 0.9);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    padding: 8px 14px;
    z-index: 10;
  }
  #legend .legend-item {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11.5px;
    font-weight: 500;
    color: var(--text-secondary);
    cursor: pointer;
    padding: 2px 6px;
    border-radius: 6px;
  }
  #legend .legend-item:hover { background: rgba(255, 255, 255, 0.08); color: #fff; }
  #legend .legend-swatch {
    width: 10px; height: 10px;
    border-radius: 50%;
  }
  #legend .legend-count {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-muted);
  }

  /* Graph Node Labels & Lines */
  .link {
    stroke: rgba(255, 255, 255, 0.15);
    stroke-opacity: 0.7;
    transition: stroke 0.2s, stroke-width 0.2s;
  }
  .link.highlighted {
    stroke: #60a5fa !important;
    stroke-opacity: 1 !important;
    stroke-dasharray: 6 3;
  }

  .node { cursor: grab; transition: opacity 0.2s; }
  .node:hover { opacity: 1 !important; }
  
  .node-label-bg {
    fill: #0d0f18;
    stroke: #1e2235;
    stroke-width: 1px;
    rx: 5px; ry: 5px;
  }
  .node-label-text {
    font-family: var(--mono);
    font-size: 11.5px;
    font-weight: 600;
    fill: #f1f5f9;
    pointer-events: none;
    text-anchor: middle;
    dominant-baseline: middle;
  }

  /* Enhanced Tooltip */
  #tooltip {
    position: absolute;
    pointer-events: none;
    background: #11131c;
    border: 1px solid #1e2235;
    border-left: 3px solid var(--blue-fg);
    border-radius: 8px;
    padding: 12px 14px;
    font-size: 12px;
    color: var(--text-primary);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
    opacity: 0;
    transition: opacity 0.15s;
    max-width: 260px;
    z-index: 100;
  }
  #tooltip .t-header {
    font-family: var(--mono);
    font-weight: 700;
    font-size: 13px;
    color: #ffffff;
    margin-bottom: 6px;
    display: flex; align-items: center; justify-content: space-between;
  }
  #tooltip .t-type-tag {
    font-size: 10px;
    font-weight: 600;
    padding: 2px 6px;
    border-radius: 4px;
    text-transform: uppercase;
    background: rgba(255, 255, 255, 0.1);
  }
  #tooltip .t-row {
    display: flex;
    justify-content: space-between;
    color: var(--text-secondary);
    margin-top: 4px;
    font-size: 11.5px;
  }
  #tooltip .t-val { font-family: var(--mono); color: #cbd5e1; font-weight: 600; }

  /* ---------- Findings List ---------- */
  .findings-list { display: flex; flex-direction: column; gap: 12px; }
  .finding-card {
    background: #0d0e17;
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 16px 18px;
  }
  .finding-card.border-sev-critical { border-left: 3px solid var(--red-fg); }
  .finding-card.border-sev-high     { border-left: 3px solid var(--amber-fg); }
  .finding-card.border-sev-medium   { border-left: 3px solid var(--blue-fg); }
  
  .finding-head { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }
  .finding-title { font-size: 15px; font-weight: 700; color: #ffffff; }
  .finding-cat { font-family: var(--mono); font-size: 11px; color: var(--text-muted); background: rgba(255,255,255,0.05); padding: 2px 8px; border-radius: 4px; }
  .finding-desc { margin: 0; color: var(--text-secondary); font-size: 13.5px; line-height: 1.5; }
  
  .finding-fix { margin-top: 12px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 10px; }
  .finding-fix summary {
    cursor: pointer;
    color: var(--blue-fg);
    font-weight: 600;
    font-size: 12px;
    display: flex; align-items: center; gap: 6px;
    user-select: none;
  }
  .finding-fix summary .chevron { transition: transform 0.2s; }
  .finding-fix[open] summary .chevron { transform: rotate(180deg); }
  
  .fix-content {
    margin-top: 8px;
    position: relative;
    background: #06070a;
    border: 1px solid var(--card-border);
    border-radius: 8px;
    padding: 12px 14px;
  }
  .fix-content code {
    font-family: var(--mono);
    color: #38bdf8;
    font-size: 12.5px;
    white-space: pre-wrap;
    display: block;
  }
  .copy-btn {
    position: absolute;
    top: 8px; right: 8px;
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.12);
    color: var(--text-secondary);
    border-radius: 6px;
    padding: 3px 8px;
    font-size: 11px;
    cursor: pointer;
    transition: all 0.15s;
  }
  .copy-btn:hover { background: rgba(255,255,255,0.2); color: #fff; }

  /* ---------- Tables ---------- */
  .table-scroll { overflow-x: auto; margin-top: 6px; }
  table.attack-table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
  table.attack-table th, table.attack-table td {
    text-align: left; padding: 12px 14px;
    border-bottom: 1px solid var(--card-border);
  }
  table.attack-table th {
    color: var(--text-muted);
    font-weight: 600; font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.05em;
    background: rgba(255,255,255,0.02);
  }
  td.mono { font-family: var(--mono); }
  .font-bold { font-weight: 700; color: #ffffff; }
  .pill-tag {
    font-family: var(--mono);
    font-size: 12px;
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.08);
    padding: 3px 8px;
    border-radius: 6px;
    color: #e2e8f0;
  }
  .channel-tag { color: #38bdf8; border-color: rgba(56, 189, 248, 0.2); }

  /* ---------- AI Remediation Panel ---------- */
  .ai-panel .panel-title { color: #facc15; }
  .sparkle-icon { color: #facc15; flex-shrink: 0; }
  .markdown-body { color: #cbd5e1; font-size: 14px; line-height: 1.65; }
  .markdown-body h2, .markdown-body h3 { color: #ffffff; margin: 20px 0 10px; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 6px; }
  .markdown-body h2:first-child, .markdown-body h3:first-child { margin-top: 0; }
  .markdown-body strong { color: #ffffff; }
  .markdown-body code {
    font-family: var(--mono);
    background: rgba(0, 0, 0, 0.4);
    border: 1px solid var(--card-border);
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 12.5px;
    color: #38bdf8;
  }
  .markdown-body table { width: 100%; border-collapse: collapse; margin: 14px 0; }
  .markdown-body th, .markdown-body td { border: 1px solid var(--card-border); padding: 8px 12px; text-align: left; }
  .markdown-body th { background: rgba(255,255,255,0.04); color: #fff; }
  .ai-footer { margin: 18px 0 0; color: var(--text-muted); font-size: 12px; font-family: var(--mono); }

  @media (max-width: 640px) {
    .page { padding: 20px 14px 40px; }
    .stat-value { font-size: 24px; }
    .graph-controls { top: 8px; right: 8px; }
  }
</style>
</head>
<body>
<div class="page">

  <header class="page-header">
    <div class="header-row">
      <div class="brand">
        <div class="brand-icon-box">__BRAND_ICON__</div>
        <div class="brand-title-wrap">
          <span class="brand-name">__PRODUCT_NAME__</span>
          <span class="brand-tag">Cybernetic Agent Auditor</span>
        </div>
      </div>
      __RISK_BADGE__
    </div>
    <p class="tagline">__TAGLINE__ &mdash; audit target: <code>__SOURCE_PATH__</code></p>
  </header>

  __STAT_CARDS__

  <section class="panel">
    <div class="panel-header-wrap">
      <div>
        <h2 class="panel-title">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>
          Blast Radius Graph
        </h2>
        <p class="panel-subtitle">Multi-hop reachability model: Agent core hub and all downstream accessible assets</p>
      </div>
    </div>
    <div id="chart-wrap" style="height: __GRAPH_HEIGHT_PX__px;">
      <div class="graph-controls">
        <input type="text" id="graph-search-input" class="graph-search" placeholder="Search node..." oninput="filterGraph(this.value)">
        <button class="control-btn" onclick="zoomIn()" title="Zoom In">+</button>
        <button class="control-btn" onclick="zoomOut()" title="Zoom Out">&minus;</button>
        <button class="control-btn" onclick="resetZoom()" title="Reset View">&#x21bb;</button>
      </div>
      <div id="legend"></div>
      <div id="tooltip"></div>
      <svg id="graph-svg"></svg>
    </div>
  </section>

  <section class="panel">
    <h2 class="panel-title">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      Static Audit Findings
    </h2>
    __FINDINGS_LIST__
  </section>

  __ATTACK_SECTION__

  __AI_SECTION__

</div>

<script>
const GRAPH_DATA = __GRAPH_DATA_JSON__;
const TYPE_COLORS = __TYPE_COLORS_JSON__;

function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.innerText;
    btn.innerText = "Copied!";
    setTimeout(() => { btn.innerText = orig; }, 1500);
  });
}

const colorMap = {
  "agent":       "#3b82f6",
  "credential":  "#ef4444",
  "network":     "#10b981",
  "mcp_server":  "#f59e0b",
  "filesystem":  "#eab308",
  "skill":       "#06b6d4"
};

const defaultColor = "#64748b";

const colorFor = (type) => colorMap[type] || defaultColor;

const nodes = GRAPH_DATA.nodes.map(d => Object.assign({}, d));
const links = GRAPH_DATA.edges.map(d => Object.assign({}, d, { source: d.from, target: d.to }));

const maxScore = Math.max(1, ...nodes.map(d => d.blast_radius_score || 0));
// Sleek, compact node circles
const radiusScale = d3.scaleSqrt().domain([0, maxScore]).range([7, 18]);

const svg = d3.select("#graph-svg");
const wrap = document.getElementById("chart-wrap");
const g = svg.append("g");

const zoomBehavior = d3.zoom().scaleExtent([0.2, 4]).on("zoom", (event) => {
  g.attr("transform", event.transform);
});
svg.call(zoomBehavior);

function zoomIn() { svg.transition().duration(300).call(zoomBehavior.scaleBy, 1.3); }
function zoomOut() { svg.transition().duration(300).call(zoomBehavior.scaleBy, 0.7); }
function resetZoom() {
  svg.transition().duration(450).call(
    zoomBehavior.transform,
    d3.zoomIdentity.translate(0, 0).scale(1)
  );
}

// Background Dot Grid Pattern
const defs = svg.append("defs");
const pattern = defs.append("pattern")
  .attr("id", "dot-grid")
  .attr("width", 24)
  .attr("height", 24)
  .attr("patternUnits", "userSpaceOnUse");
pattern.append("circle").attr("cx", 12).attr("cy", 12).attr("r", 1).attr("fill", "rgba(255,255,255,0.05)");

// Draw grid background
g.append("rect")
  .attr("x", -2000).attr("y", -2000)
  .attr("width", 4000).attr("height", 4000)
  .attr("fill", "url(#dot-grid)")
  .style("pointer-events", "none");

// Increased link distance & repulsion so the graph spreads out and breathes
const simulation = d3.forceSimulation(nodes)
  .force("link", d3.forceLink(links).id(d => d.id).distance(180).strength(0.5))
  .force("charge", d3.forceManyBody().strength(-550))
  .force("center", d3.forceCenter(0, 0))
  .force("collide", d3.forceCollide(d => radiusScale(d.blast_radius_score || 0) + 32));

function resize() {
  const rect = wrap.getBoundingClientRect();
  svg.attr("viewBox", [-rect.width / 2, -rect.height / 2, rect.width, rect.height]);
}
resize();
window.addEventListener("resize", resize);

// Draw Link Edges
const linkGroup = g.append("g");
const link = linkGroup.selectAll("line")
  .data(links)
  .join("line")
  .attr("class", "link")
  .attr("stroke-width", d => Math.max(1.5, 1 + (d.ease || 0) / 3));

// Draw Link Permission Badges
const linkLabelGroup = g.append("g");
const linkLabels = linkLabelGroup.selectAll("text")
  .data(links)
  .join("text")
  .attr("font-family", "var(--mono)")
  .attr("font-size", "9px")
  .attr("fill", "rgba(255,255,255,0.35)")
  .attr("text-anchor", "middle")
  .text(d => d.permission || "");

const tooltip = d3.select("#tooltip");

function showTooltip(event, d) {
  const typeColor = colorFor(d.type);
  const rows = [];
  rows.push(`<div class="t-row"><span>Type</span><span class="t-val">${d.type}</span></div>`);
  if (d.sensitivity !== undefined) rows.push(`<div class="t-row"><span>Sensitivity</span><span class="t-val">${d.sensitivity}/10</span></div>`);
  if (d.ease_of_reach !== undefined) rows.push(`<div class="t-row"><span>Ease of Reach</span><span class="t-val">${d.ease_of_reach}/10</span></div>`);
  if (d.blast_radius_score !== undefined) rows.push(`<div class="t-row"><span>Blast Radius Score</span><span class="t-val" style="color:#f87171">${d.blast_radius_score}</span></div>`);
  if (d.source) rows.push(`<div class="t-row"><span>Source</span><span class="t-val">${d.source}</span></div>`);

  tooltip.html(`
    <div class="t-header">
      <span>${d.label}</span>
      <span class="t-type-tag" style="background:${typeColor}22; color:${typeColor}">${d.type}</span>
    </div>
    ${rows.join("")}
  `);

  const wrapRect = wrap.getBoundingClientRect();
  tooltip
    .style("border-left-color", typeColor)
    .style("left", (event.clientX - wrapRect.left + 16) + "px")
    .style("top", (event.clientY - wrapRect.top + 16) + "px")
    .style("opacity", 1);
}

function hideTooltip() { tooltip.style("opacity", 0); }

// Highlight connected nodes on hover
function handleMouseOver(event, d) {
  showTooltip(event, d);
  const connectedNodeIds = new Set([d.id]);
  links.forEach(l => {
    if (l.source.id === d.id) connectedNodeIds.add(l.target.id);
    if (l.target.id === d.id) connectedNodeIds.add(l.source.id);
  });

  nodeGroup.selectAll(".node-container").style("opacity", n => connectedNodeIds.has(n.id) ? 1 : 0.15);
  linkGroup.selectAll(".link").classed("highlighted", l => l.source.id === d.id || l.target.id === d.id);
}

function handleMouseOut() {
  hideTooltip();
  nodeGroup.selectAll(".node-container").style("opacity", 1);
  linkGroup.selectAll(".link").classed("highlighted", false);
}

// Draw Nodes
const nodeGroup = g.append("g");
const nodeContainers = nodeGroup.selectAll("g")
  .data(nodes)
  .join("g")
  .attr("class", "node-container node")
  .call(drag(simulation))
  .on("mousemove", handleMouseOver)
  .on("mouseleave", handleMouseOut);

// Clean Solid Node Circles
nodeContainers.append("circle")
  .attr("r", d => radiusScale(d.blast_radius_score || 0))
  .attr("fill", d => colorFor(d.type))
  .attr("stroke", "#1e2235")
  .attr("stroke-width", 2);

// Node Glassmorphic Label Backgrounds & Text (Legible 11.5px bold font)
const labelPaddingX = 8;
const labelPaddingY = 4;

nodeContainers.each(function(d) {
  const el = d3.select(this);
  const r = radiusScale(d.blast_radius_score || 0);
  const textVal = d.label;
  
  const textNode = el.append("text")
    .attr("class", "node-label-text")
    .attr("dy", r + 15)
    .text(textVal);

  const bbox = textNode.node().getBBox();
  
  el.insert("rect", "text")
    .attr("class", "node-label-bg")
    .attr("x", bbox.x - labelPaddingX)
    .attr("y", bbox.y - labelPaddingY)
    .attr("width", bbox.width + labelPaddingX * 2)
    .attr("height", bbox.height + labelPaddingY * 2);
});

simulation.on("tick", () => {
  link
    .attr("x1", d => d.source.x)
    .attr("y1", d => d.source.y)
    .attr("x2", d => d.target.x)
    .attr("y2", d => d.target.y);

  linkLabels
    .attr("x", d => (d.source.x + d.target.x) / 2)
    .attr("y", d => (d.source.y + d.target.y) / 2);

  nodeContainers.attr("transform", d => `translate(${d.x},${d.y})`);
});

function drag(sim) {
  function dragstarted(event, d) {
    if (!event.active) sim.alphaTarget(0.3).restart();
    d.fx = d.x; d.fy = d.y;
  }
  function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
  function dragended(event, d) {
    if (!event.active) sim.alphaTarget(0);
    d.fx = null; d.fy = null;
  }
  return d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended);
}

// Search Filter Implementation
function filterGraph(query) {
  const q = query.trim().toLowerCase();
  if (!q) {
    nodeGroup.selectAll(".node-container").style("opacity", 1);
    linkGroup.selectAll(".link").style("opacity", 0.7);
    return;
  }
  nodeGroup.selectAll(".node-container").style("opacity", d => {
    return (d.label.toLowerCase().includes(q) || d.type.toLowerCase().includes(q)) ? 1 : 0.1;
  });
}

// Dynamic Legend Generation
const typeCounts = {};
nodes.forEach(d => { typeCounts[d.type] = (typeCounts[d.type] || 0) + 1; });

const legend = d3.select("#legend");
Object.keys(typeCounts).forEach(type => {
  const item = legend.append("div").attr("class", "legend-item")
    .on("click", () => filterGraph(type));
  item.append("div").attr("class", "legend-swatch").style("background", colorFor(type));
  item.append("span").text(_prettify_snake_case(type));
  item.append("span").attr("class", "legend-count").text(`[${typeCounts[type]}]`);
});

function _prettify_snake_case(s) {
  return s.replace("_", " ").replace(/\\b\\w/g, l => l.upperCase ? l.upperCase() : l.toUpperCase());
}

__AI_MARKDOWN_SCRIPT__
</script>
</body>
</html>
"""


def render(machine_report: dict, verdict: dict = None, ai_remediation_md: str = None, source_path: str = None) -> str:
    failed_rules = machine_report.get("failed_rules", [])
    top_attack_targets = machine_report.get("top_attack_targets", [])
    full_graph = machine_report.get("full_graph", {"nodes": [], "edges": []})
    source_path = source_path or "unknown config path"

    highest_sev = _highest_severity(failed_rules)
    risk_badge = _risk_badge_html(highest_sev, has_findings=bool(failed_rules))

    stat_cards_html = _render_stat_cards(failed_rules, verdict)
    findings_html = _render_findings_list(failed_rules)
    graph_data_json, type_colors_json, graph_height_px = _render_graph_section(full_graph, top_attack_targets)

    if verdict:
        attack_section = f"""
        <section class="panel">
          <div class="panel-header-wrap">
            <div>
              <h2 class="panel-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f43f5e" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                Proven Attacks &mdash; Real Exfiltration Evidence
              </h2>
              <p class="panel-subtitle">Dynamic penetration test results against sandboxed container replica</p>
            </div>
          </div>
          {_render_attack_table(verdict)}
        </section>
        """
    else:
        attack_section = ""

    if ai_remediation_md:
        ai_section = f"""
        <section class="panel ai-panel">
          <div class="panel-header-wrap">
            <div>
              <h2 class="panel-title">{SPARKLE_ICON_SVG} Automated Remediation Advisor</h2>
              <p class="panel-subtitle">Contextual, plain-English guidance and step-by-step fixes</p>
            </div>
            <button class="copy-btn" onclick="copyText(document.getElementById('ai-remediation-content').innerText, this)">Copy Advice</button>
          </div>
          <div id="ai-remediation-content" class="markdown-body"></div>
          <p class="ai-footer">Report saved to output/ai_remediation.md</p>
        </section>
        """
        ai_markdown_script = (
            f"document.getElementById('ai-remediation-content').innerHTML = "
            f"marked.parse({_safe_json_for_script(ai_remediation_md)});"
        )
    else:
        ai_section = ""
        ai_markdown_script = ""

    out = PAGE_TEMPLATE
    out = out.replace("__PRODUCT_NAME__", _esc(PRODUCT_NAME))
    out = out.replace("__TAGLINE__", _esc(TAGLINE))
    out = out.replace("__SOURCE_PATH__", _esc(source_path))
    out = out.replace("__BRAND_ICON__", BRAND_ICON_SVG)
    out = out.replace("__RISK_BADGE__", risk_badge)
    out = out.replace("__STAT_CARDS__", stat_cards_html)
    out = out.replace("__FINDINGS_LIST__", findings_html)
    out = out.replace("__ATTACK_SECTION__", attack_section)
    out = out.replace("__AI_SECTION__", ai_section)
    out = out.replace("__GRAPH_HEIGHT_PX__", str(graph_height_px))
    out = out.replace("__GRAPH_DATA_JSON__", graph_data_json)
    out = out.replace("__TYPE_COLORS_JSON__", type_colors_json)
    out = out.replace("__AI_MARKDOWN_SCRIPT__", ai_markdown_script)

    return out


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print("Usage: python render_dashboard.py [/path/to/output/dir]")
        sys.exit(1)

    out_dir = Path(sys.argv[1]) if len(sys.argv) >= 2 else Path("output")
    report_path = out_dir / "report.json"
    if not report_path.exists():
        report_path = out_dir / "machine_report.json"

    if not report_path.exists():
        print(f"[dashboard] ERROR: report.json (or machine_report.json) not found in {out_dir}.")
        sys.exit(1)

    machine_report = _load_json_or_exit(report_path)

    verdict_path = out_dir / "verdict.json"
    verdict = None
    if verdict_path.exists():
        _warn_if_stale(report_path, verdict_path, "verdict.json", "python3 run_pipeline.py attack")
        verdict = _load_json_or_exit(verdict_path)
        print(f"[dashboard] including proven-attack data from {verdict_path}")

    ai_remediation_path = out_dir / "ai_remediation.md"
    ai_remediation_md = None
    if ai_remediation_path.exists():
        _warn_if_stale(report_path, ai_remediation_path, "ai_remediation.md", "python3 run_pipeline.py advise")
        ai_remediation_md = ai_remediation_path.read_text(encoding="utf-8")
        print(f"[dashboard] including AI remediation advice from {ai_remediation_path}")
    else:
        print("[dashboard] no ai_remediation.md found -- skipping the AI remediation section.")

    source_path = machine_report.get("source_path", "unknown config path")
    dashboard_html = render(machine_report, verdict, ai_remediation_md, source_path)

    dashboard_path = out_dir / "dashboard.html"
    dashboard_path.write_text(dashboard_html, encoding="utf-8")
    print(f"[dashboard] saved to {dashboard_path}")
