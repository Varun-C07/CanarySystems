"""
render_dashboard.py

Renders a single self-contained HTML dashboard combining:
  - output/machine_report.json (required) -- failed_rules, top_attack_targets, full_graph
  - output/verdict.json (optional) -- Method 2's PROVEN exfiltration results
  - output/ai_remediation.md (optional) -- Groq-generated remediation advice

Reuses graph_builder/render_graph.py's node-annotation logic and categorical
color palette directly (imported, not duplicated) rather than rebuilding the
blast-radius graph from scratch; the D3 force-simulation approach mirrors
render_graph.py's too, restyled (dashed edges, glow on the agent node,
monospace labels) to fit this dashboard's fixed dark theme instead of
render_graph.py's own light/dark toggle.

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
from method1.graph_builder.render_graph import TYPE_COLORS, _annotate_nodes

# ---------------------------------------------------------------------------
# Branding -- change here, nowhere else. Placeholder name per user request;
# swap PRODUCT_NAME when the final name is chosen.
# ---------------------------------------------------------------------------
PRODUCT_NAME = "AgentGuard"
TAGLINE = "Prove it, don't guess it"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

ATTACK_TYPE_LABELS = {
    "direct_injection": "Direct injection",
    "indirect_injection": "Indirect injection",
    "tool_poisoning": "Tool poisoning",
    "dns_exfil_injection": "DNS exfil injection",
    "file_exfil_injection": "File exfil injection",
    "exec_exfil_injection": "Exec exfil injection",
    "package_install_injection": "Package install injection",
    "tool_abuse_injection": "Tool abuse injection",
    "unknown": "Unknown",
}
CHANNEL_LABELS = {
    "HTTP_WEBHOOK": "HTTP webhook",
    "DNS_TUNNEL": "DNS tunnel",
    "FILE_WRITE": "File write",
    "SHELL_EXEC": "Shell exec",
    "PACKAGE_INSTALL": "Package install",
    "TOOL_ABUSE": "Tool abuse",
}


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _prettify_rule_name(rule: str) -> str:
    """'auth_token' -> 'Auth Token'. Formatting only, never invents new text."""
    return rule.replace("_", " ").title()


def _highest_severity(failed_rules: list) -> str:
    present = {f.get("severity") for f in failed_rules}
    for sev in SEVERITY_ORDER:
        if sev in present:
            return sev
    return "info"


def _risk_badge_html(highest_sev: str, has_findings: bool) -> str:
    if not has_findings:
        return '<span class="risk-badge risk-low">No findings</span>'
    label = f"{highest_sev.capitalize()} exposure"
    return f'<span class="risk-badge risk-{_esc(highest_sev)}">{_esc(label)}</span>'


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
    else:
        creds_value = "N/A"

    return f"""
    <section class="stats-row">
      <div class="stat-card">
        <div class="stat-label">Static findings</div>
        <div class="stat-value">{total}</div>
      </div>
      <div class="stat-card stat-critical">
        <div class="stat-label">Critical</div>
        <div class="stat-value">{critical}</div>
      </div>
      <div class="stat-card stat-high">
        <div class="stat-label">High</div>
        <div class="stat-value">{high}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Credentials leaked</div>
        <div class="stat-value">{_esc(creds_value)}</div>
      </div>
    </section>
    """


def _render_findings_list(failed_rules: list) -> str:
    if not failed_rules:
        return '<p class="empty-state">No failed checks -- every static rule passed.</p>'

    ordered = sorted(
        failed_rules,
        key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f.get("severity") in SEVERITY_ORDER else len(SEVERITY_ORDER),
    )

    cards = []
    for f in ordered:
        cards.append(f"""
        <div class="finding-card">
          <div class="finding-head">
            {_severity_badge_html(f.get('severity', 'info'))}
            <span class="finding-title">{_esc(_prettify_rule_name(f.get('rule', 'unknown')))}</span>
          </div>
          <p class="finding-desc">{_esc(f.get('finding', ''))}</p>
          <details class="finding-fix">
            <summary>Fix</summary>
            <p>{_esc(f.get('fix') or 'No fix text available.')}</p>
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
            '<span class="badge badge-critical">LEAKED</span>' if fired
            else '<span class="badge badge-low">SAFE</span>'
        )
        rows.append(f"""
        <tr>
          <td class="mono">{_esc(cred)}</td>
          <td>{_esc(attack_type)}</td>
          <td>{_esc(channel)}</td>
          <td>{status_badge}</td>
        </tr>
        """)

    return f"""
    <div class="table-scroll">
      <table class="attack-table">
        <thead>
          <tr><th>Credential</th><th>Attack type</th><th>Channel</th><th>Status</th></tr>
        </thead>
        <tbody>
          {"".join(rows)}
        </tbody>
      </table>
    </div>
    """


def _render_graph_section(full_graph: dict, top_attack_targets: list) -> tuple:
    """Reuses render_graph.py's own node-annotation logic (blast_radius_score
    etc. merged onto each node) and categorical color palette, unchanged."""
    nodes = _annotate_nodes(full_graph, top_attack_targets)
    data = {"nodes": nodes, "edges": full_graph["edges"]}
    return json.dumps(data), json.dumps(TYPE_COLORS)


BRAND_ICON_SVG = """<svg class="brand-icon" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5.25 3.4 9.74 8 11 4.6-1.26 8-5.75 8-11V5l-8-3z"/><path d="m9 12 2 2 4-4"/></svg>"""

SPARKLE_ICON_SVG = """<svg class="sparkle-icon" width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l1.6 5.4L19 9l-5.4 1.6L12 16l-1.6-5.4L5 9l5.4-1.6L12 2z"/></svg>"""


PAGE_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>__PRODUCT_NAME__ // Audit Report</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
  :root {
    --bg: #0a0a0c;
    --card-bg: #141417;
    --card-bg-alt: #101013;
    --card-border: rgba(255,255,255,0.08);
    --text-primary: #f5f5f7;
    --text-secondary: #9a9aa2;
    --text-muted: #6b6b74;
    --mono: ui-monospace, "SF Mono", "Cascadia Code", "Roboto Mono", Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;

    --red-bg: rgba(239,68,68,0.12);   --red-fg: #f87171;   --red-border: rgba(239,68,68,0.28);
    --amber-bg: rgba(245,158,11,0.12); --amber-fg: #fbbf24; --amber-border: rgba(245,158,11,0.28);
    --blue-bg: rgba(59,130,246,0.12);  --blue-fg: #60a5fa;  --blue-border: rgba(59,130,246,0.28);
    --green-bg: rgba(34,197,94,0.12);  --green-fg: #4ade80; --green-border: rgba(34,197,94,0.28);
    --gray-bg: rgba(148,163,184,0.10); --gray-fg: #94a3b8;  --gray-border: rgba(148,163,184,0.22);
  }

  * { box-sizing: border-box; }
  html, body {
    margin: 0; padding: 0;
    background: var(--bg);
    color: var(--text-primary);
    font-family: var(--sans);
  }
  body { overflow-x: hidden; }

  .page {
    max-width: 980px;
    margin: 0 auto;
    padding: 28px 20px 60px;
  }

  /* ---------- Header ---------- */
  .page-header { margin-bottom: 22px; }
  .header-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
  }
  .brand { display: flex; align-items: center; gap: 8px; }
  .brand-icon { color: var(--text-primary); flex-shrink: 0; }
  .brand-name { font-size: 20px; font-weight: 700; letter-spacing: -0.01em; }
  .tagline {
    margin: 6px 0 0;
    color: var(--text-secondary);
    font-size: 13px;
  }
  .tagline code {
    font-family: var(--mono);
    background: var(--card-bg-alt);
    border: 1px solid var(--card-border);
    padding: 1px 6px;
    border-radius: 4px;
    color: var(--text-primary);
    font-size: 12px;
  }

  .risk-badge, .badge {
    display: inline-flex;
    align-items: center;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.02em;
    border: 1px solid transparent;
    white-space: nowrap;
  }
  .risk-critical, .badge-critical { background: var(--red-bg);   color: var(--red-fg);   border-color: var(--red-border); }
  .risk-high,     .badge-high     { background: var(--amber-bg); color: var(--amber-fg); border-color: var(--amber-border); }
  .risk-medium,   .badge-medium   { background: var(--blue-bg);  color: var(--blue-fg);  border-color: var(--blue-border); }
  .risk-low,      .badge-low      { background: var(--green-bg); color: var(--green-fg); border-color: var(--green-border); }
  .risk-info,     .badge-info     { background: var(--gray-bg);  color: var(--gray-fg);  border-color: var(--gray-border); }

  /* ---------- Stat cards ---------- */
  .stats-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }
  .stat-card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 16px 18px;
  }
  .stat-card.stat-critical { background: var(--red-bg); border-color: var(--red-border); }
  .stat-card.stat-high     { background: var(--amber-bg); border-color: var(--amber-border); }
  .stat-label {
    font-size: 12px;
    color: var(--text-secondary);
    margin-bottom: 6px;
  }
  .stat-card.stat-critical .stat-label,
  .stat-card.stat-high .stat-label { color: inherit; opacity: 0.85; }
  .stat-value { font-size: 28px; font-weight: 700; }
  .stat-card.stat-critical .stat-value { color: var(--red-fg); }
  .stat-card.stat-high .stat-value { color: var(--amber-fg); }

  /* ---------- Panels ---------- */
  .panel {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 18px 20px;
    margin-bottom: 20px;
  }
  .panel-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-secondary);
    margin: 0 0 14px;
    text-transform: none;
  }
  .empty-state { color: var(--text-muted); font-size: 13px; }

  /* ---------- Graph ---------- */
  #chart-wrap {
    position: relative;
    height: 420px;
    background: var(--card-bg-alt);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    overflow: hidden;
  }
  #graph-svg { width: 100%; height: 100%; display: block; cursor: grab; }
  #graph-svg:active { cursor: grabbing; }
  .link { stroke: rgba(255,255,255,0.28); stroke-opacity: 0.9; }
  .node { cursor: grab; }
  .node-label {
    font-family: var(--mono);
    font-size: 10px;
    fill: var(--text-secondary);
    pointer-events: none;
    text-anchor: middle;
  }
  #legend {
    position: absolute;
    bottom: 12px;
    left: 12px;
    display: flex;
    gap: 14px;
    font-size: 11px;
    color: var(--text-secondary);
  }
  #legend .row { display: flex; align-items: center; gap: 6px; }
  #legend .swatch { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
  #tooltip {
    position: absolute;
    pointer-events: none;
    background: #1c1c20;
    border: 1px solid var(--card-border);
    border-radius: 6px;
    padding: 8px 10px;
    font-size: 12px;
    color: var(--text-primary);
    box-shadow: 0 4px 16px rgba(0,0,0,0.4);
    opacity: 0;
    transition: opacity 0.1s;
    max-width: 240px;
    z-index: 10;
  }
  #tooltip .t-title { font-family: var(--mono); font-weight: 600; margin-bottom: 2px; }
  #tooltip .t-row { color: var(--text-secondary); }

  /* ---------- Findings ---------- */
  .findings-list { display: flex; flex-direction: column; gap: 10px; }
  .finding-card {
    background: var(--card-bg-alt);
    border: 1px solid var(--card-border);
    border-radius: 10px;
    padding: 14px 16px;
  }
  .finding-head { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
  .finding-title { font-size: 14px; font-weight: 600; }
  .finding-desc { margin: 0; color: var(--text-secondary); font-size: 13px; line-height: 1.5; }
  .finding-fix { margin-top: 8px; font-size: 12px; }
  .finding-fix summary {
    cursor: pointer;
    color: var(--text-muted);
    font-weight: 600;
    letter-spacing: 0.03em;
    text-transform: uppercase;
    font-size: 11px;
  }
  .finding-fix summary:hover { color: var(--text-secondary); }
  .finding-fix p {
    margin: 8px 0 0;
    padding: 10px 12px;
    background: rgba(255,255,255,0.03);
    border-left: 2px solid var(--card-border);
    color: var(--text-secondary);
    font-size: 12.5px;
    line-height: 1.5;
  }

  /* ---------- Tables (attack proof + markdown) ---------- */
  .table-scroll { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--card-border); }
  th { color: var(--text-muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.03em; }
  td.mono { font-family: var(--mono); }
  .attack-table td.mono { font-family: var(--mono); }

  /* ---------- AI remediation panel ---------- */
  .ai-panel .panel-title { display: flex; align-items: center; gap: 6px; color: var(--text-primary); font-size: 14px; }
  .sparkle-icon { color: var(--amber-fg); flex-shrink: 0; }
  .markdown-body { color: var(--text-secondary); font-size: 13.5px; line-height: 1.6; }
  .markdown-body h2, .markdown-body h3 { color: var(--text-primary); margin: 18px 0 8px; }
  .markdown-body h2:first-child, .markdown-body h3:first-child { margin-top: 0; }
  .markdown-body strong { color: var(--text-primary); }
  .markdown-body code {
    font-family: var(--mono);
    background: var(--card-bg-alt);
    border: 1px solid var(--card-border);
    padding: 1px 5px;
    border-radius: 4px;
    font-size: 12px;
    color: var(--text-primary);
  }
  .markdown-body table { margin: 10px 0; }
  .markdown-body hr { border: none; border-top: 1px solid var(--card-border); margin: 16px 0; }
  .ai-footer { margin: 16px 0 0; color: var(--text-muted); font-size: 11.5px; }

  @media (max-width: 640px) {
    .page { padding: 20px 14px 40px; }
    .stat-value { font-size: 22px; }
  }
</style>
</head>
<body>
<div class="page">

  <header class="page-header">
    <div class="header-row">
      <div class="brand">
        __BRAND_ICON__
        <span class="brand-name">__PRODUCT_NAME__</span>
      </div>
      __RISK_BADGE__
    </div>
    <p class="tagline">__TAGLINE__ &mdash; audit of <code>__SOURCE_PATH__</code></p>
  </header>

  __STAT_CARDS__

  <section class="panel">
    <h2 class="panel-title">Blast radius &mdash; agent and everything it can reach</h2>
    <div id="chart-wrap">
      <div id="legend"></div>
      <div id="tooltip"></div>
      <svg id="graph-svg"></svg>
    </div>
  </section>

  <section class="panel">
    <h2 class="panel-title">Static findings</h2>
    __FINDINGS_LIST__
  </section>

  __ATTACK_SECTION__

  __AI_SECTION__

</div>

<script>
const GRAPH_DATA = __GRAPH_DATA_JSON__;
const TYPE_COLORS = __TYPE_COLORS_JSON__;

const colorFor = (type) => {
  const c = TYPE_COLORS[type];
  return c ? c.dark : "#898781";
};

const nodes = GRAPH_DATA.nodes.map(d => Object.assign({}, d));
const links = GRAPH_DATA.edges.map(d => Object.assign({}, d, { source: d.from, target: d.to }));

const maxScore = Math.max(1, ...nodes.map(d => d.blast_radius_score || 0));
const radiusScale = d3.scaleSqrt().domain([0, maxScore]).range([7, 34]);

const svg = d3.select("#graph-svg");
const wrap = document.getElementById("chart-wrap");
const g = svg.append("g");

svg.call(
  d3.zoom().scaleExtent([0.3, 4]).on("zoom", (event) => {
    g.attr("transform", event.transform);
  })
);

const defs = svg.append("defs");
const glow = defs.append("filter")
  .attr("id", "agent-glow")
  .attr("x", "-60%").attr("y", "-60%").attr("width", "220%").attr("height", "220%");
glow.append("feGaussianBlur").attr("stdDeviation", "5").attr("result", "blur");
const merge = glow.append("feMerge");
merge.append("feMergeNode").attr("in", "blur");
merge.append("feMergeNode").attr("in", "SourceGraphic");

const simulation = d3.forceSimulation(nodes)
  .force("link", d3.forceLink(links).id(d => d.id).distance(115).strength(0.6))
  .force("charge", d3.forceManyBody().strength(-340))
  .force("center", d3.forceCenter(0, 0))
  .force("collide", d3.forceCollide(d => radiusScale(d.blast_radius_score || 0) + 16));

function resize() {
  const rect = wrap.getBoundingClientRect();
  svg.attr("viewBox", [-rect.width / 2, -rect.height / 2, rect.width, rect.height]);
}
resize();
window.addEventListener("resize", resize);

const link = g.append("g")
  .selectAll("line")
  .data(links)
  .join("line")
  .attr("class", "link")
  .attr("stroke-dasharray", "4 3")
  .attr("stroke-width", d => 1 + (d.ease || 0) / 5);

link.append("title").text(d => `${d.permission} (ease ${d.ease})`);

const tooltip = d3.select("#tooltip");

function showTooltip(event, d) {
  const rows = [];
  rows.push(`<div class="t-row">type: ${d.type}</div>`);
  if (d.sensitivity !== undefined) rows.push(`<div class="t-row">sensitivity: ${d.sensitivity}</div>`);
  if (d.ease_of_reach !== undefined) rows.push(`<div class="t-row">ease of reach: ${d.ease_of_reach}</div>`);
  if (d.blast_radius_score !== undefined) rows.push(`<div class="t-row">blast radius score: ${d.blast_radius_score}</div>`);
  if (d.source) rows.push(`<div class="t-row">source: ${d.source}</div>`);
  if (d.scopes) rows.push(`<div class="t-row">scopes: ${d.scopes.join(", ")}</div>`);
  tooltip.html(`<div class="t-title">${d.label}</div>${rows.join("")}`);
  const wrapRect = wrap.getBoundingClientRect();
  tooltip
    .style("left", (event.clientX - wrapRect.left + 14) + "px")
    .style("top", (event.clientY - wrapRect.top + 14) + "px")
    .style("opacity", 1);
}
function hideTooltip() { tooltip.style("opacity", 0); }

const node = g.append("g")
  .selectAll("g")
  .data(nodes)
  .join("g")
  .attr("class", "node")
  .call(drag(simulation))
  .on("mousemove", showTooltip)
  .on("mouseleave", hideTooltip);

node.append("circle")
  .attr("r", d => radiusScale(d.blast_radius_score || 0))
  .attr("fill", d => colorFor(d.type))
  .attr("stroke", "#0a0a0c")
  .attr("stroke-width", 2)
  .attr("filter", d => d.type === "agent" ? "url(#agent-glow)" : null);

node.append("text")
  .attr("class", "node-label")
  .attr("dy", d => radiusScale(d.blast_radius_score || 0) + 13)
  .text(d => d.label);

simulation.on("tick", () => {
  link
    .attr("x1", d => d.source.x)
    .attr("y1", d => d.source.y)
    .attr("x2", d => d.target.x)
    .attr("y2", d => d.target.y);
  node.attr("transform", d => `translate(${d.x},${d.y})`);
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

const typesPresent = [...new Set(nodes.map(d => d.type))];
const legend = d3.select("#legend");
typesPresent.forEach(type => {
  const row = legend.append("div").attr("class", "row");
  row.append("div").attr("class", "swatch").style("background", colorFor(type));
  row.append("span").text(type);
});

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
    graph_data_json, type_colors_json = _render_graph_section(full_graph, top_attack_targets)

    if verdict:
        attack_section = f"""
        <section class="panel">
          <h2 class="panel-title">Proven attacks &mdash; real exfiltration, not a guess</h2>
          {_render_attack_table(verdict)}
        </section>
        """
    else:
        attack_section = ""

    if ai_remediation_md:
        ai_section = f"""
        <section class="panel ai-panel">
          <h2 class="panel-title">{SPARKLE_ICON_SVG} AI remediation &mdash; generated by Groq</h2>
          <div id="ai-remediation-content" class="markdown-body"></div>
          <p class="ai-footer">Full report saved to output/ai_remediation.md</p>
        </section>
        """
        ai_markdown_script = (
            f"document.getElementById('ai-remediation-content').innerHTML = "
            f"marked.parse({json.dumps(ai_remediation_md)});"
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
    out = out.replace("__GRAPH_DATA_JSON__", graph_data_json)
    out = out.replace("__TYPE_COLORS_JSON__", type_colors_json)
    out = out.replace("__AI_MARKDOWN_SCRIPT__", ai_markdown_script)
    return out


if __name__ == "__main__":
    if len(sys.argv) > 2:
        print("Usage: python render_dashboard.py [/path/to/output/dir]")
        sys.exit(1)

    output_dir = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).parent.parent.parent / "output"

    machine_report_path = output_dir / "machine_report.json"
    if not machine_report_path.exists():
        print(f"[dashboard] ERROR: {machine_report_path} not found.")
        print("[dashboard] Run 'python3 run_pipeline.py scan <config_dir>' first.")
        sys.exit(1)
    machine_report = json.loads(machine_report_path.read_text())

    # machine_report.json itself never carries source_path (report_renderer.py's
    # build_machine_report() doesn't include it) -- it lives in the sibling
    # normalized_config.json that config_collector.py produces during the
    # same scan run.
    source_path = None
    normalized_config_path = output_dir / "normalized_config.json"
    if normalized_config_path.exists():
        normalized_config = json.loads(normalized_config_path.read_text())
        source_path = normalized_config.get("source_path")
        # collector.py stores the resolved absolute path; display it relative
        # to the project root when possible (purely cosmetic -- same real
        # path either way, just shorter when the scanned config lives inside
        # this repo, which is the common case for sample_configs/*).
        if source_path:
            project_root = Path(__file__).parent.parent.parent
            try:
                source_path = str(Path(source_path).relative_to(project_root))
            except ValueError:
                pass  # config lives outside the repo -- keep the absolute path

    verdict = None
    verdict_path = output_dir / "verdict.json"
    if verdict_path.exists():
        verdict = json.loads(verdict_path.read_text())
        print(f"[dashboard] including proven-attack data from {verdict_path}")
    else:
        print(f"[dashboard] no verdict.json found -- skipping the proven-attacks section.")

    ai_remediation_md = None
    ai_path = output_dir / "ai_remediation.md"
    if ai_path.exists():
        ai_remediation_md = ai_path.read_text()
        print(f"[dashboard] including AI remediation advice from {ai_path}")
    else:
        print(f"[dashboard] no ai_remediation.md found -- skipping the AI remediation section.")

    html_out = render(machine_report, verdict, ai_remediation_md, source_path)

    out_path = output_dir / "dashboard.html"
    out_path.write_text(html_out)
    print(f"[dashboard] saved to {out_path}")
