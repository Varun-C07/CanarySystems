"""
render_graph.py

Takes graph_builder.py's JSON output (graph + ranked_blast_radius) and
renders a self-contained HTML file with an interactive D3.js force-directed
blast-radius graph: nodes colored by type, sized by blast_radius_score,
draggable, with hover tooltips.

Usage:
    python render_graph.py /path/to/graph_output.json [output.html]
"""

import json
import sys

# Fixed categorical color order (light/dark), assigned by node type.
# Agent labels never collide with color alone: every node also carries a
# direct text label plus a hover tooltip with its full detail.
TYPE_COLORS = {
    "agent":       {"light": "#2a78d6", "dark": "#3987e5"},  # blue
    "mcp_server":  {"light": "#eb6834", "dark": "#d95926"},  # orange
    "skill":       {"light": "#1baf7a", "dark": "#199e70"},  # aqua
    "filesystem":  {"light": "#eda100", "dark": "#c98500"},  # yellow
    "credential":  {"light": "#e87ba4", "dark": "#d55181"},  # magenta
    "network":     {"light": "#008300", "dark": "#008300"},  # green
}
DEFAULT_COLOR = {"light": "#898781", "dark": "#898781"}

HTML_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Blast Radius Graph</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
  .viz-root {
    color-scheme: light;
    --surface-1:      #fcfcfb;
    --page-plane:     #f9f9f7;
    --text-primary:   #0b0b0b;
    --text-secondary: #52514e;
    --muted:          #898781;
    --gridline:       #e1e0d9;
    --border:         rgba(11,11,11,0.10);
  }
  @media (prefers-color-scheme: dark) {
    .viz-root {
      color-scheme: dark;
      --surface-1:      #1a1a19;
      --page-plane:     #0d0d0d;
      --text-primary:   #ffffff;
      --text-secondary: #c3c2b7;
      --muted:          #898781;
      --gridline:       #2c2c2a;
      --border:         rgba(255,255,255,0.10);
    }
  }
  html, body {
    margin: 0;
    padding: 0;
    height: 100%;
    background: var(--page-plane);
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  .viz-root {
    height: 100vh;
    display: flex;
    flex-direction: column;
    background: var(--page-plane);
  }
  header {
    padding: 16px 20px 12px;
  }
  h1 {
    margin: 0 0 2px;
    font-size: 16px;
    font-weight: 600;
    color: var(--text-primary);
  }
  .subtitle {
    margin: 0;
    font-size: 12px;
    color: var(--text-secondary);
  }
  #chart-wrap {
    position: relative;
    flex: 1;
    margin: 0 20px 20px;
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }
  svg { width: 100%; height: 100%; display: block; cursor: grab; }
  svg:active { cursor: grabbing; }
  .link { stroke: var(--gridline); stroke-opacity: 0.9; }
  .node { cursor: grab; }
  .node:active { cursor: grabbing; }
  .node-label {
    font-size: 10px;
    fill: var(--text-secondary);
    pointer-events: none;
    text-anchor: middle;
  }
  #legend {
    position: absolute;
    top: 12px;
    left: 12px;
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 11px;
    color: var(--text-secondary);
    line-height: 1.8;
  }
  #legend .row { display: flex; align-items: center; gap: 6px; }
  #legend .swatch { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  #tooltip {
    position: absolute;
    pointer-events: none;
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 10px;
    font-size: 12px;
    color: var(--text-primary);
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    opacity: 0;
    transition: opacity 0.1s;
    max-width: 260px;
    z-index: 10;
  }
  #tooltip .t-title { font-weight: 600; margin-bottom: 2px; }
  #tooltip .t-row { color: var(--text-secondary); }
</style>
</head>
<body>
<div class="viz-root">
  <header>
    <h1>Agent Blast Radius Graph</h1>
    <p class="subtitle">Drag nodes to reposition. Hover for details. Node size = blast radius score.</p>
  </header>
  <div id="chart-wrap">
    <div id="legend"></div>
    <div id="tooltip"></div>
    <svg></svg>
  </div>
</div>
<script>
const DATA = __DATA_JSON__;
const TYPE_COLORS = __TYPE_COLORS_JSON__;
const DEFAULT_COLOR = __DEFAULT_COLOR_JSON__;

const isDark = () => window.matchMedia("(prefers-color-scheme: dark)").matches;
const colorFor = (type) => {
  const c = TYPE_COLORS[type] || DEFAULT_COLOR;
  return isDark() ? c.dark : c.light;
};

const nodes = DATA.nodes.map(d => Object.assign({}, d));
const links = DATA.edges.map(d => Object.assign({}, d, { source: d.from, target: d.to }));

const maxScore = Math.max(1, ...nodes.map(d => d.blast_radius_score || 0));
const radiusScale = d3.scaleSqrt().domain([0, maxScore]).range([8, 40]);

const svg = d3.select("svg");
const wrap = document.getElementById("chart-wrap");
const g = svg.append("g");

svg.call(
  d3.zoom().scaleExtent([0.2, 4]).on("zoom", (event) => {
    g.attr("transform", event.transform);
  })
);

svg.append("defs").append("marker")
  .attr("id", "arrow")
  .attr("viewBox", "0 -5 10 10")
  .attr("refX", 22)
  .attr("refY", 0)
  .attr("markerWidth", 6)
  .attr("markerHeight", 6)
  .attr("orient", "auto")
  .append("path")
  .attr("d", "M0,-5L10,0L0,5")
  .attr("fill", "var(--muted)");

const simulation = d3.forceSimulation(nodes)
  .force("link", d3.forceLink(links).id(d => d.id).distance(110).strength(0.6))
  .force("charge", d3.forceManyBody().strength(-320))
  .force("center", d3.forceCenter(0, 0))
  .force("collide", d3.forceCollide(d => radiusScale(d.blast_radius_score || 0) + 14));

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
  .attr("stroke-width", d => 1 + (d.ease || 0) / 4)
  .attr("marker-end", "url(#arrow)");

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
  if (d.pinned !== undefined) rows.push(`<div class="t-row">pinned: ${d.pinned}</div>`);
  tooltip.html(`<div class="t-title">${d.label}</div>${rows.join("")}`);
  const wrapRect = wrap.getBoundingClientRect();
  tooltip
    .style("left", (event.clientX - wrapRect.left + 14) + "px")
    .style("top", (event.clientY - wrapRect.top + 14) + "px")
    .style("opacity", 1);
}
function hideTooltip() {
  tooltip.style("opacity", 0);
}

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
  .attr("stroke", "var(--surface-1)")
  .attr("stroke-width", 2);

node.append("text")
  .attr("class", "node-label")
  .attr("dy", d => radiusScale(d.blast_radius_score || 0) + 12)
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
  function dragged(event, d) {
    d.fx = event.x; d.fy = event.y;
  }
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
</script>
</body>
</html>
"""


def _annotate_nodes(graph: dict, ranked: list) -> list:
    """Merge blast_radius_score/sensitivity/ease_of_reach onto each node.

    The agent (root) node is absent from ranked_blast_radius, so it gets the
    top score in the graph -- it is the hub every other asset is reached
    from, and should render at least as large as the biggest downstream asset.
    """
    scores_by_id = {r["node_id"]: r for r in ranked}
    max_score = max((r["blast_radius_score"] for r in ranked), default=10)

    nodes = []
    for node in graph["nodes"]:
        merged = dict(node)
        rank = scores_by_id.get(node["id"])
        if rank:
            merged["sensitivity"] = rank["sensitivity"]
            merged["ease_of_reach"] = rank["ease_of_reach"]
            merged["blast_radius_score"] = rank["blast_radius_score"]
        elif node["type"] == "agent":
            merged["blast_radius_score"] = max_score
        else:
            merged.setdefault("blast_radius_score", 0)
        nodes.append(merged)
    return nodes


def _safe_json_for_script(obj) -> str:
    """json.dumps() output embedded directly inside a <script> block is
    vulnerable to premature tag closure: if the serialized string contains
    a literal "</script>" substring -- e.g. from a malicious tool/skill
    name in the scanned config -- the HTML PARSER closes the script tag
    right there (it has no notion of "inside a JS string literal"), and
    whatever follows can execute as a new, literal script tag. Escaping
    "</" to "<\\/" is a no-op for JSON semantics (both parse to the same
    string) but makes this byte sequence impossible to produce."""
    return json.dumps(obj).replace("</", "<\\/")


def render(graph_output: dict) -> str:
    graph = graph_output["graph"]
    ranked = graph_output.get("ranked_blast_radius", [])

    nodes = _annotate_nodes(graph, ranked)
    data = {"nodes": nodes, "edges": graph["edges"]}

    html = HTML_TEMPLATE
    html = html.replace("__DATA_JSON__", _safe_json_for_script(data))
    html = html.replace("__TYPE_COLORS_JSON__", _safe_json_for_script(TYPE_COLORS))
    html = html.replace("__DEFAULT_COLOR_JSON__", _safe_json_for_script(DEFAULT_COLOR))
    return html


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print("Usage: python render_graph.py /path/to/graph_output.json [output.html]")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        graph_output = json.load(f)

    output_path = sys.argv[2] if len(sys.argv) == 3 else "graph_visualization.html"

    html = render(graph_output)

    with open(output_path, "w") as f:
        f.write(html)

    print(f"[Saved {output_path}]")
