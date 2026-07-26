"""
render_graph.py

Takes graph_builder.py's JSON output (graph + ranked_blast_radius) and
renders a self-contained HTML file with an interactive D3.js force-directed
blast-radius graph: sleek, compact nodes colored by type, sized by blast_radius_score,
draggable, with crisp glassmorphic pill labels, zoom/pan controls, and hover tooltips.

Usage:
    python render_graph.py /path/to/graph_output.json [output.html]
"""

import json
import sys

# Fixed categorical color order (light/dark), assigned by node type.
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
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Blast Radius Graph</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
  :root {
    --bg: #090a0f;
    --card-bg: #11131c;
    --card-border: #1e2235;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --mono: "Fira Code", monospace;
    --sans: "Inter", -apple-system, sans-serif;
  }
  html, body {
    margin: 0; padding: 0; height: 100%;
    background: var(--bg);
    color: var(--text-primary);
    font-family: var(--sans);
    overflow: hidden;
  }
  .viz-root {
    height: 100vh;
    display: flex;
    flex-direction: column;
  }
  header {
    padding: 16px 24px;
    background: #11131c;
    border-bottom: 1px solid var(--card-border);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  h1 {
    margin: 0;
    font-size: 18px;
    font-weight: 700;
    color: #ffffff;
    letter-spacing: -0.01em;
  }
  .subtitle {
    margin: 4px 0 0;
    font-size: 12px;
    color: var(--text-secondary);
  }
  #chart-wrap {
    position: relative;
    flex: 1;
    background: #06070a;
    overflow: hidden;
  }
  svg { width: 100%; height: 100%; display: block; cursor: grab; }
  svg:active { cursor: grabbing; }

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
    display: flex; align-items: center; gap: 6px;
    font-size: 11.5px; font-weight: 500; color: var(--text-secondary);
    cursor: pointer; padding: 2px 6px; border-radius: 6px;
  }
  #legend .legend-item:hover { background: rgba(255, 255, 255, 0.08); color: #fff; }
  #legend .legend-swatch { width: 10px; height: 10px; border-radius: 50%; }

  #tooltip {
    position: absolute;
    pointer-events: none;
    background: #11131c;
    border: 1px solid #1e2235;
    border-left: 3px solid #60a5fa;
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
  #tooltip .t-header { font-family: var(--mono); font-weight: 700; font-size: 13px; color: #fff; margin-bottom: 6px; }
  #tooltip .t-row { display: flex; justify-content: space-between; color: var(--text-secondary); margin-top: 4px; font-size: 11.5px; }
  #tooltip .t-val { font-family: var(--mono); color: #cbd5e1; font-weight: 600; }
</style>
</head>
<body>
<div class="viz-root">
  <header>
    <div>
      <h1>Agent Blast Radius Graph</h1>
      <p class="subtitle">Multi-hop reachability model &mdash; Drag nodes to reposition, scroll to zoom</p>
    </div>
  </header>
  <div id="chart-wrap">
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
</div>
<script>
const DATA = __DATA_JSON__;
const TYPE_COLORS = __TYPE_COLORS_JSON__;
const DEFAULT_COLOR = __DEFAULT_COLOR_JSON__;

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

const nodes = DATA.nodes.map(d => Object.assign({}, d));
const links = DATA.edges.map(d => Object.assign({}, d, { source: d.from, target: d.to }));

const maxScore = Math.max(1, ...nodes.map(d => d.blast_radius_score || 0));
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
  svg.transition().duration(450).call(zoomBehavior.transform, d3.zoomIdentity.translate(0,0).scale(1));
}

const defs = svg.append("defs");
const pattern = defs.append("pattern")
  .attr("id", "dot-grid").attr("width", 24).attr("height", 24).attr("patternUnits", "userSpaceOnUse");
pattern.append("circle").attr("cx", 12).attr("cy", 12).attr("r", 1).attr("fill", "rgba(255,255,255,0.05)");

g.append("rect").attr("x", -2000).attr("y", -2000).attr("width", 4000).attr("height", 4000).attr("fill", "url(#dot-grid)").style("pointer-events", "none");

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

const linkGroup = g.append("g");
const link = linkGroup.selectAll("line").data(links).join("line").attr("class", "link").attr("stroke-width", d => Math.max(1.5, 1 + (d.ease || 0) / 3));

const linkLabelGroup = g.append("g");
const linkLabels = linkLabelGroup.selectAll("text").data(links).join("text")
  .attr("font-family", "var(--mono)").attr("font-size", "9px").attr("fill", "rgba(255,255,255,0.35)").attr("text-anchor", "middle").text(d => d.permission || "");

const tooltip = d3.select("#tooltip");

function showTooltip(event, d) {
  const typeColor = colorFor(d.type);
  const rows = [];
  rows.push(`<div class="t-row"><span>Type</span><span class="t-val">${d.type}</span></div>`);
  if (d.sensitivity !== undefined) rows.push(`<div class="t-row"><span>Sensitivity</span><span class="t-val">${d.sensitivity}/10</span></div>`);
  if (d.ease_of_reach !== undefined) rows.push(`<div class="t-row"><span>Ease of Reach</span><span class="t-val">${d.ease_of_reach}/10</span></div>`);
  if (d.blast_radius_score !== undefined) rows.push(`<div class="t-row"><span>Blast Radius Score</span><span class="t-val" style="color:#f87171">${d.blast_radius_score}</span></div>`);
  tooltip.html(`<div class="t-header"><span>${d.label}</span></div>${rows.join("")}`);
  const wrapRect = wrap.getBoundingClientRect();
  tooltip.style("border-left-color", typeColor).style("left", (event.clientX - wrapRect.left + 16) + "px").style("top", (event.clientY - wrapRect.top + 16) + "px").style("opacity", 1);
}

function hideTooltip() { tooltip.style("opacity", 0); }

function handleMouseOver(event, d) {
  showTooltip(event, d);
  const connected = new Set([d.id]);
  links.forEach(l => { if (l.source.id === d.id) connected.add(l.target.id); if (l.target.id === d.id) connected.add(l.source.id); });
  nodeGroup.selectAll(".node-container").style("opacity", n => connected.has(n.id) ? 1 : 0.15);
  linkGroup.selectAll(".link").classed("highlighted", l => l.source.id === d.id || l.target.id === d.id);
}

function handleMouseOut() {
  hideTooltip();
  nodeGroup.selectAll(".node-container").style("opacity", 1);
  linkGroup.selectAll(".link").classed("highlighted", false);
}

const nodeGroup = g.append("g");
const nodeContainers = nodeGroup.selectAll("g").data(nodes).join("g").attr("class", "node-container node").call(drag(simulation)).on("mousemove", handleMouseOver).on("mouseleave", handleMouseOut);

nodeContainers.append("circle")
  .attr("r", d => radiusScale(d.blast_radius_score || 0))
  .attr("fill", d => colorFor(d.type))
  .attr("stroke", "#1e2235")
  .attr("stroke-width", 2);

nodeContainers.each(function(d) {
  const el = d3.select(this);
  const r = radiusScale(d.blast_radius_score || 0);
  const textNode = el.append("text").attr("class", "node-label-text").attr("dy", r + 15).text(d.label);
  const bbox = textNode.node().getBBox();
  el.insert("rect", "text").attr("class", "node-label-bg").attr("x", bbox.x - 8).attr("y", bbox.y - 4).attr("width", bbox.width + 16).attr("height", bbox.height + 8);
});

simulation.on("tick", () => {
  link.attr("x1", d => d.source.x).attr("y1", d => d.source.y).attr("x2", d => d.target.x).attr("y2", d => d.target.y);
  linkLabels.attr("x", d => (d.source.x + d.target.x) / 2).attr("y", d => (d.source.y + d.target.y) / 2);
  nodeContainers.attr("transform", d => `translate(${d.x},${d.y})`);
});

function drag(sim) {
  function dragstarted(event, d) { if (!event.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }
  function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
  function dragended(event, d) { if (!event.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }
  return d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended);
}

function filterGraph(query) {
  const q = query.trim().toLowerCase();
  if (!q) { nodeGroup.selectAll(".node-container").style("opacity", 1); return; }
  nodeGroup.selectAll(".node-container").style("opacity", d => (d.label.toLowerCase().includes(q) || d.type.toLowerCase().includes(q)) ? 1 : 0.1);
}

const typeCounts = {};
nodes.forEach(d => { typeCounts[d.type] = (typeCounts[d.type] || 0) + 1; });
const legend = d3.select("#legend");
Object.keys(typeCounts).forEach(type => {
  const item = legend.append("div").attr("class", "legend-item").on("click", () => filterGraph(type));
  item.append("div").attr("class", "legend-swatch").style("background", colorFor(type));
  item.append("span").text(type);
});
</script>
</body>
</html>
"""


def _annotate_nodes(graph: dict, ranked: list) -> list:
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

    with open(sys.argv[1], "r", encoding="utf-8") as f:
        graph_output = json.load(f)

    output_path = sys.argv[2] if len(sys.argv) == 3 else "graph_visualization.html"

    html = render(graph_output)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[Saved {output_path}]")
