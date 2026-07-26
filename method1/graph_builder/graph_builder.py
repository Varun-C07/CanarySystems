"""
graph_builder.py

Models the agent and every reachable asset as a directed graph.
agent -> MCP server -> external API/data store
agent -> filesystem path -> sensitive file
Each edge carries a permission label (read/write/execute) and a confidence score.

Uses BFS from the agent node to compute cumulative ease-of-reach through
multi-hop paths. Ranks nodes by (sensitivity x cumulative ease of reaching).

Usage:
    python graph_builder.py /path/to/normalized_config.json
"""

import json
import sys
from collections import defaultdict, deque

# Sensitivity scores: how bad is it if this asset is reached (0-10)
SENSITIVITY_SCORES = {
    "credential": 10,
    "filesystem_root": 9,
    "filesystem_scoped": 5,
    "mcp_server_write": 7,
    "mcp_server_read": 3,
    "mcp_server_execute": 9,
    "skill_unverified": 6,
    "skill_verified": 2,
    "network_exposed_no_auth": 9,
    "network_exposed_with_auth": 4,
}

# Ease of reaching: how easy is it for an attacker to reach this node (0-10, 10 = trivial)
def ease_score(edge_type: str, has_auth: bool, is_root_scope: bool) -> int:
    base = 5
    if edge_type == "network" and not has_auth:
        base = 9
    if is_root_scope:
        base += 2
    return min(base, 10)


def build_graph(config: dict) -> dict:
    nodes = [{"id": "agent", "type": "agent", "label": "Agent"}]
    edges = []

    has_auth = config.get("auth", {}).get("token_present", False)

    # Network exposure node
    bind_address = config.get("network", {}).get("bind_address", "unknown")
    if bind_address != "127.0.0.1":
        net_sensitivity = (
            SENSITIVITY_SCORES["network_exposed_no_auth"]
            if not has_auth
            else SENSITIVITY_SCORES["network_exposed_with_auth"]
        )
        nodes.append({
            "id": "network_exposure",
            "type": "network",
            "label": f"Network ({bind_address})",
            "sensitivity": net_sensitivity,
        })
        edges.append({
            "from": "agent",
            "to": "network_exposure",
            "permission": "control",
            "ease": ease_score("network", has_auth, False),
        })

    # Credential nodes
    for cred in config.get("credentials", []):
        node_id = f"cred_{cred['key']}"
        nodes.append({
            "id": node_id,
            "type": "credential",
            "label": cred["key"],
            "sensitivity": SENSITIVITY_SCORES["credential"],
        })
        edges.append({
            "from": "agent",
            "to": node_id,
            "permission": "read",
            "ease": 8,  # plaintext env vars are easy to reach if agent is compromised
        })

    # MCP server nodes
    for server in config.get("mcp_servers", []):
        node_id = f"mcp_{server['name']}"
        scopes = server.get("scopes", [])
        allowed_paths = server.get("raw_config", {}).get("allowed_paths", [])
        is_root_scope = "/" in allowed_paths

        if "execute" in scopes:
            sensitivity = SENSITIVITY_SCORES["mcp_server_execute"]
        elif "write" in scopes:
            sensitivity = SENSITIVITY_SCORES["mcp_server_write"]
        else:
            sensitivity = SENSITIVITY_SCORES["mcp_server_read"]

        if is_root_scope:
            sensitivity = min(sensitivity + 2, 10)

        nodes.append({
            "id": node_id,
            "type": "mcp_server",
            "label": server["name"],
            "sensitivity": sensitivity,
            "source": server.get("source"),
            "scopes": scopes,
        })
        edges.append({
            "from": "agent",
            "to": node_id,
            "permission": "/".join(scopes) if scopes else "unknown",
            "ease": ease_score("tool", has_auth, is_root_scope),
        })

        # If root filesystem write, add a downstream "sensitive file" node
        if is_root_scope and "write" in scopes:
            file_node_id = f"{node_id}_filesystem_root"
            nodes.append({
                "id": file_node_id,
                "type": "filesystem",
                "label": "Entire filesystem (root scope)",
                "sensitivity": SENSITIVITY_SCORES["filesystem_root"],
            })
            edges.append({
                "from": node_id,
                "to": file_node_id,
                "permission": "write",
                "ease": 8,
            })

    # Skill nodes
    for skill in config.get("skills", []):
        node_id = f"skill_{skill['name']}"
        sensitivity = (
            SENSITIVITY_SCORES["skill_unverified"]
            if not skill.get("pinned", False)
            else SENSITIVITY_SCORES["skill_verified"]
        )
        nodes.append({
            "id": node_id,
            "type": "skill",
            "label": skill["name"],
            "sensitivity": sensitivity,
            "pinned": skill.get("pinned", False),
            "source": skill.get("source"),
        })
        edges.append({
            "from": "agent",
            "to": node_id,
            "permission": "execute",
            "ease": ease_score("skill", has_auth, False),
        })

    return {"nodes": nodes, "edges": edges}


def rank_blast_radius(graph: dict) -> list:
    """Rank every non-agent node by (sensitivity x cumulative ease of reaching it).

    Uses BFS from the agent node to compute cumulative ease through
    multi-hop paths. For nodes reachable via multiple paths, takes the
    maximum cumulative ease (worst case for the defender).
    """
    # Build adjacency list
    adjacency = defaultdict(list)
    for edge in graph["edges"]:
        adjacency[edge["from"]].append((edge["to"], edge["ease"]))

    # BFS from agent -- compute cumulative ease
    # Cumulative ease for a path is: product of (ease/10) along each hop, * 10
    # This models the idea that each hop's difficulty compounds
    cumulative_ease = {}
    queue = deque([("agent", 10)])  # agent itself is trivially reachable (ease=10)

    while queue:
        current_node, current_ease = queue.popleft()

        for neighbor, edge_ease in adjacency[current_node]:
            # Cumulative ease: current_ease * (edge_ease / 10)
            # This means a 2-hop path through ease=7 then ease=8 gives: 10 * 0.7 * 0.8 = 5.6
            new_ease = current_ease * (edge_ease / 10.0)

            if neighbor not in cumulative_ease or new_ease > cumulative_ease[neighbor]:
                cumulative_ease[neighbor] = new_ease
                queue.append((neighbor, new_ease))

    # Build node lookup
    node_by_id = {n["id"]: n for n in graph["nodes"]}

    ranked = []
    for node in graph["nodes"]:
        if node["type"] == "agent":
            continue
        sensitivity = node.get("sensitivity", 5)
        ease = cumulative_ease.get(node["id"], 5)
        score = round(sensitivity * ease, 1)
        ranked.append({
            "node_id": node["id"],
            "label": node["label"],
            "type": node["type"],
            "sensitivity": sensitivity,
            "ease_of_reach": round(ease, 1),
            "blast_radius_score": score,
        })

    ranked.sort(key=lambda x: x["blast_radius_score"], reverse=True)
    return ranked


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python graph_builder.py /path/to/normalized_config.json")
        sys.exit(1)

    with open(sys.argv[1], "r", encoding="utf-8") as f:
        config = json.load(f)

    graph = build_graph(config)
    ranked = rank_blast_radius(graph)

    output = {
        "graph": graph,
        "ranked_blast_radius": ranked,
    }
    print(json.dumps(output, indent=2))