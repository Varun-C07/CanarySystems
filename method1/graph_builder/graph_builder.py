"""
graph_builder.py

Models the agent and every reachable asset as a directed graph.
agent -> MCP server -> external API/data store
agent -> filesystem path -> sensitive file
Each edge carries a permission label (read/write/execute) and a confidence score.
Walks outward from the agent node; ranks nodes by (sensitivity x ease of reaching).

Usage:
    python graph_builder.py /path/to/normalized_config.json
"""

import json
import sys

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
        nodes.append({
            "id": "network_exposure",
            "type": "network",
            "label": f"Network ({bind_address})",
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
    """Rank every non-agent node by (sensitivity x ease of reaching it)."""
    # Build a lookup of ease-of-reach per node id (from its incoming edge)
    ease_by_node = {}
    for edge in graph["edges"]:
        ease_by_node[edge["to"]] = edge["ease"]

    ranked = []
    for node in graph["nodes"]:
        if node["type"] == "agent":
            continue
        sensitivity = node.get("sensitivity", 5)
        ease = ease_by_node.get(node["id"], 5)
        score = sensitivity * ease
        ranked.append({
            "node_id": node["id"],
            "label": node["label"],
            "type": node["type"],
            "sensitivity": sensitivity,
            "ease_of_reach": ease,
            "blast_radius_score": score,
        })

    ranked.sort(key=lambda x: x["blast_radius_score"], reverse=True)
    return ranked


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python graph_builder.py /path/to/normalized_config.json")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        config = json.load(f)

    graph = build_graph(config)
    ranked = rank_blast_radius(graph)

    output = {
        "graph": graph,
        "ranked_blast_radius": ranked,
    }
    print(json.dumps(output, indent=2))