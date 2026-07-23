"""Rule: flag skills that are unpinned and/or from a third-party/unverified source."""

def check(config: dict) -> dict:
    risky = []
    for skill in config.get("skills", []):
        if not skill.get("pinned", False):
            risky.append(skill["name"])

    for server in config.get("mcp_servers", []):
        if server.get("source") == "third_party_url":
            risky.append(server["name"])

    if risky:
        return {
            "rule": "unpinned_provenance",
            "category": "provenance",
            "severity": "medium",
            "passed": False,
            "finding": f"Unpinned skill(s) or third-party-sourced MCP server(s): {', '.join(risky)}.",
            "fix": "Pin skill versions; prefer official registry sources over arbitrary URLs."
        }
    return {
        "rule": "unpinned_provenance",
        "category": "provenance",
        "severity": "info",
        "passed": True,
        "finding": "All skills pinned; all MCP servers from trusted sources.",
        "fix": None
    }