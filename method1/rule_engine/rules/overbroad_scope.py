"""Rule: flag MCP servers with filesystem write access to root or unscoped write access."""

def check(config: dict) -> dict:
    findings = []
    for server in config.get("mcp_servers", []):
        allowed_paths = server.get("raw_config", {}).get("allowed_paths", [])
        if "write" in server.get("scopes", []) and "/" in allowed_paths:
            findings.append(server["name"])

    if findings:
        return {
            "rule": "overbroad_scope",
            "category": "permissions",
            "severity": "critical",
            "passed": False,
            "finding": f"MCP server(s) with unrestricted write access to '/': {', '.join(findings)}.",
            "fix": "Scope filesystem write access to a specific working directory, not root."
        }
    return {
        "rule": "overbroad_scope",
        "category": "permissions",
        "severity": "info",
        "passed": True,
        "finding": "No MCP servers found with unrestricted root write access.",
        "fix": None
    }