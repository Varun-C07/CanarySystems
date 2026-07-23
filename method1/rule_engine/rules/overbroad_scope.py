"""Rule: flag MCP servers with filesystem write access to root or unscoped write access."""

ROOT_PATH_PATTERNS = {"/", "C:\\", "c:\\", "*", "root"}

def check(config: dict) -> dict:
    findings = []
    for server in config.get("mcp_servers", []):
        raw_config = server.get("raw_config", {})
        raw_entry = server.get("raw_entry", {})
        scopes = server.get("scopes", [])

        # Check standard allowed_paths
        allowed_paths = raw_config.get("allowed_paths", []) or raw_entry.get("allowed_paths", [])
        has_root_path = any(p in ROOT_PATH_PATTERNS for p in allowed_paths)

        # Check custom capabilities or permissions dicts
        caps = raw_entry.get("capabilities", {})
        perms = raw_entry.get("permissions", {})

        is_write_scoped = (
            "write" in scopes or 
            caps.get("filesystem", {}).get("write") or 
            perms.get("write")
        )

        if is_write_scoped and (has_root_path or not allowed_paths):
            findings.append(server["name"])

    if findings:
        return {
            "rule": "overbroad_scope",
            "category": "permissions",
            "severity": "critical",
            "passed": False,
            "finding": f"MCP server(s) with unrestricted write access to root ('/'): {', '.join(findings)}.",
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