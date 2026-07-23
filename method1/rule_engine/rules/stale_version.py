"""Rule: flag skills or MCP servers running versions with known issues.

This is a placeholder/starter implementation using a simple lookup table
of known-vulnerable version patterns. In production this would query a
real CVE database or advisory feed. Even the simple version is useful:
it demonstrates the rule engine's extensibility and catches the most
obvious cases.
"""

# Known-bad versions -- add entries as they're discovered.
# Format: {"package_name_pattern": {"affected_versions": [...], "advisory": "..."}}
KNOWN_VULNERABLE = {
    "server-filesystem": {
        "affected_versions": ["1.0.0", "1.0.1", "1.1.0"],
        "advisory": "MCP filesystem server <=1.1.0 allows path traversal outside allowed_paths.",
    },
    "server-shell": {
        "affected_versions": ["0.1.0", "0.2.0"],
        "advisory": "MCP shell server <=0.2.0 does not enforce sandboxing even when configured.",
    },
}


def _extract_package_name(url: str) -> str:
    """Extract a short package name from a URL like 'npm://@scope/server-filesystem'."""
    if not url:
        return ""
    # Take the last path segment
    return url.rstrip("/").rsplit("/", 1)[-1]


def check(config: dict) -> dict:
    flagged = []

    for server in config.get("mcp_servers", []):
        pkg = _extract_package_name(server.get("url", ""))
        version = server.get("raw_config", {}).get("version", "")
        if pkg in KNOWN_VULNERABLE and version in KNOWN_VULNERABLE[pkg]["affected_versions"]:
            flagged.append(
                f"{server['name']} ({pkg} v{version}): "
                f"{KNOWN_VULNERABLE[pkg]['advisory']}"
            )

    for skill in config.get("skills", []):
        version = skill.get("version", "")
        # Flag very old-looking versions with no updates (heuristic)
        # This is intentionally conservative -- better to flag and let user dismiss
        # than to miss a stale dependency
        if version and version.startswith("0.") and not skill.get("pinned", False):
            flagged.append(
                f"skill '{skill['name']}' is at pre-1.0 version {version} and unpinned "
                f"-- may be unmaintained or contain unfixed issues."
            )

    if flagged:
        return {
            "rule": "stale_version",
            "category": "versioning",
            "severity": "medium",
            "passed": False,
            "finding": f"Version concerns found: {'; '.join(flagged)}",
            "fix": (
                "Update to the latest versions of all MCP servers and skills. "
                "Pin versions explicitly and check changelogs for security fixes."
            ),
        }
    return {
        "rule": "stale_version",
        "category": "versioning",
        "severity": "info",
        "passed": True,
        "finding": "No known version issues detected.",
        "fix": None,
    }
