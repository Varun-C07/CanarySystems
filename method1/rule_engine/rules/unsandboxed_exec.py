"""Rule: flag MCP servers with 'execute' scope where sandboxing is disabled.

An unsandboxed shell-exec tool gives an attacker arbitrary command execution
on the host machine if the agent is compromised -- one of the most dangerous
configurations possible.
"""


def check(config: dict) -> dict:
    findings = []
    for server in config.get("mcp_servers", []):
        if "execute" in server.get("scopes", []):
            raw_config = server.get("raw_config", {})
            # Flag if explicitly unsandboxed, OR if sandboxed key is absent
            # (default-open is just as dangerous as explicitly disabled)
            if not raw_config.get("sandboxed", False):
                findings.append(server["name"])

    if findings:
        return {
            "rule": "unsandboxed_exec",
            "category": "permissions",
            "severity": "critical",
            "passed": False,
            "finding": (
                f"MCP server(s) with unsandboxed execute access: {', '.join(findings)}. "
                f"An attacker can run arbitrary commands on the host."
            ),
            "fix": (
                "Enable sandboxing on execute-capable tools, or remove execute scope "
                "if shell access is not required. If needed, restrict to an allowlist "
                "of safe commands."
            ),
        }
    return {
        "rule": "unsandboxed_exec",
        "category": "permissions",
        "severity": "info",
        "passed": True,
        "finding": "No unsandboxed execute-capable MCP servers found.",
        "fix": None,
    }
