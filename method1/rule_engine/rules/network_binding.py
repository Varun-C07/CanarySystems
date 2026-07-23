"""Rule: flag if the agent's gateway is bound to all interfaces instead of loopback."""

def check(config: dict) -> dict:
    bind_address = config.get("network", {}).get("bind_address", "unknown")
    if bind_address == "0.0.0.0":
        return {
            "rule": "network_binding",
            "category": "network",
            "severity": "critical",
            "passed": False,
            "finding": "Gateway is bound to 0.0.0.0 (all interfaces), reachable from LAN/internet.",
            "fix": "Bind to 127.0.0.1 (localhost) unless remote access is explicitly required."
        }
    return {
        "rule": "network_binding",
        "category": "network",
        "severity": "info",
        "passed": True,
        "finding": f"Gateway bound to {bind_address}.",
        "fix": None
    }