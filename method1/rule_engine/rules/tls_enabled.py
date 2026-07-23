"""Rule: flag if TLS is disabled, meaning credentials could transmit in plaintext."""

def check(config: dict) -> dict:
    tls_enabled = config.get("network", {}).get("tls_enabled", False)
    bind_address = config.get("network", {}).get("bind_address", "unknown")
    if not tls_enabled and bind_address != "127.0.0.1":
        return {
            "rule": "tls_enabled",
            "category": "network",
            "severity": "high",
            "passed": False,
            "finding": "TLS is disabled on a non-loopback binding. Traffic, including credentials, can be intercepted.",
            "fix": "Enable TLS, or restrict binding to localhost only."
        }
    return {
        "rule": "tls_enabled",
        "category": "network",
        "severity": "info",
        "passed": True,
        "finding": "TLS enabled or binding is loopback-only.",
        "fix": None
    }