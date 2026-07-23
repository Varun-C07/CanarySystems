"""Rule: flag if the gateway has no authentication token set."""

def check(config: dict) -> dict:
    token_present = config.get("auth", {}).get("token_present", False)
    if not token_present:
        return {
            "rule": "auth_token",
            "category": "auth",
            "severity": "critical",
            "passed": False,
            "finding": "No auth token set on the gateway's control API. Anyone reaching the port can control the agent.",
            "fix": "Set an auth_token in the gateway config and require it on every request."
        }
    return {
        "rule": "auth_token",
        "category": "auth",
        "severity": "info",
        "passed": True,
        "finding": "Auth token is present.",
        "fix": None
    }