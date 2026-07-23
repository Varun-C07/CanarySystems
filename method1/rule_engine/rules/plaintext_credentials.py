"""Rule: flag any credentials stored in plaintext .env rather than a secrets manager/keychain."""

def check(config: dict) -> dict:
    plaintext_creds = [c for c in config.get("credentials", []) if c.get("storage") == "plaintext_env"]
    if plaintext_creds:
        keys = ", ".join(c["key"] for c in plaintext_creds)
        return {
            "rule": "plaintext_credentials",
            "category": "credentials",
            "severity": "high",
            "passed": False,
            "finding": f"{len(plaintext_creds)} credential(s) stored in plaintext .env: {keys}.",
            "fix": "Move secrets to OS keychain or a secrets manager; inject at call time instead of storing in config."
        }
    return {
        "rule": "plaintext_credentials",
        "category": "credentials",
        "severity": "info",
        "passed": True,
        "finding": "No plaintext credentials found in .env.",
        "fix": None
    }