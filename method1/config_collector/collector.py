"""
config_collector.py

Read-only filesystem walker for OpenClaw-style agent configs.
Reads: settings file, .env, MCP server manifest, skills directory.
Outputs a normalized internal schema, independent of the underlying
agent's native config format.

Usage:
    python collector.py /path/to/sample_configs/openclaw_default
"""

import json
import os
import re
import sys
from pathlib import Path

import math

CREDENTIAL_KEY_PATTERN = re.compile(
    r"(API_KEY|SECRET|TOKEN|PASSWORD|ACCESS_KEY|DATABASE_URL|KEY|AUTH|PASS|CRED|PRIVATE)", re.IGNORECASE
)


def calculate_entropy(s: str) -> float:
    """Calculate Shannon Entropy of a string to measure randomness/information density."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log2(p) for p in prob])


def mask_value(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def read_settings(config_dir: Path) -> dict:
    settings_path = config_dir / "settings.json"
    if not settings_path.exists():
        return {"network": {}, "auth": {}, "_missing": True}

    with open(settings_path, "r") as f:
        raw = json.load(f)

    gateway = raw.get("gateway", {})
    return {
        "network": {
            "bind_address": gateway.get("bind_address", "unknown"),
            "port": gateway.get("port"),
            "tls_enabled": gateway.get("tls_enabled", False),
        },
        "auth": {
            "token_present": gateway.get("auth_token") is not None
        },
    }


def read_env_credentials(config_dir: Path) -> list:
    env_path = config_dir / ".env"
    if not env_path.exists():
        return []

    credentials = []
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()

            # Detect by name pattern OR high entropy (> 3.5 for strings >= 12 chars) OR structural secrets
            is_named_cred = bool(CREDENTIAL_KEY_PATTERN.search(key))
            entropy = calculate_entropy(value)
            is_high_entropy = len(value) >= 12 and entropy >= 3.5

            if is_named_cred or is_high_entropy:
                credentials.append({
                    "key": key,
                    "value_masked": mask_value(value),
                    "source_file": ".env",
                    "storage": "plaintext_env",
                    "detection_reason": "name_pattern" if is_named_cred else "high_entropy",
                    "entropy_score": round(entropy, 2)
                })
    return credentials


def read_mcp_servers(config_dir: Path) -> list:
    mcp_path = config_dir / "mcp_servers.json"
    if not mcp_path.exists():
        return []

    with open(mcp_path, "r") as f:
        raw = json.load(f)

    servers = []
    for entry in raw.get("servers", []):
        servers.append({
            "name": entry.get("name", "unknown"),
            "source": entry.get("source", "unknown"),
            "scopes": entry.get("scopes", []),
            "url": entry.get("url", ""),
            "description": entry.get("description", ""),
            "raw_config": entry.get("config", {}),
            "raw_entry": entry,  # Allows rules to inspect arbitrary 3rd party attributes
        })
    return servers


def read_skills(config_dir: Path) -> list:
    skills_dir = config_dir / "skills"
    if not skills_dir.exists() or not skills_dir.is_dir():
        return []

    skills = []
    for skill_file in skills_dir.glob("*.json"):
        with open(skill_file, "r") as f:
            raw = json.load(f)
        skills.append({
            "name": raw.get("name", skill_file.stem),
            "author": raw.get("author", "unknown"),
            "version": raw.get("version", "unknown"),
            "pinned": raw.get("pinned", False),
            "source": raw.get("source", "unknown"),
        })
    return skills


def collect(config_dir_str: str) -> dict:
    config_dir = Path(config_dir_str)
    if not config_dir.exists():
        raise FileNotFoundError(f"Config directory not found: {config_dir_str}")

    settings = read_settings(config_dir)

    normalized = {
        "source_path": str(config_dir.resolve()),
        "network": settings["network"],
        "auth": settings["auth"],
        "credentials": read_env_credentials(config_dir),
        "mcp_servers": read_mcp_servers(config_dir),
        "skills": read_skills(config_dir),
    }
    return normalized


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python collector.py /path/to/config_dir")
        sys.exit(1)

    result = collect(sys.argv[1])
    print(json.dumps(result, indent=2))