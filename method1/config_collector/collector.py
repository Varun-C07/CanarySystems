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

CREDENTIAL_KEY_PATTERN = re.compile(
    r"(API_KEY|SECRET|TOKEN|PASSWORD|ACCESS_KEY|DATABASE_URL)", re.IGNORECASE
)


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
            if CREDENTIAL_KEY_PATTERN.search(key):
                credentials.append({
                    "key": key,
                    "value_masked": mask_value(value),
                    "source_file": ".env",
                    "storage": "plaintext_env",
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
            "raw_config": entry.get("config", {}),
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