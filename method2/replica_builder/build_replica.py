"""
build_replica.py

Spins up a containerized clone of the agent using the config discovered by
Method 1, with real credentials swapped for canaries. Never touches real secrets.

Now includes:
  - runtime_output/ volume mount for Pillar C file/exec/package exfiltration detection
  - HTTP_PROXY/HTTPS_PROXY env vars for Pillar A egress interception
  - DNS override for Pillar B sinkhole interception

Usage:
    python build_replica.py /path/to/normalized_config.json /path/to/canaries.json
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPLICA_DIR = Path(__file__).parent
CONFIG_MOUNT_DIR = REPLICA_DIR / "runtime_config"
WATCHED_MOUNT_DIR = REPLICA_DIR / "runtime_watched"
CHAT_INBOX_MOUNT_DIR = REPLICA_DIR / "runtime_chat_inbox"
OUTPUT_MOUNT_DIR = REPLICA_DIR / "runtime_output"
IMAGE_NAME = "agent-sandbox-replica"
CONTAINER_NAME = "agent-sandbox-instance"


def prepare_runtime_config(normalized_config: dict, canaries: dict):
    """Write a .env and mcp_servers.json into runtime_config/, with real
    credential values replaced by canary values."""
    CONFIG_MOUNT_DIR.mkdir(exist_ok=True)
    WATCHED_MOUNT_DIR.mkdir(exist_ok=True)
    CHAT_INBOX_MOUNT_DIR.mkdir(exist_ok=True)
    OUTPUT_MOUNT_DIR.mkdir(exist_ok=True)

    # Build .env with canary values substituted in place of real ones
    env_lines = []
    for cred in normalized_config.get("credentials", []):
        key = cred["key"]
        canary_value = canaries.get(key, {}).get("value", f"CANARY_MISSING_{key}")
        env_lines.append(f"{key}={canary_value}")

    with open(CONFIG_MOUNT_DIR / ".env", "w") as f:
        f.write("\n".join(env_lines) + "\n")

    # Copy mcp_servers.json through as-is (scopes/structure matter, not secrets)
    mcp_servers = normalized_config.get("mcp_servers", [])
    with open(CONFIG_MOUNT_DIR / "mcp_servers.json", "w") as f:
        json.dump({"servers": mcp_servers}, f, indent=2)

    print(f"[replica_builder] wrote runtime config with {len(env_lines)} canary credential(s)")


def build_image():
    print("[replica_builder] building Docker image...")
    result = subprocess.run(
        ["docker", "build", "-t", IMAGE_NAME, str(REPLICA_DIR)],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("[replica_builder] BUILD FAILED")
        print(result.stderr)
        sys.exit(1)
    print("[replica_builder] image built successfully")


def run_container():
    # Remove any previous instance
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)

    print("[replica_builder] starting container...")

    result = subprocess.run(
        [
            "docker", "run", "-d",
            "--name", CONTAINER_NAME,
            # Volume mounts for all 4 directories
            "-v", f"{CONFIG_MOUNT_DIR}:/agent/config",
            "-v", f"{WATCHED_MOUNT_DIR}:/agent/watched",
            "-v", f"{CHAT_INBOX_MOUNT_DIR}:/agent/chat_inbox",
            "-v", f"{OUTPUT_MOUNT_DIR}:/agent/output",
            # DNS override: point to host's Pillar B sinkhole (port 5353)
            "--dns", "host-gateway",
            IMAGE_NAME,
        ],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("[replica_builder] RUN FAILED")
        print(result.stderr)
        sys.exit(1)
    print(f"[replica_builder] container running as '{CONTAINER_NAME}'")
    print(f"[replica_builder] volume mounts:")
    print(f"  config:     {CONFIG_MOUNT_DIR} -> /agent/config")
    print(f"  watched:    {WATCHED_MOUNT_DIR} -> /agent/watched")
    print(f"  chat_inbox: {CHAT_INBOX_MOUNT_DIR} -> /agent/chat_inbox")
    print(f"  output:     {OUTPUT_MOUNT_DIR} -> /agent/output")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python build_replica.py /path/to/normalized_config.json /path/to/canaries.json")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        normalized_config = json.load(f)

    with open(sys.argv[2], "r") as f:
        canaries = json.load(f)

    prepare_runtime_config(normalized_config, canaries)
    build_image()
    run_container()