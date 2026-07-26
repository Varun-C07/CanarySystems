"""
build_replica.py

Spins up a containerized clone of the agent using the config discovered by
Method 1, with real credentials swapped for canaries. Never touches real secrets.

Now includes:
  - runtime_output/ volume mount for Pillar C file/exec/package exfiltration detection
  - HTTP_PROXY/HTTPS_PROXY env vars for Pillar A egress interception
  - --add-host to guarantee host.docker.internal resolves, so fake_agent.py
    can reach the Pillar B sinkhole directly (see dns_sinkhole.py)

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
    """Write .env, mcp_servers.json, and canary_mappings.json into runtime_config/,
    replacing real credentials with canaries across all storage types."""
    CONFIG_MOUNT_DIR.mkdir(exist_ok=True)
    WATCHED_MOUNT_DIR.mkdir(exist_ok=True)
    CHAT_INBOX_MOUNT_DIR.mkdir(exist_ok=True)
    OUTPUT_MOUNT_DIR.mkdir(exist_ok=True)

    # Build .env with canary values substituted in place of real ones
    env_lines = []
    mappings = []

    for cred in normalized_config.get("credentials", []):
        key = cred["key"]
        canary_data = canaries.get(key, {})
        canary_value = canary_data.get("value", f"CANARY_MISSING_{key}")
        env_lines.append(f"{key}={canary_value}")

        mappings.append({
            "key": key,
            "canary_value": canary_value,
            "source_file": cred.get("source_file", ".env"),
            "storage": cred.get("storage", "plaintext_env"),
            "pattern_name": cred.get("pattern_name"),
        })

    with open(CONFIG_MOUNT_DIR / ".env", "w", encoding="utf-8") as f:
        f.write("\n".join(env_lines) + "\n")

    with open(CONFIG_MOUNT_DIR / "canary_mappings.json", "w", encoding="utf-8") as f:
        json.dump(mappings, f, indent=2)

    # Copy mcp_servers.json through as-is (scopes/structure matter, not secrets)
    mcp_servers = normalized_config.get("mcp_servers", [])
    with open(CONFIG_MOUNT_DIR / "mcp_servers.json", "w", encoding="utf-8") as f:
        json.dump({"servers": mcp_servers}, f, indent=2)

    print(f"[replica_builder] wrote runtime config with {len(env_lines)} canary credential(s) across all storage types")


def build_image():
    print("[replica_builder] building Docker image...")
    result = subprocess.run(
        ["docker", "build", "-t", IMAGE_NAME, str(REPLICA_DIR)],
        capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    if result.returncode != 0:
        print("[replica_builder] BUILD FAILED")
        print(result.stderr)
        sys.exit(1)
    print("[replica_builder] image built successfully")


def run_container(source_path: str = None):
    # Remove any previous instance
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)

    print("[replica_builder] starting container...")

    # Convert paths to POSIX format for Docker volume mounts (cross-platform)
    cfg_posix = CONFIG_MOUNT_DIR.resolve().as_posix()
    wat_posix = WATCHED_MOUNT_DIR.resolve().as_posix()
    inb_posix = CHAT_INBOX_MOUNT_DIR.resolve().as_posix()
    out_posix = OUTPUT_MOUNT_DIR.resolve().as_posix()

    cmd = [
        "docker", "run", "-d",
        "--name", CONTAINER_NAME,
        "-v", f"{cfg_posix}:/agent/config",
        "-v", f"{wat_posix}:/agent/watched",
        "-v", f"{inb_posix}:/agent/chat_inbox",
        "-v", f"{out_posix}:/agent/output",
    ]

    # Mount real agent codebase into /agent/source READ-ONLY (:ro) for host safety
    if source_path and Path(source_path).exists():
        src_posix = Path(source_path).resolve().as_posix()
        cmd.extend(["-v", f"{src_posix}:/agent/source:ro"])
        print(f"[replica_builder] mounting target agent workspace (READ-ONLY): {src_posix} -> /agent/source:ro")

    cmd.extend([
        "--add-host=host.docker.internal:host-gateway",
        IMAGE_NAME,
    ])

    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        print("[replica_builder] RUN FAILED")
        print(result.stderr)
        sys.exit(1)
    print(f"[replica_builder] container running as '{CONTAINER_NAME}'")
    print(f"[replica_builder] volume mounts:")
    print(f"  config:     {cfg_posix} -> /agent/config")
    print(f"  watched:    {wat_posix} -> /agent/watched")
    print(f"  chat_inbox: {inb_posix} -> /agent/chat_inbox")
    print(f"  output:     {out_posix} -> /agent/output")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python build_replica.py /path/to/report.json /path/to/canaries.json")
        sys.exit(1)

    with open(sys.argv[1], "r", encoding="utf-8") as f:
        normalized_config = json.load(f)

    with open(sys.argv[2], "r", encoding="utf-8") as f:
        canaries = json.load(f)

    source_path = normalized_config.get("source_path")
    prepare_runtime_config(normalized_config, canaries)
    build_image()
    run_container(source_path)