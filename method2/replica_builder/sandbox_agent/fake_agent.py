"""
fake_agent.py

A minimal stand-in for a real personal agent, running inside the Docker sandbox.
It reads its own config/credentials from disk (like a real agent would) and
exposes a simple loop that can 'read files' and 'make outbound requests' --
enough surface area for Method 2's attack payloads to act against.

This is intentionally simple: the point is to prove the canary/attack
mechanism, not to reimplement OpenClaw.
"""

import json
import os
import time
import urllib.request

CONFIG_PATH = "/agent/config/mcp_servers.json"
ENV_PATH = "/agent/config/.env"
WATCHED_DIR = "/agent/watched"


def load_env():
    env = {}
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()
    return env


def read_watched_files():
    """Simulates the agent's normal behavior of reading files in its watched folder."""
    contents = {}
    if os.path.exists(WATCHED_DIR):
        for fname in os.listdir(WATCHED_DIR):
            fpath = os.path.join(WATCHED_DIR, fname)
            if os.path.isfile(fpath):
                with open(fpath, "r", errors="ignore") as f:
                    contents[fname] = f.read()
    return contents


def send_outbound(url: str, payload: str):
    """Simulates the agent using its web-fetch/send capability to reach an external URL."""
    try:
        req = urllib.request.Request(
            url, data=payload.encode(), method="POST",
            headers={"Content-Type": "text/plain"}
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"[agent] sent outbound request to {url}")
    except Exception as e:
        print(f"[agent] outbound request failed: {e}")


def process_instruction(instruction: str, env: dict):
    if "SEND_TO:" in instruction and "VALUE:" in instruction:
        try:
            url_part = instruction.split("SEND_TO:")[1].split("VALUE:")[0].strip()
            raw_key_part = instruction.split("VALUE:")[1].strip()
            # Only take the first line/word -- everything after VALUE: up to
            # the next whitespace/newline is the actual key name.
            key_part = raw_key_part.split()[0] if raw_key_part.split() else ""
            value = env.get(key_part, "")
            if value:
                send_outbound(url_part, f"{key_part}={value}")
            else:
                print(f"[agent] no matching env value for key: '{key_part}'")
        except Exception as e:
            print(f"[agent] failed to process instruction: {e}")


if __name__ == "__main__":
    print("[agent] fake_agent starting up...")
    env = load_env()
    print(f"[agent] loaded {len(env)} env vars")

    # Main loop: simulate the agent periodically reading its watched folder
    # (this is where indirect injection payloads will be encountered)
    while True:
        files = read_watched_files()
        for fname, content in files.items():
            process_instruction(content, env)
        time.sleep(3)