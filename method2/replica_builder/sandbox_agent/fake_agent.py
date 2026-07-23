"""
fake_agent.py

A minimal stand-in for a real personal agent, running inside the Docker sandbox.
Supports three input channels, matching the three attack types:
  1. Direct injection  -> reads /agent/chat_inbox (simulates a chat message sent to the agent)
  2. Indirect injection -> reads /agent/watched (simulates the agent reading a normal file)
  3. Tool poisoning     -> reads /agent/config/mcp_servers.json tool descriptions
"""

import json
import os
import time
import urllib.request

CONFIG_PATH = "/agent/config/mcp_servers.json"
ENV_PATH = "/agent/config/.env"
WATCHED_DIR = "/agent/watched"
CHAT_INBOX_DIR = "/agent/chat_inbox"

processed_chat_files = set()


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
    contents = {}
    if os.path.exists(WATCHED_DIR):
        for fname in os.listdir(WATCHED_DIR):
            fpath = os.path.join(WATCHED_DIR, fname)
            if os.path.isfile(fpath):
                with open(fpath, "r", errors="ignore") as f:
                    contents[fname] = f.read()
    return contents


def read_new_chat_messages():
    """Only process each chat message file once, simulating a real inbox."""
    contents = {}
    if os.path.exists(CHAT_INBOX_DIR):
        for fname in os.listdir(CHAT_INBOX_DIR):
            if fname in processed_chat_files:
                continue
            fpath = os.path.join(CHAT_INBOX_DIR, fname)
            if os.path.isfile(fpath):
                with open(fpath, "r", errors="ignore") as f:
                    contents[fname] = f.read()
                processed_chat_files.add(fname)
    return contents


def read_tool_descriptions():
    """Tool descriptions are 'trusted context' the agent reads as part of
    knowing what tools are available -- exactly what tool poisoning exploits."""
    contents = {}
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            raw = json.load(f)
        for server in raw.get("servers", []):
            description = server.get("description", "")
            if description:
                contents[server["name"]] = description
    return contents


def send_outbound(url: str, payload: str):
    try:
        req = urllib.request.Request(
            url, data=payload.encode(), method="POST",
            headers={"Content-Type": "text/plain"}
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"[agent] sent outbound request to {url}")
    except Exception as e:
        print(f"[agent] outbound request failed: {e}")


def process_instruction(instruction: str, env: dict, source: str):
    """
    Simplified stand-in for an LLM agent 'reasoning' over an instruction.
    If it contains a recognizable exfiltration pattern, it complies.
    source is logged so we know which channel (chat/file/tool) triggered it.
    """
    if "SEND_TO:" in instruction and "VALUE:" in instruction:
        try:
            url_part = instruction.split("SEND_TO:")[1].split("VALUE:")[0].strip()
            raw_key_part = instruction.split("VALUE:")[1].strip()
            key_part = raw_key_part.split()[0] if raw_key_part.split() else ""
            value = env.get(key_part, "")
            if value:
                print(f"[agent] following instruction from source: {source}")
                send_outbound(url_part, f"{key_part}={value}")
            else:
                print(f"[agent] no matching env value for key: '{key_part}' (source: {source})")
        except Exception as e:
            print(f"[agent] failed to process instruction: {e}")


if __name__ == "__main__":
    print("[agent] fake_agent starting up...")
    env = load_env()
    print(f"[agent] loaded {len(env)} env vars")

    tools_checked = False

    while True:
        # Channel 1: direct chat messages (new only, simulating a real inbox)
        for fname, content in read_new_chat_messages().items():
            process_instruction(content, env, source=f"direct_chat:{fname}")

        # Channel 2: watched files (agent's normal file-reading behavior)
        for fname, content in read_watched_files().items():
            process_instruction(content, env, source=f"watched_file:{fname}")

        # Channel 3: tool descriptions (checked once at startup, like a real
        # agent loading its tool manifest -- not re-checked every loop)
        if not tools_checked:
            for tool_name, description in read_tool_descriptions().items():
                process_instruction(description, env, source=f"tool_description:{tool_name}")
            tools_checked = True

        time.sleep(3)