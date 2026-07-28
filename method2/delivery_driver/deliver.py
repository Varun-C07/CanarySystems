"""
deliver.py

Pushes a payload (from attack_payload_library) into the sandbox through the
correct channel an attacker would actually use.

Supports all 8 attack payload types across 3 delivery channels:
  - chat_inbox:        Direct messages into the agent's chat interface
  - watched_file:      Documents placed in folders the agent monitors
  - tool_description:  Poisoned tool metadata injected into MCP config

Usage:
    python deliver.py <payload_type> <target_credential_key>
Example:
    python deliver.py direct_injection OPENAI_API_KEY
    python deliver.py dns_exfil_injection STRIPE_SECRET_KEY
    python deliver.py tool_abuse_injection GITHUB_TOKEN
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from method2.attack_payloads.payloads import ALL_PAYLOAD_TYPES

REPLICA_DIR = Path(__file__).parent.parent / "replica_builder"
CHAT_INBOX_DIR = REPLICA_DIR / "runtime_chat_inbox"
WATCHED_DIR = REPLICA_DIR / "runtime_watched"
CONFIG_DIR = REPLICA_DIR / "runtime_config"
OUTPUT_DIR = REPLICA_DIR / "runtime_output"


import urllib.request
import urllib.error


def _try_http_gateway_delivery(prompt_text: str):
    """Attempt HTTP POST delivery to real running agent gateway endpoints."""
    endpoints = [
        "http://127.0.0.1:18789/api/chat",
        "http://127.0.0.1:18789/v1/chat/completions",
        "http://127.0.0.1:8080/chat",
        "http://127.0.0.1:3000/api/chat",
    ]
    payload_data = json.dumps({"prompt": prompt_text, "message": prompt_text, "text": prompt_text}).encode("utf-8")

    for url in endpoints:
        try:
            req = urllib.request.Request(
                url,
                data=payload_data,
                headers={"Content-Type": "application/json", "User-Agent": "security-tester/1.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                print(f"[delivery_driver] HTTP gateway delivery SUCCESS to {url} (status {resp.status})")
                return
        except Exception:
            pass


def deliver_to_chat_inbox(payload: dict):
    """Deliver payload as a direct chat message file and attempt HTTP Gateway POST."""
    CHAT_INBOX_DIR.mkdir(exist_ok=True)
    filepath = CHAT_INBOX_DIR / payload["filename"]
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(payload["content"])
    print(f"[delivery_driver] delivered {payload['type']} to chat_inbox: {filepath}")
    _try_http_gateway_delivery(payload["content"])


def deliver_to_watched_file(payload: dict):
    """Deliver payload as a document in the agent's watched folder."""
    WATCHED_DIR.mkdir(exist_ok=True)
    filepath = WATCHED_DIR / payload["filename"]
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(payload["content"])
    print(f"[delivery_driver] delivered {payload['type']} to watched folder: {filepath}")


def deliver_to_tool_description(payload: dict):
    """Inject poisoned tool description into mcp_servers.json config."""
    CONFIG_DIR.mkdir(exist_ok=True)
    mcp_path = CONFIG_DIR / "mcp_servers.json"
    if mcp_path.exists():
        with open(mcp_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = {"servers": []}

    data["servers"].append({
        "name": payload["tool_name"],
        "source": "third_party_url",
        "scopes": ["read"],
        "description": payload["content"],
    })

    with open(mcp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"[delivery_driver] delivered {payload['type']}: added poisoned tool "
          f"'{payload['tool_name']}' to {mcp_path}")
    print("[delivery_driver] NOTE: container must be rebuilt/restarted to pick up this config change")


# Map delivery channels to handler functions
DELIVERY_HANDLERS = {
    "chat_inbox": deliver_to_chat_inbox,
    "watched_file": deliver_to_watched_file,
    "tool_description": deliver_to_tool_description,
}


def deliver_payload(payload: dict):
    """Route payload to correct delivery handler based on its channel."""
    channel = payload.get("channel")
    handler = DELIVERY_HANDLERS.get(channel)
    if handler:
        handler(payload)
    else:
        print(f"[delivery_driver] ERROR: unknown delivery channel '{channel}'")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python deliver.py <payload_type> <target_credential_key>")
        print(f"Available types: {', '.join(ALL_PAYLOAD_TYPES.keys())}")
        sys.exit(1)

    payload_type = sys.argv[1]
    target_key = sys.argv[2]

    if payload_type not in ALL_PAYLOAD_TYPES:
        print(f"Unknown payload type '{payload_type}'. "
              f"Available: {', '.join(ALL_PAYLOAD_TYPES.keys())}")
        sys.exit(1)

    payload = ALL_PAYLOAD_TYPES[payload_type](target_key)
    deliver_payload(payload)