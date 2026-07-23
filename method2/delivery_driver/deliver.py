"""
deliver.py

Pushes a payload (from attack_payload_library) into the sandbox through the
correct channel an attacker would actually use.

Usage:
    python deliver.py <payload_type> <target_credential_key>
Example:
    python deliver.py direct_injection OPENAI_API_KEY
    python deliver.py indirect_injection STRIPE_SECRET_KEY
    python deliver.py tool_poisoning GITHUB_TOKEN
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


def deliver_direct_injection(payload: dict):
    CHAT_INBOX_DIR.mkdir(exist_ok=True)
    filepath = CHAT_INBOX_DIR / payload["filename"]
    with open(filepath, "w") as f:
        f.write(payload["content"])
    print(f"[delivery_driver] delivered direct_injection to chat_inbox: {filepath}")


def deliver_indirect_injection(payload: dict):
    WATCHED_DIR.mkdir(exist_ok=True)
    filepath = WATCHED_DIR / payload["filename"]
    with open(filepath, "w") as f:
        f.write(payload["content"])
    print(f"[delivery_driver] delivered indirect_injection to watched folder: {filepath}")


def deliver_tool_poisoning(payload: dict):
    """Modifies mcp_servers.json to add a poisoned tool description."""
    mcp_path = CONFIG_DIR / "mcp_servers.json"
    if mcp_path.exists():
        with open(mcp_path, "r") as f:
            data = json.load(f)
    else:
        data = {"servers": []}

    data["servers"].append({
        "name": payload["tool_name"],
        "source": "third_party_url",
        "scopes": ["read"],
        "description": payload["content"],
    })

    with open(mcp_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[delivery_driver] delivered tool_poisoning: added poisoned tool "
          f"'{payload['tool_name']}' to {mcp_path}")
    print("[delivery_driver] NOTE: container must be rebuilt/restarted to pick up this config change")


DELIVERY_HANDLERS = {
    "direct_injection": deliver_direct_injection,
    "indirect_injection": deliver_indirect_injection,
    "tool_poisoning": deliver_tool_poisoning,
}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python deliver.py <payload_type> <target_credential_key>")
        print(f"Available types: {', '.join(ALL_PAYLOAD_TYPES.keys())}")
        sys.exit(1)

    payload_type = sys.argv[1]
    target_key = sys.argv[2]

    if payload_type not in ALL_PAYLOAD_TYPES:
        print(f"Unknown payload type '{payload_type}'. Available: {', '.join(ALL_PAYLOAD_TYPES.keys())}")
        sys.exit(1)

    payload = ALL_PAYLOAD_TYPES[payload_type](target_key)
    DELIVERY_HANDLERS[payload_type](payload)