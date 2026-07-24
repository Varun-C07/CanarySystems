"""
intercept_hits.py

Shared utility for all interceptors (Pillar A/B/C) to write canary hits
in a consistent format to intercept_hits.json.

All interceptors call log_intercept_hit() when they detect a canary token
in any exfiltration channel. The verdict aggregator merges these hits with
the HTTP listener's canary_hits.json for a unified, multi-channel verdict.
"""

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

# Thread-safe lock for concurrent writes from multiple interceptors
_write_lock = threading.Lock()

# Default path -- overridden by orchestrator at startup
INTERCEPT_HITS_PATH = Path(__file__).parent.parent / "listener_service" / "intercept_hits.json"

# Pattern to match any canary token embedded anywhere in text
CANARY_PATTERN = re.compile(r"CANARY_[A-Za-z0-9_]+", re.IGNORECASE)


def set_hits_path(path: Path):
    """Allow orchestrator to override the default hits path."""
    global INTERCEPT_HITS_PATH
    INTERCEPT_HITS_PATH = path


def load_intercept_hits() -> list:
    if INTERCEPT_HITS_PATH.exists():
        with open(INTERCEPT_HITS_PATH, "r") as f:
            return json.load(f)
    return []


def log_intercept_hit(
    channel: str,
    extracted_value: str,
    detail: str,
    extracted_key: str = "",
    attack_id: str = "",
):
    """
    Log a canary interception hit from any pillar.

    Args:
        channel: One of HTTP_WEBHOOK, DNS_TUNNEL, FILE_WRITE, SHELL_EXEC,
                 PACKAGE_INSTALL, TOOL_ABUSE
        extracted_value: The canary value that was detected (e.g. "sk-CANARY_123")
        detail: Human-readable description of how/where the leak was detected
        extracted_key: The credential key name if known (e.g. "OPENAI_API_KEY")
        attack_id: The ATTACK_ID tag if present in the payload
    """
    hit = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "channel": channel,
        "extracted_key": extracted_key,
        "extracted_value": extracted_value,
        "is_canary": True,
        "detail": detail,
        "attack_id": attack_id,
    }

    # Extract attack type from attack_id (e.g. "dns_exfil_injection_a1b2c3d4" -> "dns_exfil_injection")
    if attack_id:
        parts = attack_id.rsplit("_", 1)
        if len(parts) == 2:
            hit["attack_type"] = parts[0]

    with _write_lock:
        hits = load_intercept_hits()
        hits.append(hit)
        INTERCEPT_HITS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(INTERCEPT_HITS_PATH, "w") as f:
            json.dump(hits, f, indent=2)

    print(f"[interceptor] CANARY CAUGHT via {channel}: {extracted_value[:40]}... "
          f"(detail: {detail[:60]})")


def scan_text_for_canaries(text: str) -> list:
    """
    Scan arbitrary text for canary token patterns.
    Returns list of matched canary strings.
    """
    return CANARY_PATTERN.findall(text)
