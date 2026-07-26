"""
intercept_hits.py

Shared utility for all interceptors (Pillar A/B/C) to write canary hits
in a consistent format to intercept_hits.json.

All interceptors call log_intercept_hit() when they detect a canary token
in any exfiltration channel. The verdict aggregator merges these hits with
the HTTP listener's canary_hits.json for a unified, multi-channel verdict.
"""

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
    _HAVE_FCNTL = True
except ImportError:
    # Windows has no fcntl -- fall back to in-process-only locking there.
    # Every writer in this project (interceptors, orchestrator) runs on
    # POSIX (macOS dev machines, Linux in Docker), so this is a documented
    # gap, not an active one.
    _HAVE_FCNTL = False

# In-process thread lock: cheap fast path so threads in the SAME process
# (the normal case -- all 3 pillars run as threads inside one orchestrator
# process) don't even need to touch the filesystem lock below to serialize.
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
    """Returns [] if the file is missing, unreadable, or contains invalid
    JSON (e.g. left truncated by a process killed mid-write) -- a bad hits
    file should never crash a caller (an interceptor logging a new hit, or
    aggregate_verdict.py reading the final results). See log_intercept_hit's
    atomic write below, which is what actually prevents this file from
    ending up truncated/invalid in the first place."""
    if not INTERCEPT_HITS_PATH.exists():
        return []
    try:
        with open(INTERCEPT_HITS_PATH, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[interceptor] WARNING: {INTERCEPT_HITS_PATH} is unreadable "
              f"({e}) -- treating as empty rather than crashing.")
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
        INTERCEPT_HITS_PATH.parent.mkdir(parents=True, exist_ok=True)
        lock_path = INTERCEPT_HITS_PATH.with_suffix(".json.lock")
        lock_file = open(lock_path, "a")
        try:
            if _HAVE_FCNTL:
                # File-level locking for multi-process coordination
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)

            hits = load_intercept_hits()
            hits.append(hit)
            # Atomic write to process-unique temp file before replace
            tmp_path = INTERCEPT_HITS_PATH.parent / (
                f"{INTERCEPT_HITS_PATH.name}.{os.getpid()}."
                f"{threading.get_ident()}.tmp"
            )
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(hits, f, indent=2)
            os.replace(tmp_path, INTERCEPT_HITS_PATH)
        finally:
            if _HAVE_FCNTL:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()

    print(f"[interceptor] CANARY CAUGHT via {channel}: {extracted_value[:40]}... "
          f"(detail: {detail[:60]})")


def scan_text_for_canaries(text: str) -> list:
    """
    Scan arbitrary text for canary token patterns.
    Returns list of matched canary strings.
    """
    return CANARY_PATTERN.findall(text)
