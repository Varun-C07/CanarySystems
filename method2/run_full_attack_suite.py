"""
run_full_attack_suite.py

The Method 1 -> Method 2 handoff. Reads Method 1's machine_report.json
(top_attack_targets), picks the highest-ranked credential-type targets,
and automatically runs all three attack types against them.

This is the "static scan tells dynamic test where to aim" pipeline described
in the architecture: Method 1 ranks exposure, Method 2 fires targeted attacks
instead of guessing blind.

Usage:
    python run_full_attack_suite.py /path/to/machine_report.json
"""

import json
import subprocess
import sys
import time
from pathlib import Path

METHOD2_DIR = Path(__file__).parent
DELIVERY_SCRIPT = METHOD2_DIR / "delivery_driver" / "deliver.py"
BUILD_REPLICA_SCRIPT = METHOD2_DIR / "replica_builder" / "build_replica.py"
CANARY_SEEDER_SCRIPT = METHOD2_DIR / "canary_seeder" / "seed_canaries.py"
RESET_SCRIPT = METHOD2_DIR / "reset_test_environment.py"

ATTACK_TYPES = ["direct_injection", "indirect_injection", "tool_poisoning"]


def get_credential_targets(machine_report: dict, max_targets: int = 3) -> list:
    """Pull the highest-ranked credential-type nodes from Method 1's blast
    radius ranking -- these are the targets Method 2 will attack."""
    targets = []
    for item in machine_report.get("top_attack_targets", []):
        if item["type"] == "credential":
            targets.append(item["label"])
        if len(targets) >= max_targets:
            break
    return targets


def run(cmd: list, description: str):
    print(f"\n[orchestrator] {description}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(f"[orchestrator] WARNING: command failed: {result.stderr}")
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python run_full_attack_suite.py /path/to/machine_report.json")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        machine_report = json.load(f)

    targets = get_credential_targets(machine_report, max_targets=len(ATTACK_TYPES))
    if not targets:
        print("[orchestrator] no credential targets found in machine_report.json")
        sys.exit(1)

    # Pair each attack type with a distinct target, so all three attack types
    # get exercised against the top-ranked exposures from Method 1.
    pairings = list(zip(ATTACK_TYPES, targets))

    print(f"[orchestrator] Method 1 identified these top targets: {targets}")
    print(f"[orchestrator] running {len(pairings)} attack(s), one per type\n")

    run(["python3", str(RESET_SCRIPT)], "resetting test environment")

    normalized_config_path = "sample_configs/openclaw_default_normalized.json"
    canaries_path = str(METHOD2_DIR / "canary_seeder" / "canaries.json")

    run(["python3", str(CANARY_SEEDER_SCRIPT), normalized_config_path],
        "seeding fresh canaries")

    run(["python3", str(BUILD_REPLICA_SCRIPT), normalized_config_path, canaries_path],
        "building and starting sandbox replica")

    print("[orchestrator] waiting 3s for container to stabilize...")
    time.sleep(3)

    for attack_type, target in pairings:
        run(["python3", str(DELIVERY_SCRIPT), attack_type, target],
            f"delivering {attack_type} targeting {target}")

    if "tool_poisoning" in [a for a, _ in pairings]:
        run(["docker", "restart", "agent-sandbox-instance"],
            "restarting container so tool_poisoning payload is picked up at startup")

    print("\n[orchestrator] all attacks delivered.")
    print("[orchestrator] NOTE: start listener_service separately, then wait ~10s,")
    print("[orchestrator] then run verdict_aggregator to see results.")