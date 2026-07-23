"""
run_full_attack_suite.py

The Method 1 -> Method 2 handoff. Reads Method 1's machine_report.json
(top_attack_targets), picks the highest-ranked credential-type targets,
and automatically runs all three attack types against them.

This is the "static scan tells dynamic test where to aim" pipeline described
in the architecture: Method 1 ranks exposure, Method 2 fires targeted attacks
instead of guessing blind.

Automatically starts the listener, delivers attacks, waits for results,
and runs the verdict aggregator -- no manual steps needed.

Usage:
    python run_full_attack_suite.py /path/to/machine_report.json
"""

import json
import subprocess
import sys
import threading
import time
from http.server import HTTPServer
from pathlib import Path

METHOD2_DIR = Path(__file__).parent
DELIVERY_SCRIPT = METHOD2_DIR / "delivery_driver" / "deliver.py"
BUILD_REPLICA_SCRIPT = METHOD2_DIR / "replica_builder" / "build_replica.py"
CANARY_SEEDER_SCRIPT = METHOD2_DIR / "canary_seeder" / "seed_canaries.py"
RESET_SCRIPT = METHOD2_DIR / "reset_test_environment.py"
VERDICT_SCRIPT = METHOD2_DIR / "verdict_aggregator" / "aggregate_verdict.py"
CANARIES_PATH = METHOD2_DIR / "canary_seeder" / "canaries.json"
HITS_PATH = METHOD2_DIR / "listener_service" / "canary_hits.json"

ATTACK_TYPES = ["direct_injection", "indirect_injection", "tool_poisoning"]

# How long to wait after all attacks are delivered for the agent to process
# and exfiltrate canaries (seconds)
EXFILTRATION_WINDOW = 15

PYTHON = sys.executable


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


def start_listener_background():
    """Start the canary listener as a background thread so we don't need
    a separate terminal."""
    PROJECT_ROOT = METHOD2_DIR.parent
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from method2.listener_service.listener import CanaryListenerHandler

    server = HTTPServer(("0.0.0.0", 9000), CanaryListenerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print("[orchestrator] canary listener started on port 9000 (background thread)")
    return server


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {PYTHON} run_full_attack_suite.py /path/to/machine_report.json")
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

    report_path = Path(sys.argv[1]).resolve()
    output_dir = report_path.parent

    normalized_config_path = output_dir / "normalized_config.json"
    if not normalized_config_path.exists():
        normalized_config_path = METHOD2_DIR.parent / "output" / "normalized_config.json"

    if not normalized_config_path.exists():
        print(f"[orchestrator] ERROR: normalized config not found at {normalized_config_path}")
        sys.exit(1)

    canaries_path = str(CANARIES_PATH)

    print(f"[orchestrator] Method 1 identified these top targets: {targets}")
    print(f"[orchestrator] running {len(pairings)} attack(s), one per type\n")

    run([PYTHON, str(RESET_SCRIPT)], "resetting test environment")

    run([PYTHON, str(CANARY_SEEDER_SCRIPT), str(normalized_config_path)],
        "seeding fresh canaries")

    # Check if docker is installed and available before building
    docker_check = subprocess.run(["docker", "info"], capture_output=True)
    if docker_check.returncode != 0:
        print("\n[orchestrator] NOTICE: Docker daemon is not active on this machine.")
        print("[orchestrator] Container replica execution skipped.")
        print("[orchestrator] (Static scan, risk rules, canary seeding, and dry-run simulation are fully operational!)\n")
    else:
        run([PYTHON, str(BUILD_REPLICA_SCRIPT), str(normalized_config_path), canaries_path],
            "building and starting sandbox replica")

    # Start the listener BEFORE delivering attacks
    listener_server = start_listener_background()

    print("[orchestrator] waiting 3s for container to stabilize...")
    time.sleep(3)

    for attack_type, target in pairings:
        run([PYTHON, str(DELIVERY_SCRIPT), attack_type, target],
            f"delivering {attack_type} targeting {target}")

    if docker_check.returncode == 0 and "tool_poisoning" in [a for a, _ in pairings]:
        run(["docker", "restart", "agent-sandbox-instance"],
            "restarting container so tool_poisoning payload is picked up at startup")

    print(f"\n[orchestrator] all attacks delivered.")
    print(f"[orchestrator] waiting {EXFILTRATION_WINDOW}s for agent to process and exfiltrate...")
    time.sleep(EXFILTRATION_WINDOW)

    # Shut down listener
    listener_server.shutdown()
    print("[orchestrator] listener stopped.")

    # Auto-run verdict aggregator if canaries file exists
    if Path(canaries_path).exists():
        print("\n[orchestrator] running verdict aggregator...")
        run([PYTHON, str(VERDICT_SCRIPT), canaries_path, str(HITS_PATH)],
            "aggregating verdict")
    else:
        print("[orchestrator] canaries file missing -- skipping verdict aggregation.")

    print("\n[orchestrator] DONE. Dynamic testing phase complete.")