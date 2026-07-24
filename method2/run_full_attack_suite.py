"""
run_full_attack_suite.py

The Method 1 -> Method 2 handoff. Reads Method 1's machine_report.json
(top_attack_targets), picks the highest-ranked credential-type targets,
and automatically runs all eight attack types against them.

This is the "static scan tells dynamic test where to aim" pipeline described
in the architecture: Method 1 ranks exposure, Method 2 fires targeted attacks
instead of guessing blind.

Now starts all 3 Pillar interceptors alongside the HTTP listener:
  - Pillar A: Egress proxy (port 8080) catches outbound HTTP/S to any destination
  - Pillar B: DNS sinkhole (port 5353) catches DNS tunneling exfiltration
  - Pillar C: Volume auditor (post-execution) catches file/exec/package leaks

Automatically starts interceptors, delivers all 8 attack types, waits for
results, runs volume audit, and produces unified attributed verdict.

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
PROJECT_ROOT = METHOD2_DIR.parent

# Add project root to path for clean imports
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DELIVERY_SCRIPT = METHOD2_DIR / "delivery_driver" / "deliver.py"
BUILD_REPLICA_SCRIPT = METHOD2_DIR / "replica_builder" / "build_replica.py"
CANARY_SEEDER_SCRIPT = METHOD2_DIR / "canary_seeder" / "seed_canaries.py"
RESET_SCRIPT = METHOD2_DIR / "reset_test_environment.py"
VERDICT_SCRIPT = METHOD2_DIR / "verdict_aggregator" / "aggregate_verdict.py"
CANARIES_PATH = METHOD2_DIR / "canary_seeder" / "canaries.json"
HITS_PATH = METHOD2_DIR / "listener_service" / "canary_hits.json"
INTERCEPT_HITS_PATH = METHOD2_DIR / "listener_service" / "intercept_hits.json"

# All 8 attack types covering all 6 exfiltration channels
ATTACK_TYPES = [
    "direct_injection",         # HTTP webhook via chat message
    "indirect_injection",       # HTTP webhook via watched file
    "tool_poisoning",           # HTTP webhook via tool description
    "dns_exfil_injection",      # DNS tunneling via watched file
    "file_exfil_injection",     # File write via watched file
    "exec_exfil_injection",     # Shell exec via chat message
    "package_install_injection", # Package install via chat message
    "tool_abuse_injection",     # Tool abuse via tool description
]

# How long to wait after all attacks are delivered for the agent to process
# and exfiltrate canaries (seconds)
EXFILTRATION_WINDOW = 15

PYTHON = sys.executable


def get_credential_targets(machine_report: dict, max_targets: int = 8) -> list:
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
    """Start the canary HTTP listener as a background thread."""
    from method2.listener_service.listener import CanaryListenerHandler

    server = HTTPServer(("0.0.0.0", 9000), CanaryListenerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print("[orchestrator] Pillar A (legacy): HTTP canary listener started on port 9000")
    return server


def start_egress_interceptor():
    """Start Pillar A: transparent HTTP egress proxy."""
    try:
        from method2.interceptors.egress_interceptor import start_egress_interceptor as _start
        server = _start(port=8080)
        print("[orchestrator] Pillar A: egress interceptor started on port 8080")
        return server
    except Exception as e:
        print(f"[orchestrator] WARNING: Pillar A failed to start: {e}")
        return None


def start_dns_sinkhole():
    """Start Pillar B: DNS sinkhole interceptor."""
    try:
        from method2.interceptors.dns_sinkhole import start_dns_sinkhole as _start
        sinkhole = _start(port=5353)
        print("[orchestrator] Pillar B: DNS sinkhole started on port 5353")
        return sinkhole
    except Exception as e:
        print(f"[orchestrator] WARNING: Pillar B failed to start: {e}")
        return None


def run_volume_audit():
    """Run Pillar C: post-execution volume & process auditor."""
    try:
        from method2.interceptors.volume_auditor import run_audit
        replica_dir = METHOD2_DIR / "replica_builder"
        scan_dirs = [
            replica_dir / "runtime_output",
            replica_dir / "runtime_watched",
            replica_dir / "runtime_chat_inbox",
        ]
        total = run_audit(scan_dirs)
        print(f"[orchestrator] Pillar C: volume audit complete ({total} canary token(s) found)")
        return total
    except Exception as e:
        print(f"[orchestrator] WARNING: Pillar C audit failed: {e}")
        return 0


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

    # Pair each attack type with a credential target, cycling targets if needed
    pairings = []
    for i, attack_type in enumerate(ATTACK_TYPES):
        target = targets[i % len(targets)]
        pairings.append((attack_type, target))

    print(f"[orchestrator] Method 1 identified these top targets: {targets}")
    print(f"[orchestrator] running {len(pairings)} attack(s) across all 6 exfiltration channels\n")

    report_path = Path(sys.argv[1]).resolve()
    output_dir = report_path.parent

    normalized_config_path = output_dir / "normalized_config.json"
    if not normalized_config_path.exists():
        normalized_config_path = PROJECT_ROOT / "output" / "normalized_config.json"

    if not normalized_config_path.exists():
        print(f"[orchestrator] ERROR: normalized config not found at {normalized_config_path}")
        sys.exit(1)

    canaries_path = str(CANARIES_PATH)

    # Configure intercept hits path
    from method2.interceptors.intercept_hits import set_hits_path
    set_hits_path(INTERCEPT_HITS_PATH)

    # Step 1: Reset test environment
    run([PYTHON, str(RESET_SCRIPT)], "resetting test environment")

    # Step 2: Seed fresh canaries
    run([PYTHON, str(CANARY_SEEDER_SCRIPT), str(normalized_config_path)],
        "seeding fresh canaries")

    # Step 3: Check Docker availability and build container
    docker_check = subprocess.run(["docker", "info"], capture_output=True)
    docker_available = docker_check.returncode == 0

    if not docker_available:
        print("\n[orchestrator] NOTICE: Docker daemon is not active on this machine.")
        print("[orchestrator] Container replica execution skipped.")
        print("[orchestrator] Interceptors, payload delivery, and dry-run simulation are fully operational!\n")
    else:
        run([PYTHON, str(BUILD_REPLICA_SCRIPT), str(normalized_config_path), canaries_path],
            "building and starting sandbox replica")

    # Step 4: Start all interceptors
    print("\n" + "=" * 60)
    print("  STARTING INTERCEPTOR PILLARS")
    print("=" * 60 + "\n")

    listener_server = start_listener_background()
    egress_server = start_egress_interceptor()
    dns_sinkhole = start_dns_sinkhole()

    print("[orchestrator] waiting 3s for interceptors to stabilize...")
    time.sleep(3)

    # Step 5: Deliver all 8 attack payloads
    print("\n" + "=" * 60)
    print("  DELIVERING ATTACK PAYLOADS (8 types, 6 exfiltration channels)")
    print("=" * 60 + "\n")

    tool_poisoning_delivered = False
    for attack_type, target in pairings:
        run([PYTHON, str(DELIVERY_SCRIPT), attack_type, target],
            f"delivering {attack_type} targeting {target}")
        if "tool_poisoning" in attack_type or "tool_abuse" in attack_type:
            tool_poisoning_delivered = True

    # Restart container if tool descriptions were modified
    if docker_available and tool_poisoning_delivered:
        run(["docker", "restart", "agent-sandbox-instance"],
            "restarting container so tool_poisoning/tool_abuse payloads are picked up at startup")

    print(f"\n[orchestrator] all {len(pairings)} attacks delivered.")
    print(f"[orchestrator] waiting {EXFILTRATION_WINDOW}s for agent to process and exfiltrate...")
    time.sleep(EXFILTRATION_WINDOW)

    # Step 6: Run Pillar C volume audit (post-execution)
    print("\n" + "=" * 60)
    print("  RUNNING POST-EXECUTION AUDITS (Pillar C)")
    print("=" * 60 + "\n")
    run_volume_audit()

    # Step 7: Shut down interceptors
    print("\n[orchestrator] shutting down interceptors...")
    listener_server.shutdown()
    print("[orchestrator] HTTP listener stopped.")
    if egress_server:
        egress_server.shutdown()
        print("[orchestrator] egress interceptor stopped.")
    if dns_sinkhole:
        dns_sinkhole.stop()
        print("[orchestrator] DNS sinkhole stopped.")

    # Step 8: Run verdict aggregator
    if Path(canaries_path).exists():
        print("\n[orchestrator] running verdict aggregator...")
        run([PYTHON, str(VERDICT_SCRIPT), canaries_path, str(HITS_PATH)],
            "aggregating verdict")
    else:
        print("[orchestrator] canaries file missing -- skipping verdict aggregation.")

    print("\n[orchestrator] DONE. Dynamic testing phase complete.")