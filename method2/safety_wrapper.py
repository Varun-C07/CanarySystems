"""
safety_wrapper.py

Enforces explicit consent before any attack test runs, and provides a
dry-run mode plus a kill switch to immediately halt an active test.

This wraps run_full_attack_suite.py -- it should be the actual entry point
a user runs, not run_full_attack_suite.py directly.

Usage:
    python safety_wrapper.py /path/to/machine_report.json [--dry-run]
    python safety_wrapper.py --kill
"""

import json
import subprocess
import sys
from pathlib import Path

METHOD2_DIR = Path(__file__).parent
ORCHESTRATOR = METHOD2_DIR / "run_full_attack_suite.py"
CONSENT_FLAG_FILE = METHOD2_DIR / ".consent_given"

PYTHON = sys.executable


def request_consent() -> bool:
    print("=" * 60)
    print("SECURITY TEST AUTHORIZATION REQUIRED")
    print("=" * 60)
    print("""
This tool will:
  - Build and run a Docker container simulating your agent's configuration
  - Plant fake (canary) credentials, never your real ones
  - Attempt to trigger the agent into leaking those fake credentials
  - Log all activity for the resulting report

This should ONLY be run against an agent configuration you own or have
explicit written authorization to test. Do not run this against systems
you do not control.
""")
    response = input("Type 'I AGREE' to proceed, or anything else to cancel: ").strip()
    return response == "I AGREE"


def kill_switch():
    print("[safety] KILL SWITCH ACTIVATED")
    subprocess.run(["docker", "rm", "-f", "agent-sandbox-instance"], capture_output=True)
    print("[safety] sandbox container forcibly stopped and removed.")
    print("[safety] any in-flight attack delivery is halted; no further payloads will be sent.")


def dry_run(machine_report_path: str):
    """In dry-run mode, generate and display the attack plan without
    touching any system. Shows which targets would be attacked, with
    which payload types, and what canary values would be generated."""
    print("=" * 60)
    print("DRY RUN MODE")
    print("=" * 60)
    print("""
No systems will be touched. This shows what WOULD happen in a live run.
""")

def dry_run(machine_report_path: str):
    """In dry-run mode, generate and display the attack plan without
    touching any system. Shows which targets would be attacked, with
    which payload types, and what canary values would be generated."""
    print("=" * 60)
    print("DRY RUN MODE")
    print("=" * 60)
    print("""
No systems will be touched. This shows what WOULD happen in a live run.
""")

    try:
        with open(machine_report_path, "r", encoding="utf-8") as f:
            machine_report = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[safety] could not load report: {e}")
        return

    # Show what Method 1 found
    failed_rules = machine_report.get("failed_rules", [])
    print(f"Method 1 found {len(failed_rules)} issue(s):")
    for rule in failed_rules:
        print(f"  [{rule['severity'].upper()}] {rule['rule']}: {rule['finding']}")
    print()

    # Show attack targets
    top_targets = machine_report.get("top_attack_targets", [])
    credential_targets = [t for t in top_targets if t["type"] == "credential"]

    if not credential_targets:
        print("[safety] no credential targets found - nothing to attack.")
        return

    PROJECT_ROOT = METHOD2_DIR.parent
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

    from method2.run_full_attack_suite import ATTACK_TYPES
    pairings = []
    for i, attack_type in enumerate(ATTACK_TYPES):
        target = credential_targets[i % len(credential_targets)]
        pairings.append((attack_type, target["label"], target["blast_radius_score"]))

    print(f"Attack plan ({len(pairings)} attack(s) across all 6 exfiltration channels):")
    for attack_type, target_label, score in pairings:
        print(f"  {attack_type:28s} -> {target_label:22s} (blast score: {score})")
    print()

    # Show what canary values would look like
    print("Example canary values that would be generated:")
    sys.path.insert(0, str(METHOD2_DIR.parent))
    from method2.canary_seeder.seed_canaries import generate_canary_value
    for target in credential_targets:
        key = target["label"]
        example, _tag = generate_canary_value(key, "DRYRUN_example123")
        print(f"  {key:25s} -> {example}")
    print()

    print("[safety] dry run complete - no systems were touched.")


if __name__ == "__main__":
    if "--kill" in sys.argv:
        kill_switch()
        sys.exit(0)

    if len(sys.argv) < 2:
        print(f"Usage: {PYTHON} safety_wrapper.py /path/to/report.json [--dry-run]")
        print(f"       {PYTHON} safety_wrapper.py --kill")
        sys.exit(1)

    machine_report_path = sys.argv[1]
    is_dry_run = "--dry-run" in sys.argv

    if is_dry_run:
        dry_run(machine_report_path)
        sys.exit(0)

    if not request_consent():
        print("[safety] consent not given. Aborting.")
        sys.exit(1)

    print("\n[safety] consent recorded. Proceeding with live test.\n")
    print(f"[safety] TIP: you can run '{PYTHON} safety_wrapper.py --kill' in another")
    print("[safety] terminal at any time to immediately halt this test.\n")

    subprocess.run([PYTHON, str(ORCHESTRATOR), machine_report_path])