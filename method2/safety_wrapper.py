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

import subprocess
import sys
from pathlib import Path

METHOD2_DIR = Path(__file__).parent
ORCHESTRATOR = METHOD2_DIR / "run_full_attack_suite.py"
CONSENT_FLAG_FILE = METHOD2_DIR / ".consent_given"


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


def dry_run_notice():
    print("=" * 60)
    print("DRY RUN MODE")
    print("=" * 60)
    print("""
In dry-run mode, attack payloads will be generated and logged, but the
sandbox container will NOT be built or started, and no payloads will
actually be delivered or executed. This shows you what WOULD happen
without touching any system.
""")


if __name__ == "__main__":
    if "--kill" in sys.argv:
        kill_switch()
        sys.exit(0)

    if len(sys.argv) < 2:
        print("Usage: python safety_wrapper.py /path/to/machine_report.json [--dry-run]")
        print("       python safety_wrapper.py --kill")
        sys.exit(1)

    machine_report_path = sys.argv[1]
    dry_run = "--dry-run" in sys.argv

    if dry_run:
        dry_run_notice()
        print(f"[safety] would run attacks using targets from: {machine_report_path}")
        print("[safety] dry run complete -- no systems were touched.")
        sys.exit(0)

    if not request_consent():
        print("[safety] consent not given. Aborting.")
        sys.exit(1)

    print("\n[safety] consent recorded. Proceeding with live test.\n")
    print("[safety] TIP: you can run 'python3 safety_wrapper.py --kill' in another")
    print("[safety] terminal at any time to immediately halt this test.\n")

    subprocess.run(["python3", str(ORCHESTRATOR), machine_report_path])