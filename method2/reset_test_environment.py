"""
reset_test_environment.py

Clears all artifacts from previous test runs so each new test starts clean:
- stops/removes the running sandbox container
- clears watched folder, chat inbox, canary hits log, verdict
- keeps canaries.json (regenerated fresh by canary_seeder each run anyway)

Usage:
    python reset_test_environment.py
"""

import subprocess
from pathlib import Path

REPLICA_DIR = Path(__file__).parent / "replica_builder"
LISTENER_DIR = Path(__file__).parent / "listener_service"
VERDICT_DIR = Path(__file__).parent / "verdict_aggregator"
CANARY_DIR = Path(__file__).parent / "canary_seeder"

CONTAINER_NAME = "agent-sandbox-instance"


def stop_container():
    print("[reset] stopping and removing sandbox container...")
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)


def clear_folder(folder: Path):
    if folder.exists():
        for f in folder.glob("*"):
            if f.is_file():
                f.unlink()
        print(f"[reset] cleared {folder}")


def clear_file(filepath: Path):
    if filepath.exists():
        filepath.unlink()
        print(f"[reset] removed {filepath}")


if __name__ == "__main__":
    stop_container()

    clear_folder(REPLICA_DIR / "runtime_watched")
    clear_folder(REPLICA_DIR / "runtime_chat_inbox")
    clear_folder(REPLICA_DIR / "runtime_output")

    clear_file(LISTENER_DIR / "canary_hits.json")
    clear_file(LISTENER_DIR / "intercept_hits.json")
    clear_file(VERDICT_DIR / "verdict.json")
    clear_file(CANARY_DIR / "canaries.json")

    print("[reset] environment reset complete. Ready for a fresh test run.")