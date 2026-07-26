"""
entrypoint.py

Universal container entrypoint. Loads fake canary credentials from
/agent/config/.env into process environment variables, then launches
either the real target agent (Node.js/Python) mounted at /agent/source
or falls back to the reference simulator (fake_agent.py).
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ENV_PATH = Path("/agent/config/.env")
SOURCE_DIR = Path("/agent/source")
WORKDIR = Path("/agent/workdir")
SIMULATOR_PATH = Path("/agent/fake_agent.py")
MAPPINGS_PATH = Path("/agent/config/canary_mappings.json")


def load_canary_env():
    """Load canary secrets into system environment variables."""
    if ENV_PATH.exists():
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    key, _, value = line.partition("=")
                    os.environ[key.strip()] = value.strip()
        print(f"[entrypoint] loaded canary environment variables from {ENV_PATH}")


def prepare_container_workdir() -> Path:
    """Copy read-only /agent/source into ephemeral container-local /agent/workdir.
    Guarantees user's original host files remain 100% untouched."""
    if not SOURCE_DIR.exists() or not any(SOURCE_DIR.iterdir()):
        return SOURCE_DIR

    if WORKDIR.exists():
        shutil.rmtree(WORKDIR)

    shutil.copytree(SOURCE_DIR, WORKDIR, symlinks=True)
    print(f"[entrypoint] copied read-only source to ephemeral container workdir: {WORKDIR}")
    return WORKDIR


def patch_source_canaries(workdir: Path):
    """Substitute canary credential values inside config/code files in /agent/workdir."""
    if not MAPPINGS_PATH.exists() or not workdir.exists() or workdir == SOURCE_DIR:
        return

    try:
        with open(MAPPINGS_PATH, "r", encoding="utf-8") as f:
            mappings = json.load(f)

        for m in mappings:
            rel_file = m.get("source_file")
            canary_val = m.get("canary_value")
            if not rel_file or not canary_val or rel_file == ".env":
                continue

            target_file = workdir / rel_file
            if target_file.exists() and target_file.is_file():
                try:
                    content = target_file.read_text(encoding="utf-8", errors="ignore")
                    key = m.get("key")
                    if key and key in content:
                        patched = content.replace(f'"{key}"', f'"{canary_val}"').replace(f"'{key}'", f"'{canary_val}'")
                        if patched != content:
                            target_file.write_text(patched, encoding="utf-8")
                            print(f"[entrypoint] substituted canary for {key} in container workdir file {target_file}")
                except Exception as e:
                    print(f"[entrypoint] warning patching container file {target_file}: {e}")
    except Exception as e:
        print(f"[entrypoint] error reading canary mappings: {e}")


def detect_target_command(workdir: Path) -> list | None:
    """Detect how to run the target agent inside container workdir."""
    if not workdir.exists() or workdir == SOURCE_DIR or not any(workdir.iterdir()):
        return None

    # Check for Node.js agent (e.g. OpenClaw)
    package_json = workdir / "package.json"
    if package_json.exists():
        try:
            with open(package_json, "r", encoding="utf-8") as f:
                pkg = json.load(f)
            main_file = pkg.get("main", "index.js")
            if (workdir / main_file).exists():
                return ["node", str(workdir / main_file)]
            if "scripts" in pkg and "start" in pkg["scripts"]:
                return ["npm", "start", "--prefix", str(workdir)]
        except Exception as e:
            print(f"[entrypoint] error reading package.json: {e}")

    # Check for Python agent
    for py_entry in ["main.py", "app.py", "agent.py", "run.py"]:
        if (workdir / py_entry).exists():
            return ["python3", str(workdir / py_entry)]

    return None


def main():
    load_canary_env()
    active_workdir = prepare_container_workdir()
    patch_source_canaries(active_workdir)
    target_cmd = detect_target_command(active_workdir)

    if target_cmd:
        print(f"[entrypoint] launching REAL TARGET AGENT inside container: {' '.join(target_cmd)}")
        os.chdir(active_workdir)
        proc = subprocess.run(target_cmd)
        sys.exit(proc.returncode)
    else:
        print("[entrypoint] no real agent entrypoint detected -- running reference simulator (fake_agent.py)")
        proc = subprocess.run(["python3", "-u", str(SIMULATOR_PATH)])
        sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
