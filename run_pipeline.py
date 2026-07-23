"""
run_pipeline.py

Unified CLI entry point for the Agent Security Auditor.

Usage:
    python run_pipeline.py scan <config_dir>       Run Method 1 (static scan)
    python run_pipeline.py attack <machine_report>  Run Method 2 (dynamic test)
    python run_pipeline.py full <config_dir>        Run both end-to-end
    python run_pipeline.py kill                     Emergency stop

All outputs are saved to an 'output/' directory in the project root.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
METHOD1_DIR = PROJECT_ROOT / "method1"
METHOD2_DIR = PROJECT_ROOT / "method2"
OUTPUT_DIR = PROJECT_ROOT / "output"

PYTHON = sys.executable


def ensure_output_dir():
    OUTPUT_DIR.mkdir(exist_ok=True)


def run_cmd(cmd: list, description: str, capture=True):
    print(f"\n{'-' * 50}")
    print(f"  {description}")
    print(f"{'-' * 50}")
    if capture:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        if result.returncode != 0 and result.stderr:
            print(f"ERROR: {result.stderr}")
        return result
    else:
        return subprocess.run(cmd)


def run_scan(config_dir: str):
    """Run the full Method 1 static scan pipeline."""
    ensure_output_dir()

    config_path = Path(config_dir)
    if not config_path.exists():
        print(f"Error: config directory '{config_dir}' not found.")
        sys.exit(1)

    normalized_path = OUTPUT_DIR / "normalized_config.json"
    findings_path = OUTPUT_DIR / "findings.json"
    graph_path = OUTPUT_DIR / "graph_output.json"
    machine_report_path = OUTPUT_DIR / "machine_report.json"
    human_report_path = OUTPUT_DIR / "human_report.txt"
    graph_html_path = OUTPUT_DIR / "graph_visualization.html"

    # Step 1: Collect config
    result = run_cmd(
        [PYTHON, str(METHOD1_DIR / "config_collector" / "collector.py"), config_dir],
        "Step 1/4: Collecting and normalizing agent configuration"
    )
    with open(normalized_path, "w") as f:
        f.write(result.stdout)
    print(f"  -> Saved: {normalized_path}")

    # Step 2: Run rules
    result = run_cmd(
        [PYTHON, str(METHOD1_DIR / "rule_engine" / "engine.py"), str(normalized_path)],
        "Step 2/4: Running security rules against configuration"
    )
    with open(findings_path, "w") as f:
        f.write(result.stdout)
    print(f"  -> Saved: {findings_path}")

    # Step 3: Build graph
    result = run_cmd(
        [PYTHON, str(METHOD1_DIR / "graph_builder" / "graph_builder.py"), str(normalized_path)],
        "Step 3/4: Building blast radius graph"
    )
    with open(graph_path, "w") as f:
        f.write(result.stdout)
    print(f"  -> Saved: {graph_path}")

    # Step 4: Render reports
    # The report renderer writes to CWD, so we handle it ourselves
    with open(findings_path, "r") as f:
        findings = json.load(f)
    with open(graph_path, "r") as f:
        graph_output = json.load(f)

    # Import report renderer functions directly
    sys.path.insert(0, str(PROJECT_ROOT))
    from method1.report_renderer.report_renderer import build_machine_report, build_human_report
    from method1.graph_builder.render_graph import render

    machine_report = build_machine_report(findings, graph_output)
    human_report = build_human_report(findings, graph_output)

    with open(machine_report_path, "w") as f:
        json.dump(machine_report, f, indent=2)
    with open(human_report_path, "w") as f:
        f.write(human_report)

    # Render interactive graph HTML
    html = render(graph_output)
    with open(graph_html_path, "w") as f:
        f.write(html)

    print(f"\n{'=' * 50}")
    print(f"  METHOD 1 SCAN COMPLETE")
    print(f"{'=' * 50}")
    print(human_report)
    print(f"\nAll outputs saved strictly to: {OUTPUT_DIR}/")
    print(f"  * machine_report.json       (feeds Method 2)")
    print(f"  * human_report.txt          (human-readable summary)")
    print(f"  * graph_visualization.html  (interactive map)")
    print(f"\nTo run the dynamic attack test:")
    print(f"  {PYTHON} run_pipeline.py attack {machine_report_path}")

    return str(machine_report_path)


def run_attack(machine_report_path: str):
    """Run the full Method 2 dynamic attack pipeline."""
    if not Path(machine_report_path).exists():
        print(f"Error: machine report '{machine_report_path}' not found.")
        print(f"Run '{PYTHON} run_pipeline.py scan <config_dir>' first.")
        sys.exit(1)

    run_cmd(
        [PYTHON, str(METHOD2_DIR / "run_full_attack_suite.py"), machine_report_path],
        "Running Method 2: Dynamic canary injection test",
        capture=False,
    )


def run_full(config_dir: str):
    """Run both Method 1 and Method 2 end-to-end."""
    machine_report_path = run_scan(config_dir)

    print(f"\n{'=' * 50}")
    print(f"  PROCEEDING TO METHOD 2 (DYNAMIC TEST)")
    print(f"{'=' * 50}\n")

    run_attack(machine_report_path)


def run_kill():
    """Emergency stop."""
    subprocess.run(["docker", "rm", "-f", "agent-sandbox-instance"], capture_output=True)
    print("[kill] sandbox container stopped and removed.")


def print_usage():
    print(f"""
Agent Security Auditor — Unified CLI

Usage:
    {PYTHON} run_pipeline.py scan <config_dir>        Static scan (Method 1)
    {PYTHON} run_pipeline.py attack <machine_report>   Dynamic test (Method 2)
    {PYTHON} run_pipeline.py full <config_dir>         Both end-to-end
    {PYTHON} run_pipeline.py kill                      Emergency stop

Examples:
    {PYTHON} run_pipeline.py scan sample_configs/openclaw_default
    {PYTHON} run_pipeline.py full sample_configs/openclaw_default
    {PYTHON} run_pipeline.py attack output/machine_report.json
""")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    command = sys.argv[1]

    if command == "scan":
        if len(sys.argv) != 3:
            print(f"Usage: {PYTHON} run_pipeline.py scan <config_dir>")
            sys.exit(1)
        run_scan(sys.argv[2])

    elif command == "attack":
        if len(sys.argv) != 3:
            print(f"Usage: {PYTHON} run_pipeline.py attack <machine_report>")
            sys.exit(1)
        run_attack(sys.argv[2])

    elif command == "full":
        if len(sys.argv) != 3:
            print(f"Usage: {PYTHON} run_pipeline.py full <config_dir>")
            sys.exit(1)
        run_full(sys.argv[2])

    elif command == "kill":
        run_kill()

    else:
        print(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)
