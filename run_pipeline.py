"""
run_pipeline.py

Unified CLI entry point for the Agent Security Auditor.

Usage:
    python run_pipeline.py scan <config_dir>       Run Method 1 (static scan)
    python run_pipeline.py attack <machine_report>  Run Method 2 (dynamic test)
    python run_pipeline.py full <config_dir>        Run both end-to-end
    python run_pipeline.py kill                     Emergency stop

All outputs are saved to an 'output/' directory in the project root, unless
overridden via the AGENT_AUDITOR_OUTPUT_DIR environment variable, which
applies consistently across scan/advise/report (every place this file's own
OUTPUT_DIR constant is used).

Note: 'attack' delegates to method2/run_full_attack_suite.py, which along
with aggregate_verdict.py still writes verdict.json to a hardcoded
<project_root>/output/ regardless of this override -- those are Method 2
internals, out of scope for this override. If you use
AGENT_AUDITOR_OUTPUT_DIR, 'attack' output currently still lands in the
default output/ dir.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
METHOD1_DIR = PROJECT_ROOT / "method1"
METHOD2_DIR = PROJECT_ROOT / "method2"
OUTPUT_DIR = Path(os.environ.get("AGENT_AUDITOR_OUTPUT_DIR", str(PROJECT_ROOT / "output")))

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


def _write_step_output(result, path: Path, step_number: str, step_description: str):
    """Write a subprocess step's stdout to `path` -- but only after
    confirming the step actually succeeded. Without this check, a failed
    step's empty/partial stdout gets written anyway, the next step then
    reads that broken file and cascade-crashes too, and any *later*
    output file this run never reaches (e.g. machine_report.json) is
    silently left stale from a previous successful run with no
    indication anything went wrong on this one."""
    if result.returncode != 0:
        print(f"\nError: {step_number} ({step_description}) failed (exit code {result.returncode}).")
        print("See the output above for details. Fix the underlying issue and re-run the scan.")
        print(f"Nothing past this step was run; earlier output files in {OUTPUT_DIR}/ "
              f"(if any) are from a previous run and were not touched by this one.")
        sys.exit(result.returncode)
    with open(path, "w") as f:
        f.write(result.stdout)


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
    _write_step_output(result, normalized_path, "Step 1/4", "collecting and normalizing agent configuration")
    print(f"  -> Saved: {normalized_path}")

    # Step 2: Run rules
    result = run_cmd(
        [PYTHON, str(METHOD1_DIR / "rule_engine" / "engine.py"), str(normalized_path)],
        "Step 2/4: Running security rules against configuration"
    )
    _write_step_output(result, findings_path, "Step 2/4", "running security rules")
    print(f"  -> Saved: {findings_path}")

    # Step 3: Build graph
    result = run_cmd(
        [PYTHON, str(METHOD1_DIR / "graph_builder" / "graph_builder.py"), str(normalized_path)],
        "Step 3/4: Building blast radius graph"
    )
    _write_step_output(result, graph_path, "Step 3/4", "building blast radius graph")
    print(f"  -> Saved: {graph_path}")

    # Step 4: Render reports
    # The report renderer writes to CWD, so we handle it ourselves.
    # By this point steps 1-3 are already confirmed to have succeeded (see
    # _write_step_output above), so a JSONDecodeError here would mean the
    # file was corrupted by something outside this run -- still worth a
    # clean message instead of a raw traceback.
    try:
        with open(findings_path, "r") as f:
            findings = json.load(f)
        with open(graph_path, "r") as f:
            graph_output = json.load(f)
    except json.JSONDecodeError as e:
        print(f"\nError: Step 4/4 failed -- {findings_path.name} or {graph_path.name} "
              f"contains invalid JSON ({e}).")
        print("These were just written by steps 2-3 of this same run, so this points "
              "to a real bug rather than stale data. Please report it.")
        sys.exit(1)

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

    result = run_cmd(
        [PYTHON, str(METHOD2_DIR / "run_full_attack_suite.py"), machine_report_path],
        "Running Method 2: Dynamic canary injection test",
        capture=False,
    )
    if result.returncode != 0:
        # run_full_attack_suite.py already printed its own FATAL/error
        # detail before exiting non-zero (e.g. the sandbox container
        # failed to start) -- propagate that failure as OUR exit code too,
        # so `python3 run_pipeline.py attack ...` is reliable for anything
        # scripting against the shell exit code (CI, automation), not just
        # for someone reading the console output.
        print(f"\nMethod 2 failed (exit code {result.returncode}). See output above.")
        sys.exit(result.returncode)


def run_advise():
    """Run the AI remediation advisor (Groq) against whatever scan/attack
    output already exists in output/. Requires 'scan' to have been run
    first; picks up 'attack' output automatically if present, for
    proof-backed advice instead of static-findings-only advice."""
    machine_report_path = OUTPUT_DIR / "machine_report.json"
    if not machine_report_path.exists():
        print(f"Error: {machine_report_path} not found.")
        print(f"Run '{PYTHON} run_pipeline.py scan <config_dir>' first.")
        sys.exit(1)

    cmd = [
        PYTHON,
        str(METHOD1_DIR / "remediation_advisor" / "groq_advisor.py"),
        str(machine_report_path),
    ]

    verdict_path = OUTPUT_DIR / "verdict.json"
    if verdict_path.exists():
        cmd.append(str(verdict_path))

    result = run_cmd(cmd, "Generating AI remediation advice (Groq)", capture=False)
    if result.returncode != 0:
        sys.exit(result.returncode)


def run_report():
    """Render the single-page HTML dashboard from whatever scan/attack/advise
    output already exists in output/. Requires 'scan' to have been run
    first; picks up 'attack' and 'advise' output automatically if present."""
    machine_report_path = OUTPUT_DIR / "machine_report.json"
    if not machine_report_path.exists():
        print(f"Error: {machine_report_path} not found.")
        print(f"Run '{PYTHON} run_pipeline.py scan <config_dir>' first.")
        sys.exit(1)

    cmd = [
        PYTHON,
        str(METHOD1_DIR / "report_renderer" / "render_dashboard.py"),
        str(OUTPUT_DIR),
    ]

    result = run_cmd(cmd, "Rendering HTML dashboard", capture=False)
    if result.returncode != 0:
        sys.exit(result.returncode)


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
    {PYTHON} run_pipeline.py advise                    AI remediation advice (Groq, needs GROQ_API_KEY)
    {PYTHON} run_pipeline.py report                    Render HTML dashboard (output/dashboard.html)
    {PYTHON} run_pipeline.py kill                      Emergency stop

Examples:
    {PYTHON} run_pipeline.py scan sample_configs/openclaw_default
    {PYTHON} run_pipeline.py full sample_configs/openclaw_default
    {PYTHON} run_pipeline.py attack output/machine_report.json
    {PYTHON} run_pipeline.py advise
    {PYTHON} run_pipeline.py report
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

    elif command == "advise":
        if len(sys.argv) != 2:
            print(f"Usage: {PYTHON} run_pipeline.py advise")
            sys.exit(1)
        run_advise()

    elif command == "report":
        if len(sys.argv) != 2:
            print(f"Usage: {PYTHON} run_pipeline.py report")
            sys.exit(1)
        run_report()

    elif command == "kill":
        run_kill()

    else:
        print(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)
