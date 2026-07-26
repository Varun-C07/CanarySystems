"""
run_pipeline.py

Unified CLI entry point for the Agent Security Auditor.

Usage:
    python run_pipeline.py scan <config_dir>       Run Method 1 (static scan)
    python run_pipeline.py attack <report>         Run Method 2 (dynamic test)
    python run_pipeline.py full <config_dir>        Run both end-to-end
    python run_pipeline.py advise                   AI remediation advice
    python run_pipeline.py report                   Render HTML dashboard
    python run_pipeline.py kill                     Emergency stop

All outputs are saved to an 'output/' directory in the project root, unless
overridden via the AGENT_AUDITOR_OUTPUT_DIR environment variable.

Output files (consolidated):
    report.json       - Structured scan results (findings, graph, credentials)
    verdict.json      - Method 2 dynamic test results
    ai_remediation.md - AI-generated remediation advice
    dashboard.html    - Self-contained visual report
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
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        if result.stdout:
            print(result.stdout)
        if result.returncode != 0 and result.stderr:
            print(f"ERROR: {result.stderr}")
        return result
    else:
        return subprocess.run(cmd)


def _check_step_result(result, step_number: str, step_description: str):
    """Verify a subprocess step succeeded. If not, abort with a clean message."""
    if result.returncode != 0:
        print(f"\nError: {step_number} ({step_description}) failed (exit code {result.returncode}).")
        print("See the output above for details. Fix the underlying issue and re-run the scan.")
        print(f"Nothing past this step was run; earlier output files in {OUTPUT_DIR}/ "
              f"(if any) are from a previous run and were not touched by this one.")
        sys.exit(result.returncode)


def run_scan(config_dir: str):
    """Run the full Method 1 static scan pipeline.
    Keeps all intermediates in memory; only writes report.json to disk."""
    ensure_output_dir()

    config_path = Path(config_dir)
    if not config_path.exists():
        print(f"Error: config directory '{config_dir}' not found.")
        sys.exit(1)

    report_path = OUTPUT_DIR / "report.json"

    # Step 1: Collect config
    result = run_cmd(
        [PYTHON, str(METHOD1_DIR / "config_collector" / "collector.py"), config_dir],
        "Step 1/4: Collecting and normalizing agent configuration"
    )
    _check_step_result(result, "Step 1/4", "collecting and normalizing agent configuration")
    try:
        normalized_config = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"\nError: Step 1/4 produced invalid JSON ({e}). This is a bug — please report it.")
        sys.exit(1)
    print(f"  -> Collected {len(normalized_config.get('credentials', []))} credentials from "
          f"{config_path}")

    # Step 2: Run rules (in-process instead of subprocess for efficiency)
    sys.path.insert(0, str(PROJECT_ROOT))
    from method1.rule_engine.engine import run_rules
    print(f"\n{'-' * 50}")
    print(f"  Step 2/4: Running security rules against configuration")
    print(f"{'-' * 50}")
    findings = run_rules(normalized_config)
    failed_count = sum(1 for f in findings if not f["passed"])
    print(f"  -> {failed_count} issue(s) found, {len(findings) - failed_count} check(s) passed")

    # Step 3: Build graph (in-process)
    from method1.graph_builder.graph_builder import build_graph, rank_blast_radius
    print(f"\n{'-' * 50}")
    print(f"  Step 3/4: Building blast radius graph")
    print(f"{'-' * 50}")
    graph = build_graph(normalized_config)
    ranked = rank_blast_radius(graph)
    graph_output = {"graph": graph, "ranked_blast_radius": ranked}
    print(f"  -> Graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges")

    # Step 4: Build consolidated report (in-process)
    from method1.report_renderer.report_renderer import build_machine_report, build_human_report
    print(f"\n{'-' * 50}")
    print(f"  Step 4/4: Building consolidated report")
    print(f"{'-' * 50}")
    report = build_machine_report(findings, graph_output)
    # Embed the full normalized config inside report.json so Method 2
    # can read credentials from it (eliminates normalized_config.json)
    report["source_path"] = normalized_config.get("source_path", str(config_path.resolve()))
    report["credentials"] = normalized_config.get("credentials", [])
    report["mcp_servers"] = normalized_config.get("mcp_servers", [])
    report["skills"] = normalized_config.get("skills", [])

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Print human-readable summary to stdout
    human_report = build_human_report(findings, graph_output)

    print(f"\n{'=' * 50}")
    print(f"  METHOD 1 SCAN COMPLETE")
    print(f"{'=' * 50}")
    print(human_report)
    print(f"\nAll outputs saved to: {OUTPUT_DIR}/")
    print(f"  * report.json  (structured scan results)")
    print(f"\nTo run the dynamic attack test:")
    print(f"  {PYTHON} run_pipeline.py attack {report_path}")

    return str(report_path)


def run_attack(report_path: str):
    """Run the full Method 2 dynamic attack pipeline."""
    if not Path(report_path).exists():
        print(f"Error: report '{report_path}' not found.")
        print(f"Run '{PYTHON} run_pipeline.py scan <config_dir>' first.")
        sys.exit(1)

    result = run_cmd(
        [PYTHON, str(METHOD2_DIR / "run_full_attack_suite.py"), report_path],
        "Running Method 2: Dynamic canary injection test",
        capture=False,
    )
    if result.returncode != 0:
        print(f"\nMethod 2 failed (exit code {result.returncode}). See output above.")
        sys.exit(result.returncode)


def run_advise():
    """Run the AI remediation advisor against whatever scan/attack
    output already exists in output/."""
    report_path = OUTPUT_DIR / "report.json"
    if not report_path.exists():
        print(f"Error: {report_path} not found.")
        print(f"Run '{PYTHON} run_pipeline.py scan <config_dir>' first.")
        sys.exit(1)

    cmd = [
        PYTHON,
        str(METHOD1_DIR / "remediation_advisor" / "groq_advisor.py"),
        str(report_path),
    ]

    verdict_path = OUTPUT_DIR / "verdict.json"
    if verdict_path.exists():
        cmd.append(str(verdict_path))

    result = run_cmd(cmd, "Generating AI remediation advice", capture=False)
    if result.returncode != 0:
        sys.exit(result.returncode)


def run_report():
    """Render the single-page HTML dashboard from whatever scan/attack/advise
    output already exists in output/."""
    report_path = OUTPUT_DIR / "report.json"
    if not report_path.exists():
        print(f"Error: {report_path} not found.")
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
    report_path = run_scan(config_dir)

    print(f"\n{'=' * 50}")
    print(f"  PROCEEDING TO METHOD 2 (DYNAMIC TEST)")
    print(f"{'=' * 50}\n")

    run_attack(report_path)


def run_kill():
    """Emergency stop."""
    subprocess.run(
        ["docker", "rm", "-f", "agent-sandbox-instance"],
        capture_output=True,
        creationflags=_SUBPROCESS_FLAGS,
    )
    print("[kill] sandbox container stopped and removed.")


def print_usage():
    print(f"""
Agent Security Auditor — Unified CLI

Usage:
    {PYTHON} run_pipeline.py scan <config_dir>        Static scan (Method 1)
    {PYTHON} run_pipeline.py attack <report.json>      Dynamic test (Method 2)
    {PYTHON} run_pipeline.py full <config_dir>         Both end-to-end
    {PYTHON} run_pipeline.py advise                    AI remediation advice (needs GROQ_API_KEY)
    {PYTHON} run_pipeline.py report                    Render HTML dashboard (output/dashboard.html)
    {PYTHON} run_pipeline.py kill                      Emergency stop

Examples:
    {PYTHON} run_pipeline.py scan sample_configs/openclaw_default
    {PYTHON} run_pipeline.py full sample_configs/openclaw_default
    {PYTHON} run_pipeline.py attack output/report.json
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
            print(f"Usage: {PYTHON} run_pipeline.py attack <report.json>")
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
