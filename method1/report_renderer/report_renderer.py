"""
report_renderer.py

Takes rule_engine findings + graph_builder output, produces:
  a) Machine-readable JSON (feeds Method 2 - which high-risk paths to target)
  b) Human report (ranked findings list + plain-fix instructions)

Usage:
    python report_renderer.py /path/to/findings.json /path/to/graph_output.json
"""

import json
import sys
from datetime import datetime, timezone

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build_machine_report(findings: list, graph_output: dict) -> dict:
    """The JSON that Method 2 will consume to know which high-risk paths to attack."""
    failed_findings = [f for f in findings if not f["passed"]]
    ranked = graph_output["ranked_blast_radius"]

    # Method 2 can only attack credential-type nodes, so every credential
    # must always be included here regardless of rank position -- a
    # non-credential node (e.g. network_exposure) outranking it must never
    # silently push a real credential target out of scope. Keep up to 5 of
    # the highest-ranked non-credential nodes too, for broader context.
    credential_targets = [t for t in ranked if t["type"] == "credential"]
    non_credential_top = [t for t in ranked if t["type"] != "credential"][:5]
    top_targets = sorted(
        credential_targets + non_credential_top,
        key=lambda t: t["blast_radius_score"],
        reverse=True,
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "failed_rules": failed_findings,
        "top_attack_targets": top_targets,
        "full_graph": graph_output["graph"],
    }


def build_human_report(findings: list, graph_output: dict) -> str:
    """Plain-English report: ranked findings + fixes, for the actual user to read."""
    failed = sorted(
        [f for f in findings if not f["passed"]],
        key=lambda f: SEVERITY_ORDER.get(f["severity"], 5),
    )
    passed = [f for f in findings if f["passed"]]

    lines = []
    lines.append("=" * 60)
    lines.append("AGENT SECURITY AUDIT - BLAST RADIUS REPORT")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Findings: {len(failed)} issue(s) found, {len(passed)} check(s) passed")
    lines.append("")

    if failed:
        lines.append("-- ISSUES, RANKED BY SEVERITY --")
        lines.append("")
        for f in failed:
            lines.append(f"[{f['severity'].upper()}] {f['rule']} ({f['category']})")
            lines.append(f"  Finding: {f['finding']}")
            lines.append(f"  Fix:     {f['fix']}")
            lines.append("")

    lines.append("-- TOP 5 BLAST RADIUS TARGETS --")
    lines.append("(highest sensitivity x easiest to reach)")
    lines.append("")
    for i, target in enumerate(graph_output["ranked_blast_radius"][:5], start=1):
        lines.append(
            f"{i}. {target['label']} ({target['type']}) "
            f"- score {target['blast_radius_score']} "
            f"(sensitivity {target['sensitivity']} x ease {target['ease_of_reach']})"
        )
    lines.append("")

    if passed:
        lines.append("-- PASSED CHECKS --")
        for p in passed:
            lines.append(f"[OK] {p['rule']}: {p['finding']}")

    lines.append("")
    lines.append("=" * 60)

    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python report_renderer.py /path/to/findings.json /path/to/graph_output.json")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        findings = json.load(f)

    with open(sys.argv[2], "r") as f:
        graph_output = json.load(f)

    machine_report = build_machine_report(findings, graph_output)
    human_report = build_human_report(findings, graph_output)

    with open("machine_report.json", "w") as f:
        json.dump(machine_report, f, indent=2)

    with open("human_report.txt", "w") as f:
        f.write(human_report)

    print(human_report)
    print("\n[Saved machine_report.json and human_report.txt]")