"""
engine.py

Loads all rule modules from rules/, runs each against a normalized config,
returns a list of findings (pass/fail/severity per rule).
"""

import importlib
import importlib.util
import json
import sys
from pathlib import Path

RULES_DIR = Path(__file__).parent / "rules"


def load_rules():
    rule_modules = []
    for file in sorted(RULES_DIR.glob("*.py")):
        if file.stem == "__init__":
            continue
        module_name = f"rules.{file.stem}"
        spec = importlib.util.spec_from_file_location(module_name, file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        rule_modules.append(module)
    return rule_modules


def run_rules(config: dict) -> list:
    rules = load_rules()
    results = []
    for rule_module in rules:
        result = rule_module.check(config)
        results.append(result)
    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python engine.py /path/to/config_collector_output.json")
        sys.exit(1)

    with open(sys.argv[1], "r", encoding="utf-8") as f:
        config = json.load(f)

    findings = run_rules(config)
    print(json.dumps(findings, indent=2))