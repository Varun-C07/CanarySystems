# Agent Security Auditor

A blast-radius security auditor for personal AI agents (OpenClaw-style agents
running locally with access to a user's files, credentials, and tools).

Answers one question: **if this agent gets compromised, what exactly can an
attacker reach — and can they actually get it out?**

Most existing tools stop at flagging risk. This one proves it.

## What it does

**Method 1 — Static Scanner**
Reads an agent's configuration (settings, credentials, connected MCP
servers, installed skills) and:
- Checks it against known misconfiguration patterns (no auth, exposed
  network binding, plaintext credentials, over-broad permissions, unpinned
  third-party skills)
- Builds a ranked "blast radius" map of every credential, tool, and file
  the agent can reach, scored by (sensitivity × ease of reach)
- Renders an interactive visual graph of that map
- Produces a plain-English report with concrete fixes

**Method 2 — Dynamic Exfiltration Prover**
Takes the static scanner's findings and proves whether they're actually
exploitable:
- Clones the agent's real configuration into an isolated Docker sandbox,
  with every real credential swapped for a uniquely-tagged fake one
- Fires three real attack types at it — direct injection, indirect
  injection via a poisoned document, and tool-description poisoning
- A listener service catches any fake credential that gets exfiltrated —
  a binary, timestamped, non-hallucinated pass/fail
- Produces a clean verdict: exactly which credentials leaked, when, and how

The whole pipeline is gated behind explicit user consent, includes a
dry-run mode, and has a kill switch to immediately halt an active test.

## Why this matters

Personal AI agents are increasingly given real access — file systems,
email, credentials, shell execution — often with default, unlocked
configurations. Known incidents include internet-exposed agent instances
with no authentication, one-click RCE vulnerabilities, and malicious
third-party skills shipping keyloggers. Existing scanners check
configuration; none of them prove exploitability by watching a real
credential get exfiltrated.

## Architecture
method1/
config_collector/ reads and normalizes agent config
rule_engine/ checks config against known bad patterns
graph_builder/ builds + ranks the blast radius graph, renders it visually
report_renderer/ produces human + machine-readable reports

method2/
replica_builder/ clones config into an isolated Docker sandbox
canary_seeder/ generates uniquely-tagged fake credentials
attack_payloads/ direct injection, indirect injection, tool poisoning
delivery_driver/ delivers payloads through realistic channels
listener_service/ catches and logs any exfiltrated canary
verdict_aggregator/ produces the final pass/fail report

safety_wrapper.py consent gate, dry-run mode, kill switch
run_full_attack_suite.py orchestrates the full Method 2 pipeline,
auto-targeting Method 1's top findings
reset_test_environment.py resets all test artifacts between runs

## Running it

Requires Python 3 and Docker Desktop.

**1. Run the static scan:**
```bash
python3 method1/config_collector/collector.py sample_configs/openclaw_default > sample_configs/openclaw_default_normalized.json
python3 method1/rule_engine/engine.py sample_configs/openclaw_default_normalized.json > sample_configs/openclaw_default_findings.json
python3 method1/graph_builder/graph_builder.py sample_configs/openclaw_default_normalized.json > sample_configs/openclaw_default_graph.json
python3 method1/report_renderer/report_renderer.py sample_configs/openclaw_default_findings.json sample_configs/openclaw_default_graph.json
```

**2. View the blast radius graph:**
```bash
python3 method1/graph_builder/render_graph.py sample_configs/openclaw_default_graph.json
open graph_visualization.html
```

**3. Run the full attack pipeline (requires Docker running):**
```bash
python3 method2/safety_wrapper.py machine_report.json
```
Type `I AGREE` when prompted. In a separate terminal, run the listener first:
```bash
python3 method2/listener_service/listener.py
```

**4. Check the verdict:**
```bash
python3 method2/verdict_aggregator/aggregate_verdict.py method2/canary_seeder/canaries.json method2/listener_service/canary_hits.json
```

**5. Stop everything:**
```bash
python3 method2/safety_wrapper.py --kill
```

## Status

Both methods are fully functional and tested end-to-end against a
realistic sample OpenClaw-style configuration, with all three Method 2
attack types independently verified to successfully exfiltrate targeted
canary credentials.

## Roadmap

- Testing against real OpenClaw installations (currently tested against a
  synthetic sample config)
- Expanded rule library for Method 1
- Continuous/runtime monitoring mode (MCP proxy for live tool-call inspection)
- Enterprise wedge: same engine for organizations whose employees run
  personal agents on work machines

