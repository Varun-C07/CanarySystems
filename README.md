# Agent Security Auditor

A blast-radius security auditor for personal AI agents (OpenClaw-style agents running locally with access to a user's files, credentials, and tools).

Answers one core question: **if this agent gets compromised, what exactly can an attacker reach — and can they actually get it out?**

Most existing tools stop at flagging risk. This one proves it.

---

## What It Does

### Method 1 — Static Exposure Scanner
Reads an agent's configuration (`settings.json`, `.env`, `mcp_servers.json`, `skills/*.json`) and:
- Detects high-entropy credentials automatically, even if custom key names like `key1` or `my_secret` are used.
- Checks against known misconfigurations (missing auth tokens, `0.0.0.0` network bindings, unsandboxed command execution, plaintext credentials, unpinned third-party tools, known vulnerable versions).
- Builds a ranked **Blast Radius Graph** scored by (sensitivity × BFS cumulative ease of reach).
- Renders an interactive D3.js visual graph (`output/graph_visualization.html`) and human-readable audit reports.

### Method 2 — Dynamic Exfiltration Prover
Takes Method 1's highest-ranked targets and proves exploitability in a controlled sandbox:
- Clones the agent config into an isolated Docker sandbox with real credentials replaced by uniquely tagged **canary credentials**.
- Fires three realistic attack vectors:
  1. **Direct Chat Injection** (`direct_injection`)
  2. **Indirect Document Poisoning** (`indirect_injection`)
  3. **Third-Party Tool Description Poisoning** (`tool_poisoning`)
- Uses a lightweight HTTP listener to catch exfiltrated canaries and output a structured verdict with exact attack-type attribution.

---

## Running the Pipeline End-to-End

### Prerequisites
- Python 3.10+
- Docker Desktop (required only for Method 2 dynamic attack execution)

### 1. Run Method 1 (Static Scan)
Scans the target configuration directory and outputs results into `output/`:
```bash
python3 run_pipeline.py scan sample_configs/openclaw_default
```
**Artifacts Generated (`output/`):**
- `report.json`: Structured target list and blast radius model for Method 2.
- `dashboard.html`: Self-contained interactive visual dashboard. Open this file in your browser to inspect risk nodes and recommendations!

---

### 2. Run Dry-Run Simulation (No Docker Required)
Preview attack payloads and generated canary values without touching container runtimes:
```bash
python3 method2/safety_wrapper.py output/report.json --dry-run
```

---

### 3. Run Method 2 (Dynamic Attack Test)
Runs full containerized canary injection testing:
```bash
python3 run_pipeline.py attack output/report.json
```
*(Or run both Method 1 and Method 2 end-to-end with one command: `python3 run_pipeline.py full sample_configs/openclaw_default`)*

---

### 4. Generate AI Remediation Advice
```bash
python3 run_pipeline.py advise
```

---

### 5. Emergency Kill Switch / Cleanup
To immediately halt tests and destroy sandbox containers:
```bash
python3 run_pipeline.py kill
```

---

## System Architecture

```text
run_pipeline.py                    # Unified CLI entrypoint
output/                            # Auto-generated scan & test reports

method1/                           # STATIC EXPOSURE SCANNER
├── config_collector/collector.py # Entropy-based credential & config parser
├── rule_engine/engine.py          # Plugin checklist runner (auth, network, permissions, CVEs)
├── graph_builder/graph_builder.py# BFS multi-hop blast-radius modeler
└── report_renderer/               # Human & Machine report generator

method2/                           # DYNAMIC CANARY TESTER
├── replica_builder/               # Docker replica container generator
├── canary_seeder/seed_canaries.py # Tagged canary credential generator
├── attack_payloads/payloads.py    # Injection attack payload templates (with attack_id)
├── delivery_driver/deliver.py     # Channel delivery (chat, watched files, tool manifests)
├── listener_service/listener.py   # Ground-truth canary HTTP callback listener
├── verdict_aggregator/            # Attributed pass/fail verdict generator
└── safety_wrapper.py              # Consent gate, dry-run & kill switch
```


## Method 1 static scanner checks 8 distinct security categories:

Security Category	Rule Name	What It Checks & Flags

Network Exposure	network_binding	Checks if control API is bound to 0.0.0.0 (reachable from LAN/Public Internet) instead of 127.0.0.1.

API Authentication	auth_token	Checks if gateway control API lacks an authentication token (auth_token == null).

Host System Execution	unsandboxed_exec	Checks if shell execution capabilities are enabled without container sandboxing ("sandboxed": false).

Filesystem Scope	overbroad_scope	Checks if tools have unrestricted write access to root directories (/, C:\, *).

Credential Storage	plaintext_credentials	Scans .env files using Shannon Entropy Calculation + regex to flag unencrypted secret storage vs OS keychains.

Transport Security	tls_enabled	Checks if TLS/HTTPS encryption is disabled on non-loopback connections, allowing MITM credential interception.

Dependency Pinning	unpinned_provenance	Checks if installed skills/tools come from unverified 3rd-party URLs or unpinned git commits/versions.

Version Vulnerabilities	stale_version	Scans for unpinned pre-1.0 skills or outdated component versions matching known vulnerability advisories.
