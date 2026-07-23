# Agent Security Auditor — Build Spec

## Overview
Two-method system that audits locally-run personal AI agents (e.g. OpenClaw-style)
for security exposure. Method 1 is static/deterministic. Method 2 is dynamic/behavioral,
using traceable fake credentials ("canaries") to prove — not just flag — real leaks.

## Method 1 — Static exposure & permission scanner
Location: /method1

1. Config collector (/method1/config_collector)
   - Read-only filesystem walker targeting known agent config locations
     (settings file, .env, MCP server manifest, skills directory).
   - Outputs a normalized internal schema, independent of the underlying
     agent's native config format.

2. Rule engine (/method1/rule_engine)
   - Checklist runner. Each rule is an independent, isolated file
     (plugin-registry pattern, not a monolithic if-else chain).
   - Takes normalized config, returns pass/fail/severity per rule.
   - Rule categories: network, auth, credentials, permissions, provenance, versioning.

3. Graph builder (/method1/graph_builder)
   - Models the agent and every reachable asset as a directed graph
     (agent -> MCP server -> external API; agent -> filesystem path -> sensitive file; etc).
   - Each edge has a permission label (read/write/execute) and confidence score.
   - Walks outward from the agent node; anything reachable within N hops is "in blast radius."
   - Ranks nodes by (sensitivity of asset) x (ease of reaching it).

4. Report renderer (/method1/report_renderer)
   - Outputs two things:
     a) Machine-readable JSON (feeds Method 2 — which high-risk paths to target)
     b) Human report (ranked findings list + plain-fix instructions)

## Method 2 — Sandboxed canary injection testing
Location: /method2

1. Replica builder (/method2/replica_builder)
   - Spins up a containerized clone of the agent using the config discovered
     by Method 1 (same MCP servers, same permission scopes).
   - Swaps every real credential for a canary. Never touches real secrets.

2. Canary seeder (/method2/canary_seeder)
   - Generates fake secrets uniquely tagged per test run.
   - Plants them everywhere a real secret would live: credentials file,
     env var, fake document dropped in a watched folder, fake memory entry.

3. Listener service (/method2/listener_service)
   - Small always-on HTTP endpoint. Logs any inbound request and matches
     it against known canary tags. Pure string match — no LLM judgment.
   - This is the ground truth for "did it leak."

4. Attack payload library (/method2/attack_payloads)
   - Three payload types:
     a) Direct injection — plain message instructing the agent to read/send a credential.
     b) Indirect injection — payload hidden in a document/file the agent
        encounters during normal operation (not told to look at it directly).
     c) Tool/skill poisoning — malicious instruction hidden in a mock tool's
        description field, not its function.

5. Delivery driver (/method2/delivery_driver)
   - Pushes each payload into the sandbox through the real channel an
     attacker would use (chat message, file drop, tool registration).

6. Verdict aggregator (/method2/verdict_aggregator)
   - After each payload, polls the listener for 30-60 seconds.
   - Records: which payload ran, whether a canary fired, which one,
     and the full timestamped chain (payload sent -> agent action -> canary triggered).
   - Run each payload 3-5 times per config; report success rate, not single pass/fail.

## Shared (/shared)
- Common JSON schema used by both methods (the "normalized config" format
  from Method 1's config collector, and the findings format Method 1 report
  renderer outputs, which Method 2's replica builder consumes).

## Build order (for Claude Code to follow)
1. Build Method 1 fully first: config_collector -> rule_engine -> graph_builder -> report_renderer.
   Test it against a real or sample OpenClaw config directory before moving on.
2. Build Method 2 infrastructure before attacks: replica_builder -> canary_seeder -> listener_service.
   Confirm the listener correctly catches a manually-triggered canary before writing attack code.
3. Build attack payloads in order: direct injection -> indirect injection -> tool poisoning.
4. Build delivery_driver and verdict_aggregator last.

## Tech stack
- Python for Method 1 (regex/file parsing) and Method 2 orchestration.
- Docker / docker-compose for the replica sandbox in Method 2.
- FastAPI for the listener service and any thin API layer.
- React + Tailwind (optional) for report/graph UI if time allows.