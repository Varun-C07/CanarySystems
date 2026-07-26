"""
groq_advisor.py

Generates contextual remediation advice for security findings using LLM reasoning.
Combines static scanner findings and dynamic attack evidence into prioritized,
beginner-friendly remediation guidance.

Requires GROQ_API_KEY environment variable.
Usage:
    python groq_advisor.py /path/to/report.json [/path/to/verdict.json]
"""

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
REQUEST_TIMEOUT = 60
USER_AGENT = "agent-security-auditor-advisor/1.0"

SYSTEM_PROMPT = """You are an application security advisor writing the remediation section of an AI agent security audit report. Your goal is to explain risks and fixes in plain, beginner-friendly English so that any developer can understand what is wrong and exactly how to fix it.

You're given:
1. Static findings from a configuration scanner (misconfigurations).
2. A blast-radius graph of assets reachable if the agent is compromised.
3. Proven results from a dynamic penetration test (if dynamic evidence is present).

GUIDELINES:
- Use plain, accessible language. Avoid dense jargon without explaining it.
- When mentioning a technical concept (e.g., 0.0.0.0 binding, bearer token, unsandboxed execution, TLS), explain in one simple sentence what it means in practice.
- Provide clear, step-by-step instructions on what configuration setting or file line to change.
- Only connect a static finding to a dynamic attack type if the finding directly enabled that specific attack channel.

Structure your response as:
1. **Executive Summary**: A brief 2-3 sentence overview explaining overall safety in plain terms.
2. **Prioritized Remediation Guide**: A numbered list of recommended fixes (most critical first). For each item include:
   - **What's wrong & why it matters** (in simple English).
   - **How to fix it** (exact setting to change, e.g. "In `settings.json`, set `bind_address` to `127.0.0.1`").
3. **Proven Attack Breakdown** (if dynamic test evidence is present): Name which credentials leaked, how they leaked, and the most impactful changes to block them immediately.

Be concise, clear, and actionable. Reference actual credential names, tool names, and filenames given."""


class GroqAdvisorError(Exception):
    """Raised for API errors."""


def load_json(path: Path) -> dict:
    """Load and parse a JSON file. Exits with a clean, actionable message
    (never a raw traceback) if the file contains invalid JSON -- e.g. left
    truncated by a process that was killed mid-write."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[remediation_advisor] ERROR: {path} contains invalid JSON ({e}).")
        print(f"[remediation_advisor] It may be corrupted or from an interrupted "
              f"run -- re-run the step that produces it.")
        sys.exit(1)


def _warn_if_stale(reference_path: Path, dependent_path: Path, dependent_label: str):
    """Warn (don't fail) if `dependent_path` is older than `reference_path`.
    machine_report.json/verdict.json carry no run-id or cross-reference to
    each other, so an older verdict.json here most likely means it's from
    a PREVIOUS, unrelated scan -- e.g. scan config A, attack (verdict.json
    for A), re-scan config B (new machine_report.json), forget to re-run
    attack. Without this check, advice would silently be generated as if
    B's static findings and A's proven-attack evidence were one audit."""
    try:
        if dependent_path.stat().st_mtime < reference_path.stat().st_mtime:
            print(f"[remediation_advisor] WARNING: {dependent_label} ({dependent_path}) is "
                  f"OLDER than {reference_path.name} -- it may be from a previous scan run "
                  f"and not correspond to these findings. Consider re-running "
                  f"'run_pipeline.py attack' first.")
    except OSError:
        pass  # can't stat either file -- not worth failing the whole run over


def _summarize_failed_rules(failed_rules: list) -> str:
    """Render machine_report.json's failed_rules as a bulleted list for
    the prompt, one line per finding with its severity/category/text."""
    if not failed_rules:
        return "None -- every static check passed."
    lines = []
    for f in failed_rules:
        lines.append(
            f"- [{f.get('severity', 'unknown').upper()}] {f.get('rule')} "
            f"({f.get('category')}): {f.get('finding')}"
        )
    return "\n".join(lines)


def _summarize_attack_targets(top_attack_targets: list) -> str:
    """Render machine_report.json's top_attack_targets (the blast-radius
    ranking) as a bulleted list for the prompt."""
    if not top_attack_targets:
        return "None identified."
    lines = []
    for t in top_attack_targets:
        lines.append(
            f"- {t.get('label')} (type={t.get('type')}, "
            f"sensitivity={t.get('sensitivity')}, "
            f"ease_of_reach={t.get('ease_of_reach')}, "
            f"blast_radius_score={t.get('blast_radius_score')})"
        )
    return "\n".join(lines)


def _summarize_verdict(verdict: dict) -> str:
    """Render verdict.json's proven-exploitation results for the prompt:
    which credentials leaked, via which channel/attack type, which stayed
    safe, and a per-channel hit summary."""
    summary = verdict.get("summary", {})
    results = verdict.get("results", [])

    lines = [
        f"{summary.get('leaked', 0)} of {summary.get('total_credentials_tested', 0)} "
        f"credentials were PROVEN to leak in a real sandboxed exploitation test "
        f"(fake, uniquely-tagged canary credentials -- no real secrets were used)."
    ]

    leaked = [r for r in results if r.get("fired")]
    if leaked:
        lines.append("\nCredentials that LEAKED:")
        for r in leaked:
            ev = r.get("evidence") or {}
            lines.append(
                f"- {r.get('credential')}: leaked via {ev.get('leak_channel', 'unknown')} "
                f"channel, attack type '{ev.get('attack_type', 'unknown')}' "
                f"(attack vectors that succeeded against it: "
                f"{', '.join(ev.get('attack_breakdown', {}).keys()) or 'unknown'})"
            )

    safe = [r for r in results if not r.get("fired")]
    if safe:
        lines.append(
            "\nCredentials NOT observed to leak in this test run: "
            + ", ".join(r.get("credential", "unknown") for r in safe)
            + " (this does not prove they are safe -- only that this specific "
              "test run didn't catch a leak; some attack channels may be "
              "environment-limited in this test setup)."
        )

    channel_summary = summary.get("exfiltration_channel_summary", {})
    if channel_summary:
        lines.append("\nExfiltration channels that worked at all, across any credential:")
        for channel, info in channel_summary.items():
            lines.append(f"- {channel}: {info.get('hits', 0)} hit(s)")

    return "\n".join(lines)


def build_prompt(machine_report: dict, verdict: dict = None) -> str:
    """Assemble the user-turn prompt from machine_report.json and, if
    available, verdict.json. Keeping this separate from call_groq() makes
    it independently testable without hitting the network."""
    sections = [
        "## Static scan findings (failed checks)",
        _summarize_failed_rules(machine_report.get("failed_rules", [])),
        "",
        "## Blast-radius targets (assets reachable if the agent is compromised, "
        "ranked by sensitivity x ease of reach)",
        _summarize_attack_targets(machine_report.get("top_attack_targets", [])),
    ]

    if verdict:
        sections += [
            "",
            "## Dynamic exploitation test results (PROVEN, not theoretical)",
            _summarize_verdict(verdict),
        ]
    else:
        sections += [
            "",
            "## Dynamic exploitation test results",
            "Not available -- only the static scan above has been run. Note "
            "in your advice that severity is based on theoretical exposure "
            "only; a dynamic test would confirm which of these are actually "
            "exploitable.",
        ]

    return "\n".join(sections)


def call_groq(prompt: str, api_key: str, model: str = GROQ_MODEL) -> str:
    """Call Groq's OpenAI-compatible chat completions endpoint. Returns the
    assistant's reply text. Raises GroqAdvisorError with a clear,
    human-readable message on any failure -- never lets a raw
    urllib/network exception surface to the caller."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        # Lowered from 0.3: this task needs reliable adherence to the STRICT
        # RULE in the system prompt (don't draw unsupported causal links)
        # more than it needs writing variety.
        "temperature": 0.1,
    }
    req = urllib.request.Request(
        GROQ_API_URL,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="ignore")
        try:
            message = json.loads(raw).get("error", {}).get("message", raw)
        except json.JSONDecodeError:
            message = raw
        if e.code == 401:
            raise GroqAdvisorError(
                f"Groq API rejected the API key (401 Unauthorized): {message}. "
                f"Check that GROQ_API_KEY is correct and active."
            )
        if e.code == 429:
            raise GroqAdvisorError(
                f"Groq API rate limit hit (429 Too Many Requests): {message}. "
                f"Wait a bit and retry, or check your plan's rate limits."
            )
        if e.code == 400:
            raise GroqAdvisorError(f"Groq API rejected the request (400 Bad Request): {message}")
        raise GroqAdvisorError(f"Groq API error (HTTP {e.code}): {message}")
    except urllib.error.URLError as e:
        raise GroqAdvisorError(f"Could not reach Groq API -- network error: {e.reason}")
    except TimeoutError:
        raise GroqAdvisorError(f"Groq API request timed out after {REQUEST_TIMEOUT}s")

    try:
        return body["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        raise GroqAdvisorError(f"Unexpected Groq API response shape: {body}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python groq_advisor.py /path/to/report.json [/path/to/verdict.json]")
        sys.exit(1)

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("[remediation_advisor] ERROR: GROQ_API_KEY environment variable is not set.")
        print("[remediation_advisor] Get a free key at https://console.groq.com/keys, then:")
        print("[remediation_advisor]   export GROQ_API_KEY=gsk_...")
        sys.exit(1)

    machine_report_path = Path(sys.argv[1])
    if not machine_report_path.exists():
        print(f"[remediation_advisor] ERROR: machine report not found: {machine_report_path}")
        sys.exit(1)
    machine_report = load_json(machine_report_path)

    verdict = None
    if len(sys.argv) >= 3:
        verdict_path = Path(sys.argv[2])
        if verdict_path.exists():
            verdict = load_json(verdict_path)
            print(f"[remediation_advisor] including dynamic test evidence from {verdict_path}")
            _warn_if_stale(machine_report_path, verdict_path, "verdict.json")
        else:
            print(f"[remediation_advisor] NOTE: verdict path given but not found: "
                  f"{verdict_path} -- continuing with static findings only.")
    else:
        print("[remediation_advisor] no verdict.json given -- advice will be based on "
              "static findings only. Run Method 2 first for proof-backed advice.")

    prompt = build_prompt(machine_report, verdict)

    print(f"[remediation_advisor] calling Groq API ({GROQ_MODEL})...")
    try:
        advice = call_groq(prompt, api_key)
    except GroqAdvisorError as e:
        print(f"[remediation_advisor] ERROR: {e}")
        sys.exit(1)

    # Write next to wherever machine_report.json actually came from, not a
    # hardcoded default -- matches render_dashboard.py's behavior and keeps
    # this usable with a non-default output directory, which the usage
    # string above already implies is supported.
    output_path = machine_report_path.parent / "ai_remediation.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(advice)

    print("\n" + "=" * 60)
    print("AI-GENERATED REMEDIATION ADVICE")
    print("=" * 60 + "\n")
    try:
        print(advice)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(advice.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
    print(f"\n[remediation_advisor] saved to {output_path}")


if __name__ == "__main__":
    main()
