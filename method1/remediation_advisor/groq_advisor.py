"""
groq_advisor.py

Takes Method 1's machine_report.json (failed_rules, top_attack_targets) and,
if available, Method 2's verdict.json (which credentials were actually
proven to leak, via which attack type and exfiltration channel), and calls
the Groq API to generate contextual, AI-written remediation advice -- not
just restating each rule's hardcoded fix text, but explaining why the
specific combination of issues found was exploitable together, and
prioritizing proven exploitation over theoretical risk.

Requires GROQ_API_KEY in the environment (never hardcoded). Get a free key
at https://console.groq.com/keys.

Usage:
    python groq_advisor.py /path/to/machine_report.json [/path/to/verdict.json]

Output:
    Prints the advice to stdout and saves it to output/ai_remediation.md
    (relative to the project root).
"""

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# llama-3.3-70b-versatile was the obvious default here, but Groq deprecated
# it (shutdown 2026-08-16) and its own docs recommend migrating to
# openai/gpt-oss-120b -- that's what we use. See:
# https://console.groq.com/docs/deprecations
# Overridable via GROQ_MODEL env var so a future deprecation (there will be
# one) doesn't require a code change to work around.
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")

REQUEST_TIMEOUT = 60

# Bare urllib sends "Python-urllib/3.x" as its default User-Agent, which
# Cloudflare's bot-protection rules in front of api.groq.com commonly block
# outright (HTTP 403, Cloudflare error 1010) since it's a well-known
# generic-scripting-tool signature. Self-identify honestly instead -- same
# approach the official groq-python SDK takes (it sends "Groq/Python
# <version>", not a spoofed browser string).
USER_AGENT = "agent-security-auditor-groq-advisor/1.0"

SYSTEM_PROMPT = """You are a senior application security engineer writing the remediation section of an AI agent security audit report.

You're given:
1. Static findings from a configuration scanner (what's misconfigured).
2. A blast-radius graph of assets reachable if the agent is compromised, ranked by (sensitivity x ease of reach).
3. Optionally, PROVEN results from a dynamic penetration test that actually attempted to exfiltrate uniquely-tagged fake credentials through real attack techniques (prompt injection, tool poisoning, DNS tunneling, malicious package install, etc.) against a sandboxed replica of the agent.

STRICT RULE ON CONNECTING FINDINGS -- apply this before writing anything, and re-check every sentence against it before you finalize your answer:

You may only state that a static finding relates to, enabled, or explains a specific dynamic attack type if BOTH of the following are literally true:
  (a) That attack type appears as a literal key in that credential's attack_breakdown dict in the dynamic evidence given below, AND
  (b) The static finding's own mechanism plausibly and directly produced that attack's leak_channel -- e.g. unsandboxed_exec (shell-exec has no sandbox) directly explains a SHELL_EXEC leak_channel; overbroad_scope (unrestricted filesystem write) directly explains a FILE_WRITE leak_channel; auth_token/network_binding (no auth, exposed network) directly explain ANY leak_channel, since every attack in this test requires reaching the API first.

If a static finding and an attack type merely share a keyword, topic, or theme (e.g. both mention "installing", "packages", "credentials", "access") but neither (a) nor (b) holds, DO NOT connect them -- discuss them as separate, unrelated items instead. Do not soften an unsupported link into a hedge ("could relate to", "may have contributed to", "is consistent with") -- either the evidence supports the link under the test above, or you say nothing about a relationship at all.

CONCRETE EXAMPLE OF A FORBIDDEN LINK: unpinned_provenance is a static finding about THIS AGENT'S OWN skills lacking version pins (a supply-chain trust issue in already-installed software). package_install_injection is a dynamic attack where the agent is tricked into running "pip install" on an attacker-suggested, entirely different package. Neither (a) nor (b) holds between them: package_install_injection is not what unpinned_provenance's own mechanism (unpinned skill versions) would produce, and whichever credential's attack_breakdown contains package_install_injection does not thereby implicate unpinned skills. Do not state or imply a relationship between these two findings, even in passing, even as a minor supporting point. If you find yourself about to write a sentence naming both, stop and rewrite it to discuss them separately.

Write prioritized, contextual remediation advice in Markdown. Do not just restate each finding next to a generic fix -- when the STRICT RULE above is actually satisfied for two findings, explain WHY that specific combination makes the environment exploitable together. For example: "no auth token + binding to 0.0.0.0 + plaintext credentials means anyone on the local network can trivially read every secret with no authentication at all" (auth_token and network_binding each satisfy rule (b) for every leak_channel present) or "the unsandboxed shell-exec tool being reachable is what let exec_exfil_injection actually execute code" (unsandboxed_exec satisfies rule (b) for the SHELL_EXEC channel specifically).

When dynamic test evidence is available, treat PROVEN exploitation as the highest priority and say so explicitly -- a finding that was actually demonstrated to leak a credential is more urgent than one that is only theoretically risky, even if the theoretical one has a higher static severity label.

Structure your response as:
1. A short executive-summary paragraph on overall risk posture.
2. A prioritized remediation list (most urgent first). Each item needs a one-line "why this matters here" tied to the SPECIFIC findings given, following the STRICT RULE above -- not generic security advice a template could produce, and never a connection the rule forbids.
3. If any credentials were proven to leak, a section naming exactly which attack chains succeeded (using attack_breakdown's literal keys, nothing else) and the single highest-leverage change that would have blocked the most of them.

Before finalizing, re-read every sentence that names both a static finding and a dynamic attack type together, and check it against the STRICT RULE above. If any sentence fails the check, rewrite it to discuss the two items separately.

Be concise, specific, and actionable. Reference the actual credential names, tool names, and attack types given -- never use placeholders like "[credential name]"."""


class GroqAdvisorError(Exception):
    """Raised for any Groq API failure that should be reported cleanly,
    never as a raw traceback."""


def load_json(path: Path) -> dict:
    """Load and parse a JSON file. Exits with a clean, actionable message
    (never a raw traceback) if the file contains invalid JSON -- e.g. left
    truncated by a process that was killed mid-write."""
    try:
        with open(path, "r") as f:
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
        print("Usage: python groq_advisor.py /path/to/machine_report.json [/path/to/verdict.json]")
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
    with open(output_path, "w") as f:
        f.write(advice)

    print("\n" + "=" * 60)
    print("AI-GENERATED REMEDIATION ADVICE")
    print("=" * 60 + "\n")
    print(advice)
    print(f"\n[remediation_advisor] saved to {output_path}")


if __name__ == "__main__":
    main()
