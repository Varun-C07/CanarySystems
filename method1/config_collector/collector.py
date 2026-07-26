"""
config_collector.py

Read-only filesystem walker for agent config directories.
Recursively scans all text files for credentials using three detection layers:
  Layer 1 — Recursive file walker (extension-agnostic)
  Layer 2 — Key-name pattern matching (CREDENTIAL_KEY_PATTERN)
  Layer 3 — Structural secret regex signatures + Shannon Entropy analysis

Also reads: settings file, MCP server manifest, skills directory.
Outputs a normalized internal schema, independent of the underlying
agent's native config format.

Usage:
    python collector.py /path/to/sample_configs/openclaw_default
"""

import json
import math
import os
import re
import sys
from pathlib import Path


# ── Layer 2: Key-name pattern matching ──────────────────────────────────
# Underscore is a \w character, so plain \b boundaries don't fire at
# SNAKE_CASE segment breaks -- (?:^|_) / (?:_|$) require each marker to be
# a whole underscore-delimited segment (or the whole name), not merely a
# substring, so e.g. BYPASS_CACHE and AUTHOR_NAME no longer false-positive
# on PASS/AUTH while OPENAI_API_KEY, AUTH_TOKEN, PRIVATE_KEY etc. still match.
CREDENTIAL_KEY_PATTERN = re.compile(
    r"(?:^|_)(?:API_KEY|SECRET|TOKEN|PASSWORD|ACCESS_KEY|DATABASE_URL|KEY|AUTH|PASS|CRED|PRIVATE)(?:_|$)",
    re.IGNORECASE,
)

# ── Layer 3: Structural secret regex signatures ─────────────────────────
# Each entry: (pattern_name, compiled_regex).  Applied to VALUES only.
STRUCTURAL_SECRET_PATTERNS = [
    ("openai_api_key",   re.compile(r"sk-[a-zA-Z0-9]{20,}")),
    ("openai_project",   re.compile(r"sk-proj-[a-zA-Z0-9_\-]{32,}")),
    ("stripe_key",       re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}")),
    ("github_pat",       re.compile(r"ghp_[a-zA-Z0-9]{36}")),
    ("github_pat_fine",  re.compile(r"github_pat_[a-zA-Z0-9_]{22,}")),
    ("aws_access_key",   re.compile(r"AKIA[0-9A-Z]{16}")),
    ("slack_token",      re.compile(r"xox[bpras]-[a-zA-Z0-9\-]+")),
    ("sendgrid_key",     re.compile(r"SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{22,}")),
    ("database_url",     re.compile(r"(?:postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^/\s]+/[^?\s]+")),
    ("generic_bearer",   re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}")),
]

# ── File walking config ─────────────────────────────────────────────────
# Directories to always skip during recursive walk
SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".tox", "dist", "build",
    ".eggs", ".idea", ".vscode",
}

# Files to always skip
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock", "composer.lock",
}

# File extensions to treat as text and scan
TEXT_EXTENSIONS = {
    # env files are handled specially by prefix check
    ".json", ".yaml", ".yml", ".toml",
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".cfg", ".ini", ".conf", ".properties",
    ".txt", ".md", ".rst",
    ".xml", ".csv",
    ".sh", ".bash", ".zsh",
    ".rb", ".go", ".java", ".rs", ".php",
    ".env",  # explicit, but also handled by prefix
}

# Binary extensions to never read
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a",
    ".pyc", ".pyo", ".class", ".whl",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".db", ".sqlite", ".sqlite3",
    ".woff", ".woff2", ".ttf", ".eot",
}


def calculate_entropy(s: str) -> float:
    """Calculate Shannon Entropy of a string to measure randomness/information density."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log2(p) for p in prob])


def mask_value(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _is_text_file(filepath: Path) -> bool:
    """Determine if a file should be scanned as text."""
    name = filepath.name.lower()
    # Any file starting with .env (handles .env, .env.local, .env.prod, etc.)
    if name.startswith(".env"):
        return True
    suffix = filepath.suffix.lower()
    if suffix in BINARY_EXTENSIONS:
        return False
    if suffix in TEXT_EXTENSIONS:
        return True
    # No extension — could be a dotfile like .bashrc, .profile, etc.
    if not suffix and name.startswith("."):
        return True
    return False


def _should_skip_dir(dirname: str) -> bool:
    return dirname.lower() in SKIP_DIRS or dirname.startswith(".")


def _should_skip_file(filename: str) -> bool:
    return filename.lower() in SKIP_FILES


# ── Extraction strategies per file type ─────────────────────────────────

def _extract_env_pairs(content: str) -> list:
    """Parse KEY=VALUE pairs from .env-style files. Returns [(key, value), ...]"""
    pairs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        # Strip surrounding quotes
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        if key and value:
            pairs.append((key, value))
    return pairs


def _extract_json_pairs(content: str) -> list:
    """Recursively extract all string key-value pairs from a JSON document."""
    pairs = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return pairs

    def _walk(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                path = f"{prefix}.{k}" if prefix else k
                if isinstance(v, str):
                    pairs.append((path, v))
                else:
                    _walk(v, path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _walk(item, f"{prefix}[{i}]")

    _walk(data)
    return pairs


def _extract_yaml_pairs(content: str) -> list:
    """Extract key=value pairs from YAML using simple line-by-line regex.
    Avoids a PyYAML dependency — good enough for credential detection."""
    pairs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Match simple YAML scalar: key: value
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_.\-]*)\s*:\s*(.+)$', line)
        if m:
            key, value = m.group(1).strip(), m.group(2).strip()
            # Strip surrounding quotes
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            if value:
                pairs.append((key, value))
    return pairs


def _extract_code_string_literals(content: str) -> list:
    """Extract string assignments from code files (Python, JS, TS).
    Matches patterns like: key = "value", const key = "value", etc."""
    pairs = []
    # Python/JS/TS assignment patterns
    patterns = [
        # Python: VAR = "value" or VAR = 'value'
        re.compile(r'''^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']{8,})["']''', re.MULTILINE),
        # JS/TS: const/let/var VAR = "value"
        re.compile(r'''^\s*(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']{8,})["']''', re.MULTILINE),
        # export const VAR = "value"
        re.compile(r'''^\s*export\s+(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']{8,})["']''', re.MULTILINE),
    ]
    for pattern in patterns:
        for m in pattern.finditer(content):
            pairs.append((m.group(1), m.group(2)))
    return pairs


def _classify_file(filepath: Path) -> str:
    """Return the extraction strategy name for a given file."""
    name = filepath.name.lower()
    suffix = filepath.suffix.lower()

    if name.startswith(".env"):
        return "env"
    if suffix == ".json":
        return "json"
    if suffix in (".yaml", ".yml"):
        return "yaml"
    if suffix in (".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".java", ".rs", ".php"):
        return "code"
    if suffix in (".cfg", ".ini", ".conf", ".properties", ".toml"):
        return "env"  # KEY=VALUE style
    return "env"  # fallback: try KEY=VALUE parsing


def _check_value(key: str, value: str) -> dict | None:
    """Check a key-value pair against all detection layers.
    Returns a credential dict if detected, else None."""

    # ── False-positive filters (applied before any detection) ──
    # Skip values that are clearly not secrets

    # URLs, file paths, package refs — high entropy but not secrets
    value_lower = value.lower()
    if value_lower.startswith(("http://", "https://", "ftp://", "npm://", "file://", "ssh://", "git://")):
        # Exception: database connection strings with embedded passwords ARE secrets
        if not any(value_lower.startswith(p) for p in ("postgres://", "mysql://", "mongodb://", "redis://")):
            return None

    # File system paths
    if value.startswith("/") and "/" in value[1:] and not any(p in value_lower for p in ("password", "secret", "token")):
        return None

    # Natural language text (contains spaces and common words)
    word_count = len(value.split())
    if word_count >= 4:
        return None

    # Skip known non-credential JSON key suffixes
    key_lower = key.lower()
    key_leaf = key_lower.rsplit(".", 1)[-1] if "." in key_lower else key_lower
    NON_CRED_KEYS = {
        "name", "description", "url", "source", "author", "version",
        "label", "title", "type", "format", "host", "port",
        "path", "scopes", "sandboxed", "pinned",
    }
    # Strip array index suffixes like "servers[0].source" -> "source"
    clean_leaf = re.sub(r'\[\d+\]\.?', '', key_leaf).strip(".")
    if clean_leaf in NON_CRED_KEYS:
        # Only allow through if the value matches a structural secret pattern
        has_structural_match = any(regex.search(value) for _, regex in STRUCTURAL_SECRET_PATTERNS)
        if not has_structural_match:
            return None

    # ── Layer 2: Key name pattern ──
    is_named_cred = bool(CREDENTIAL_KEY_PATTERN.search(key))

    # ── Layer 3a: Structural secret signatures (check value only) ──
    matched_pattern = None
    for pattern_name, regex in STRUCTURAL_SECRET_PATTERNS:
        if regex.search(value):
            matched_pattern = pattern_name
            break

    # ── Layer 3b: Shannon Entropy ──
    entropy = calculate_entropy(value)
    is_high_entropy = len(value) >= 12 and entropy >= 3.5

    # For entropy-only detections from config/code files, require BOTH
    # high entropy AND a credential-like key name to reduce false positives.
    # Structural signatures and named-key matches are always trusted.
    if matched_pattern or is_named_cred:
        if matched_pattern:
            reason = "structural_signature"
        else:
            reason = "name_pattern"
    elif is_high_entropy and is_named_cred:
        reason = "high_entropy"
    elif is_high_entropy:
        # Entropy alone is only trusted for .env files (handled by caller).
        # For other file types, require a key-name match too.
        return None
    else:
        return None

    return {
        "key": key,
        "value": value,  # will be masked later
        "detection_reason": reason,
        "entropy_score": round(entropy, 2),
        "pattern_name": matched_pattern,
    }


def deep_scan_credentials(config_dir: Path) -> list:
    """Recursively walk config_dir, scanning all text files for credentials
    using Layer 1 (file walker), Layer 2 (key-name), and Layer 3 (structural
    regex + entropy)."""

    credentials = []
    seen_keys = set()  # Deduplicate by (key, source_file)

    for root, dirs, files in os.walk(config_dir):
        # Prune directories we don't want to descend into
        dirs[:] = [d for d in dirs if not _should_skip_dir(d)]

        for filename in files:
            if _should_skip_file(filename):
                continue

            filepath = Path(root) / filename
            if not _is_text_file(filepath):
                continue

            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except (OSError, PermissionError):
                continue

            # Determine extraction strategy
            strategy = _classify_file(filepath)
            if strategy == "env":
                pairs = _extract_env_pairs(content)
            elif strategy == "json":
                pairs = _extract_json_pairs(content)
            elif strategy == "yaml":
                pairs = _extract_yaml_pairs(content)
            elif strategy == "code":
                pairs = _extract_code_string_literals(content)
            else:
                pairs = _extract_env_pairs(content)

            # Determine storage type from file extension/name
            rel_path = filepath.relative_to(config_dir).as_posix()
            name_lower = filepath.name.lower()
            if name_lower.startswith(".env"):
                storage = "plaintext_env"
            elif filepath.suffix.lower() in (".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".conf"):
                storage = "config_file"
            else:
                storage = "hardcoded_in_code"

            for key, value in pairs:
                dedup_key = (key, rel_path)
                if dedup_key in seen_keys:
                    continue

                result = _check_value(key, value)
                if result:
                    seen_keys.add(dedup_key)
                    credentials.append({
                        "key": result["key"],
                        "value_masked": mask_value(value),
                        "source_file": rel_path,
                        "storage": storage,
                        "detection_reason": result["detection_reason"],
                        "entropy_score": result["entropy_score"],
                        "pattern_name": result["pattern_name"],
                    })

    return credentials


# ── Legacy single-file scanner (kept for backward compat reference) ─────

def read_env_credentials(config_dir: Path) -> list:
    """Legacy: scan only .env file. Superseded by deep_scan_credentials()."""
    env_path = config_dir / ".env"
    if not env_path.exists():
        return []

    credentials = []
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()

            is_named_cred = bool(CREDENTIAL_KEY_PATTERN.search(key))
            entropy = calculate_entropy(value)
            is_high_entropy = len(value) >= 12 and entropy >= 3.5

            if is_named_cred or is_high_entropy:
                credentials.append({
                    "key": key,
                    "value_masked": mask_value(value),
                    "source_file": ".env",
                    "storage": "plaintext_env",
                    "detection_reason": "name_pattern" if is_named_cred else "high_entropy",
                    "entropy_score": round(entropy, 2),
                })
    return credentials


# ── Other config readers (settings, MCP servers, skills) ────────────────

def read_settings(config_dir: Path) -> dict:
    settings_path = config_dir / "settings.json"
    if not settings_path.exists():
        return {"network": {}, "auth": {}, "_missing": True}

    with open(settings_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    gateway = raw.get("gateway", {})
    return {
        "network": {
            "bind_address": gateway.get("bind_address", "unknown"),
            "port": gateway.get("port"),
            "tls_enabled": gateway.get("tls_enabled", False),
        },
        "auth": {
            "token_present": gateway.get("auth_token") is not None
        },
    }


def read_mcp_servers(config_dir: Path) -> list:
    mcp_path = config_dir / "mcp_servers.json"
    if not mcp_path.exists():
        return []

    with open(mcp_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    servers = []
    for entry in raw.get("servers", []):
        servers.append({
            "name": entry.get("name", "unknown"),
            "source": entry.get("source", "unknown"),
            "scopes": entry.get("scopes", []),
            "url": entry.get("url", ""),
            "description": entry.get("description", ""),
            "raw_config": entry.get("config", {}),
            "raw_entry": entry,  # Allows rules to inspect arbitrary 3rd party attributes
        })
    return servers


def read_skills(config_dir: Path) -> list:
    skills_dir = config_dir / "skills"
    if not skills_dir.exists() or not skills_dir.is_dir():
        return []

    skills = []
    for skill_file in skills_dir.glob("*.json"):
        with open(skill_file, "r", encoding="utf-8") as f:
            raw = json.load(f)
        skills.append({
            "name": raw.get("name", skill_file.stem),
            "author": raw.get("author", "unknown"),
            "version": raw.get("version", "unknown"),
            "pinned": raw.get("pinned", False),
            "source": raw.get("source", "unknown"),
        })
    return skills


def collect(config_dir_str: str) -> dict:
    config_dir = Path(config_dir_str)
    if not config_dir.exists():
        raise FileNotFoundError(f"Config directory not found: {config_dir_str}")

    settings = read_settings(config_dir)

    # Use deep scanner (Layer 1 + 2 + 3) instead of legacy .env-only reader
    credentials = deep_scan_credentials(config_dir)

    normalized = {
        "source_path": str(config_dir.resolve()),
        "network": settings["network"],
        "auth": settings["auth"],
        "credentials": credentials,
        "mcp_servers": read_mcp_servers(config_dir),
        "skills": read_skills(config_dir),
    }
    return normalized


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python collector.py /path/to/config_dir")
        sys.exit(1)

    result = collect(sys.argv[1])
    print(json.dumps(result, indent=2))