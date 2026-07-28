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
    ".eggs", ".idea", ".vscode", ".pnpm-store", ".next", "out",
    ".turbo", "coverage", ".cache", ".npm", "vendor", "tmp", "temp",
    "docs", "documentation", "test", "tests", "__tests__", "qa",
    "examples", "fixtures", "patches", "git-hooks",
    "ui", "assets", "public", "static", "components", "pages",
}

# Files to always skip
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock", "composer.lock",
    "bundle.js", "bundle.min.js", "vendor.js",
    "CHANGELOG.md", "README.md", "SECURITY.md", "AGENTS.md",
}

# Config file extensions (always scanned)
CONFIG_EXTENSIONS = {
    ".json", ".yaml", ".yml", ".toml",
    ".cfg", ".ini", ".conf", ".properties", ".env",
}

# Code file extensions (scanned if path/name matches candidate config keywords)
CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".sh", ".bash", ".zsh",
    ".rb", ".go", ".java", ".rs", ".php",
}

# Keywords in filename/path that warrant scanning a code file
CANDIDATE_PATH_KEYWORDS = {
    "config", "setting", "env", "secret", "credential",
    "key", "auth", "server", "mcp", "skill", "api", "token",
    "gateway", "client", "db", "database", "pass", "pwd",
}

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
    try:
        if filepath.stat().st_size > 250_000:
            return False
    except OSError:
        return False

    name = filepath.name.lower()
    # Any file starting with .env (handles .env, .env.local, .env.prod, etc.)
    if name.startswith(".env"):
        return True

    suffix = filepath.suffix.lower()
    if suffix in BINARY_EXTENSIONS:
        return False

    # Always scan explicit configuration format files
    if suffix in CONFIG_EXTENSIONS:
        return True

    # For code files, scan if file name/path contains candidate security/config keywords or is in root
    if suffix in CODE_EXTENSIONS:
        path_str = filepath.as_posix().lower()
        if any(kw in path_str for kw in CANDIDATE_PATH_KEYWORDS):
            return True
        if len(filepath.parts) <= 2:  # Root level code file
            return True
        return False

    # No extension — dotfiles like .bashrc, .profile, etc.
    if not suffix and name.startswith("."):
        return True

    return False


TEST_FILE_SUFFIXES = (
    ".test.ts", ".spec.ts", ".test.js", ".spec.js",
    ".test.py", ".spec.py", ".test.jsx", ".spec.jsx", ".test.tsx", ".spec.tsx"
)


def _should_skip_dir(dirname: str) -> bool:
    d_lower = dirname.lower()
    return d_lower in SKIP_DIRS or d_lower.startswith(".") or "test-" in d_lower or "-test" in d_lower or "test" in d_lower


def _should_skip_file(filename: str) -> bool:
    name_lower = filename.lower()
    if name_lower in SKIP_FILES:
        return True
    if any(name_lower.endswith(suf) for suf in TEST_FILE_SUFFIXES):
        return True
    return False


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
    """Recursively extract key-value pairs from JSON, filtering to candidate credentials."""
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
                    if CREDENTIAL_KEY_PATTERN.search(k) or any(regex.search(v) for _, regex in STRUCTURAL_SECRET_PATTERNS):
                        pairs.append((path, v))
                else:
                    _walk(v, path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _walk(item, f"{prefix}[{i}]")

    _walk(data)
    return pairs


def _extract_yaml_pairs(content: str) -> list:
    """Extract key=value pairs from YAML using simple line-by-line regex."""
    pairs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_.\-]*)\s*:\s*(.+)$', line)
        if m:
            key, value = m.group(1).strip(), m.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            if value:
                if CREDENTIAL_KEY_PATTERN.search(key) or any(regex.search(value) for _, regex in STRUCTURAL_SECRET_PATTERNS):
                    pairs.append((key, value))
    return pairs


def _extract_code_string_literals(content: str) -> list:
    """Extract string assignments from code files (Python, JS, TS).
    Filters to candidate credential keys or values matching structural secret patterns."""
    pairs = []
    patterns = [
        re.compile(r'''^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']{8,})["']''', re.MULTILINE),
        re.compile(r'''^\s*(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']{8,})["']''', re.MULTILINE),
        re.compile(r'''^\s*export\s+(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([^"']{8,})["']''', re.MULTILINE),
    ]
    for pattern in patterns:
        for m in pattern.finditer(content):
            key, val = m.group(1), m.group(2)
            # Fast filter: only keep if key name matches credential pattern or value matches structural secret
            if CREDENTIAL_KEY_PATTERN.search(key) or any(regex.search(val) for _, regex in STRUCTURAL_SECRET_PATTERNS):
                pairs.append((key, val))
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


def _check_value(key: str, value: str, storage: str = "plaintext_env") -> dict | None:
    """Check a key-value pair against all detection layers.
    Returns a credential dict if detected, else None."""

    # ── False-positive filters (applied before any detection) ──
    value_lower = value.lower()

    # URLs, file paths, package refs — high entropy but not secrets
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

    # Skip known non-credential JSON/Code key suffixes & common identifier constants
    key_lower = key.lower()
    key_leaf = key_lower.rsplit(".", 1)[-1] if "." in key_lower else key_lower
    NON_CRED_KEYS = {
        "name", "description", "url", "source", "author", "version",
        "label", "title", "type", "format", "host", "port",
        "path", "scopes", "sandboxed", "pinned", "header", "prefix",
        "filename", "suffix", "flag", "code", "schema", "attribute",
    }
    clean_leaf = re.sub(r'\[\d+\]\.?', '', key_leaf).strip(".")
    if clean_leaf in NON_CRED_KEYS or any(key_lower.endswith(s) for s in ("_filename", "_header", "_prefix", "_path", "_flag", "_schema", "_attribute", "_kind", "_type")):
        has_structural_match = any(regex.search(value) for _, regex in STRUCTURAL_SECRET_PATTERNS)
        if not has_structural_match:
            return None

    # ── Layer 2: Key name pattern ──
    is_named_cred = bool(CREDENTIAL_KEY_PATTERN.search(key))

    # ── Layer 3a: Structural secret signatures ──
    matched_pattern = None
    for pattern_name, regex in STRUCTURAL_SECRET_PATTERNS:
        if regex.search(value):
            matched_pattern = pattern_name
            break

    # ── Layer 3b: Shannon Entropy ──
    entropy = calculate_entropy(value)
    is_high_entropy = len(value) >= 12 and entropy >= 3.5

    # ── Precision Classification ──
    # 1. Structural secret signatures are ALWAYS secrets across all storage types.
    if matched_pattern:
        reason = "structural_signature"

    # 2. Plaintext .env files: trusted for name_pattern or high_entropy.
    elif storage == "plaintext_env":
        if is_named_cred:
            reason = "name_pattern"
        elif is_high_entropy:
            reason = "high_entropy"
        else:
            return None

    # 3. Hardcoded in code: require structural match OR a true secret token
    # Filter out code constants where value contains namespace separators (:, ., -) or matches key
    elif storage == "hardcoded_in_code":
        if is_high_entropy and is_named_cred:
            val_clean = value.strip('"\'')
            # Filter out code constants, env var names (containing _ or - or : or .), alphabet sets, or matching keys
            if "_" in val_clean or "-" in val_clean or ":" in val_clean or "." in val_clean or val_clean.upper() in key.upper() or key.upper() in val_clean.upper() or "abcdef" in val_clean.lower() or "012345" in val_clean:
                return None
            reason = "high_entropy"
        else:
            return None

    # 4. Config files (.json, .yaml): require high_entropy and is_named_cred
    elif is_high_entropy and is_named_cred:
        reason = "high_entropy"
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

                result = _check_value(key, value, storage)
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