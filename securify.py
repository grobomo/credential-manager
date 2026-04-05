#!/usr/bin/env python3
"""
securify.py - Scan code for hardcoded secrets and replace with keyring calls.

Analyzes Python, JS, YAML, and .env files. Detects hardcoded API keys/tokens,
stores them in OS credential store, and replaces with keyring retrieval calls.

Usage:
    python securify.py DIRECTORY [--service NAME] [--dry-run]
    python securify.py DIRECTORY --service gemini-image-gen
    python securify.py DIRECTORY --dry-run   # preview only

Part of credential-manager skill.
"""
import sys
import os
import re
import json
import shutil
import datetime
from pathlib import Path

SKILL_DIR = os.path.dirname(os.path.abspath(__file__))
REGISTRY_PATH = os.path.join(SKILL_DIR, "credential-registry.json")
KEYRING_SERVICE = "claude-code"

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".mjs", ".cjs", ".yaml", ".yml", ".env", ".json"}
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}

# Value patterns that look like real secrets (not placeholders)
SECRET_VALUE_PATTERNS = [
    r"AIza[0-9A-Za-z\-_]{35}",          # Google API key
    r"sk-[A-Za-z0-9]{20,}",              # OpenAI key
    r"sk-ant-[A-Za-z0-9\-]{20,}",        # Anthropic key
    r"ghp_[A-Za-z0-9]{36}",              # GitHub PAT
    r"gho_[A-Za-z0-9]{36}",              # GitHub OAuth
    r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",  # Slack bot
    r"ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",  # JWT
    r"AKIA[0-9A-Z]{16}",                 # AWS access key
]


def is_secret_varname(name):
    """Check if variable name suggests a secret."""
    upper = name.upper()
    markers = [
        "KEY", "TOKEN", "SECRET", "PASSWORD", "PASS", "AUTH",
        "CREDENTIAL", "BEARER", "JWT", "PRIVATE",
    ]
    return any(p in upper for p in markers)


def is_real_secret_value(value):
    """Check if value looks like a real secret (not a placeholder)."""
    if not value or len(value) < 8:
        return False
    placeholders = [
        "your-", "your_", "xxx", "placeholder", "change-me", "TODO",
        "example", "test", "dummy", "fake", "sample", "replace",
        "credential:", "process.env", "os.environ", "keyring.",
    ]
    lower = value.lower()
    if any(p in lower for p in placeholders):
        return False
    for pattern in SECRET_VALUE_PATTERNS:
        if re.match(pattern, value):
            return True
    # Long alphanumeric strings (20+) are likely secrets
    if re.match(r"^[A-Za-z0-9+/=_\-]{20,}$", value) and not value.isdigit():
        return True
    return False


def read_registry():
    try:
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            return json.load(f).get("credentials", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def write_registry(creds):
    data = {"credentials": creds}
    tmp = REGISTRY_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, REGISTRY_PATH)


def store_credential(key, value, dry_run=False):
    """Store a credential in the OS keyring."""
    if dry_run:
        return True
    try:
        import keyring
        keyring.set_password(KEYRING_SERVICE, key, value)
        return True
    except Exception as e:
        print(f"  [ERR] Failed to store {key}: {e}")
        return False


def register_credential(key, service, variable, creds):
    """Add credential to registry if not already there."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    existing = next((c for c in creds if c["key"] == key), None)
    if existing:
        existing["added"] = now
    else:
        creds.append({"key": key, "service": service, "variable": variable, "added": now})


# --- Finding dataclass ---

class Finding:
    """A detected secret in code."""
    def __init__(self, file_path, line_num, var_name, value, pattern_type, original_line):
        self.file_path = file_path
        self.line_num = line_num
        self.var_name = var_name
        self.value = value
        self.pattern_type = pattern_type
        self.original_line = original_line

    def __repr__(self):
        if self.value and len(self.value) > 8:
            val_preview = self.value[:8] + "..."
        elif self.value:
            val_preview = self.value[:4] + "..."
        else:
            val_preview = "(env ref)"
        return f"  L{self.line_num}: {self.var_name} = {val_preview} [{self.pattern_type}]"


# --- Language-specific scanners ---

def scan_python(file_path, content, lines):
    """Scan Python file for secrets."""
    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        # os.environ.get("KEY", "default_value")
        m = re.search(
            r"""os\.environ\.get\(\s*["']([A-Z_]+)["']\s*,\s*["']([^"']+)["']\s*\)""",
            line,
        )
        if m:
            var, default = m.group(1), m.group(2)
            if is_secret_varname(var) and is_real_secret_value(default):
                findings.append(Finding(file_path, i, var, default, "env_default", line))
                continue

        # os.environ.get("KEY")
        m = re.search(r"""os\.environ\.get\(\s*["']([A-Z_]+)["']\s*\)""", line)
        if m:
            var = m.group(1)
            if is_secret_varname(var):
                findings.append(Finding(file_path, i, var, None, "env_get", line))
                continue

        # os.environ["KEY"]
        m = re.search(r"""os\.environ\[\s*["']([A-Z_]+)["']\s*\]""", line)
        if m:
            var = m.group(1)
            if is_secret_varname(var):
                findings.append(Finding(file_path, i, var, None, "env_bracket", line))
                continue

        # VAR = "hardcoded_value"
        m = re.match(r"""\s*([A-Z_][A-Z_0-9]*)\s*=\s*["']([^"']{8,})["']""", line)
        if m:
            var, val = m.group(1), m.group(2)
            if is_secret_varname(var) and is_real_secret_value(val):
                findings.append(Finding(file_path, i, var, val, "hardcoded", line))
                continue

        # keyword arg like api_key="value"
        m = re.search(r"""(api_key|token|secret|password|auth)\s*=\s*["']([^"']{8,})["']""", line, re.I)
        if m:
            var, val = m.group(1), m.group(2)
            if is_real_secret_value(val):
                findings.append(Finding(file_path, i, var.upper(), val, "hardcoded_kwarg", line))

    return findings


def scan_javascript(file_path, content, lines):
    """Scan JavaScript/TypeScript file for secrets."""
    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # process.env.KEY || "default"
        m = re.search(
            r"""process\.env\.([A-Z_]+)\s*\|\|\s*["']([^"']+)["']""",
            line,
        )
        if m:
            var, default = m.group(1), m.group(2)
            if is_secret_varname(var) and is_real_secret_value(default):
                findings.append(Finding(file_path, i, var, default, "env_default", line))
                continue

        # process.env.KEY (no default)
        m = re.search(r"process\.env\.([A-Z_][A-Z_0-9]*)", line)
        if m:
            var = m.group(1)
            if is_secret_varname(var):
                findings.append(Finding(file_path, i, var, None, "env_get", line))
                continue

        # const KEY = "hardcoded"
        m = re.match(r"""\s*(?:const|let|var)\s+([A-Z_][A-Z_0-9]*)\s*=\s*["']([^"']{8,})["']""", line)
        if m:
            var, val = m.group(1), m.group(2)
            if is_secret_varname(var) and is_real_secret_value(val):
                findings.append(Finding(file_path, i, var, val, "hardcoded", line))

    return findings


def scan_yaml(file_path, content, lines):
    """Scan YAML file for secrets."""
    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        m = re.match(r"""\s*([A-Za-z_][A-Za-z_0-9]*)\s*:\s*["']?([^"'#\n]+)["']?""", line)
        if m:
            var, val = m.group(1), m.group(2).strip()
            if is_secret_varname(var) and is_real_secret_value(val) and not val.startswith("credential:"):
                findings.append(Finding(file_path, i, var.upper(), val, "yaml_value", line))

    return findings


def scan_env(file_path, content, lines):
    """Scan .env file for plaintext secrets."""
    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        m = re.match(r"^([A-Za-z_][A-Za-z_0-9]*)=(.*)$", stripped)
        if m:
            var, val = m.group(1), m.group(2).strip().strip("'\"")
            if is_secret_varname(var) and val and not val.startswith("credential:"):
                if is_real_secret_value(val) or len(val) > 8:
                    findings.append(Finding(file_path, i, var, val, "env_plaintext", line))

    return findings


# --- Replacement logic ---

def make_python_replacement(finding, service, keyring_key):
    """Generate replacement code for Python findings."""
    KS = KEYRING_SERVICE

    if finding.pattern_type == "env_default":
        old = re.compile(
            r"""os\.environ\.get\(\s*["']""" + re.escape(finding.var_name) +
            r"""["']\s*,\s*["'][^"']+["']\s*\)"""
        )
        new_expr = f'keyring.get_password("{KS}", "{keyring_key}")'
        return old.sub(new_expr, finding.original_line), True

    elif finding.pattern_type == "env_get":
        old = re.compile(
            r"""os\.environ\.get\(\s*["']""" + re.escape(finding.var_name) + r"""["']\s*\)"""
        )
        new_expr = f'keyring.get_password("{KS}", "{keyring_key}")'
        return old.sub(new_expr, finding.original_line), True

    elif finding.pattern_type == "env_bracket":
        old = re.compile(
            r"""os\.environ\[\s*["']""" + re.escape(finding.var_name) + r"""["']\s*\]"""
        )
        new_expr = f'keyring.get_password("{KS}", "{keyring_key}")'
        return old.sub(new_expr, finding.original_line), True

    elif finding.pattern_type in ("hardcoded", "hardcoded_kwarg"):
        old = re.compile(r"""["']""" + re.escape(finding.value) + r"""["']""")
        new_expr = f'keyring.get_password("{KS}", "{keyring_key}")'
        return old.sub(new_expr, finding.original_line, count=1), True

    return finding.original_line, False


def make_js_replacement(finding, service, keyring_key):
    """Generate replacement code for JS findings."""
    KS = KEYRING_SERVICE
    resolve_call = (
        "require(require('path').join(require('os').homedir(),"
        "'.claude/skills/credential-manager/claude-cred.js'))"
        f'.resolve("{keyring_key}")'
    )

    if finding.pattern_type == "env_default":
        old = re.compile(
            r"process\.env\." + re.escape(finding.var_name) +
            r"""\s*\|\|\s*["'][^"']+["']"""
        )
        return old.sub(resolve_call, finding.original_line), False

    elif finding.pattern_type == "env_get":
        old = re.compile(r"process\.env\." + re.escape(finding.var_name))
        return old.sub(resolve_call, finding.original_line), False

    elif finding.pattern_type == "hardcoded":
        old = re.compile(r"""["']""" + re.escape(finding.value) + r"""["']""")
        return old.sub(resolve_call, finding.original_line, count=1), False

    return finding.original_line, False


def make_yaml_replacement(finding, service, keyring_key):
    """Generate replacement for YAML findings."""
    return finding.original_line.replace(finding.value, f"credential:{keyring_key}"), False


def make_env_replacement(finding, service, keyring_key):
    """Generate replacement for .env findings."""
    return f"{finding.var_name}=credential:{keyring_key}\n", False


# --- Main orchestrator ---

def securify(target_dir, service=None, dry_run=False):
    """Scan directory for secrets and replace with keyring calls.

    Args:
        target_dir: Directory to scan
        service: Service name prefix for keyring keys (default: dirname)
        dry_run: If True, preview changes without modifying files.

    Returns:
        List of findings.
    """
    target = Path(target_dir).resolve()
    if not target.is_dir():
        print(f"Error: not a directory: {target}")
        return []

    if service is None:
        service = target.name.lower().replace(" ", "-")

    prefix = "[DRY RUN] " if dry_run else ""
    print(f"{prefix}Scanning: {target}")
    print(f"Service name: {service}")
    print()

    # Collect files
    all_files = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            fp = Path(root) / f
            if fp.suffix in SCAN_EXTENSIONS or fp.name == ".env":
                all_files.append(fp)

    print(f"Files to scan: {len(all_files)}")

    # Scan each file
    all_findings = []
    for fp in all_files:
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
            file_lines = content.splitlines(keepends=True)
        except Exception:
            continue

        ext = fp.suffix
        if ext == ".py":
            findings = scan_python(str(fp), content, file_lines)
        elif ext in (".js", ".ts", ".mjs", ".cjs"):
            findings = scan_javascript(str(fp), content, file_lines)
        elif ext in (".yaml", ".yml"):
            findings = scan_yaml(str(fp), content, file_lines)
        elif ext == ".env" or fp.name == ".env":
            findings = scan_env(str(fp), content, file_lines)
        else:
            continue

        if findings:
            all_findings.extend(findings)
            rel = fp.relative_to(target)
            print(f"\n  {rel} ({len(findings)} secrets)")
            for finding in findings:
                print(f"    {finding}")

    if not all_findings:
        print("\nNo secrets found. Code is clean.")
        return []

    print(f"\n{'=' * 50}")
    print(f"Found {len(all_findings)} secrets across {len(set(f.file_path for f in all_findings))} files")

    if dry_run:
        print(f"\n{prefix}No changes made. Remove --dry-run to apply.")
        return all_findings

    # --- Apply replacements ---
    print("\nApplying replacements...")

    creds = read_registry()
    files_modified = {}

    for finding in all_findings:
        fp = finding.file_path
        keyring_key = f"{service}/{finding.var_name}"

        # Store hardcoded values in keyring
        if finding.value:
            if store_credential(keyring_key, finding.value):
                register_credential(keyring_key, service, finding.var_name, creds)
                val_preview = finding.value[:6] + "..."
                print(f"  [STORE] {keyring_key} ({val_preview})")

        # Load file lines if not yet cached
        if fp not in files_modified:
            content = Path(fp).read_text(encoding="utf-8", errors="replace")
            files_modified[fp] = {
                "lines": content.splitlines(keepends=True),
                "needs_import": False,
                "ext": Path(fp).suffix,
            }

        fdata = files_modified[fp]
        line_idx = finding.line_num - 1
        if line_idx >= len(fdata["lines"]):
            continue

        ext = fdata["ext"]
        if ext == ".py":
            new_line, needs_imp = make_python_replacement(finding, service, keyring_key)
        elif ext in (".js", ".ts", ".mjs", ".cjs"):
            new_line, needs_imp = make_js_replacement(finding, service, keyring_key)
        elif ext in (".yaml", ".yml"):
            new_line, needs_imp = make_yaml_replacement(finding, service, keyring_key)
        elif ext == ".env" or Path(fp).name == ".env":
            new_line, needs_imp = make_env_replacement(finding, service, keyring_key)
        else:
            continue

        fdata["lines"][line_idx] = new_line
        if needs_imp:
            fdata["needs_import"] = True
        print(f"  [REPLACE] {Path(fp).name}:{finding.line_num} {finding.var_name}")

    # Write modified files
    for fp, fdata in files_modified.items():
        p = Path(fp)

        # Backup original
        backup = p.with_suffix(p.suffix + ".bak")
        shutil.copy2(p, backup)

        # Add keyring import if needed (Python files)
        if fdata["needs_import"] and fdata["ext"] == ".py":
            file_lines = fdata["lines"]
            has_import = any("import keyring" in l for l in file_lines)
            if not has_import:
                insert_at = 0
                for idx, line in enumerate(file_lines):
                    stripped = line.strip()
                    if stripped.startswith("import ") or stripped.startswith("from "):
                        insert_at = idx + 1
                file_lines.insert(insert_at, "import keyring\n")
                fdata["lines"] = file_lines

        p.write_text("".join(fdata["lines"]), encoding="utf-8")
        print(f"  [WRITE] {p.name} (backup: {backup.name})")

    write_registry(creds)

    print(f"\n{'=' * 50}")
    print(f"Securified: {len(all_findings)} secrets in {len(files_modified)} files")
    print(f"Backups: *.bak files created for each modified file")
    print(f"Registry: {len(creds)} total credentials")
    return all_findings


# --- CLI ---

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Scan code for secrets, replace with keyring calls")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--service", "-s", help="Service name for keyring keys (default: dirname)")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Preview without modifying")
    args = parser.parse_args()
    securify(args.directory, service=args.service, dry_run=args.dry_run)
