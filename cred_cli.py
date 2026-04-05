"""
cred_cli.py - Standalone credential manager CLI.

Self-contained -- works without super-manager. Uses OS keyring directly.
All operations are logged to audit.log (never logs secret values).

Usage:
    python cred_cli.py list [SERVICE]
    python cred_cli.py store SERVICE/KEY [--clipboard]
    python cred_cli.py delete SERVICE/KEY
    python cred_cli.py verify
    python cred_cli.py audit [PATH_TO_ENV]
    python cred_cli.py migrate PATH_TO_ENV SERVICE
    python cred_cli.py log [KEY_FILTER]
    python cred_cli.py securify DIRECTORY [--service NAME] [--dry-run]
"""
import sys
import os
import re
import json
import datetime
import platform

SKILL_DIR = os.path.dirname(os.path.abspath(__file__))
REGISTRY_PATH = os.path.join(SKILL_DIR, "credential-registry.json")
ARCHIVE_PATH = os.path.join(SKILL_DIR, "archived-credentials.jsonl")
AUDIT_LOG_PATH = os.path.join(SKILL_DIR, "audit.log")
KEYRING_SERVICE = "claude-code"
SECRET_PATTERNS = ["TOKEN", "KEY", "SECRET", "PASSWORD", "PASS", "AUTH"]

try:
    import keyring
except ImportError:
    print("ERROR: keyring not installed. Run: pip install keyring")
    sys.exit(1)


# --- Registry I/O ---

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


def now_iso():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def audit_log(action, key, detail="", caller=None):
    """Append an entry to audit.log. Never logs secret values."""
    ts = now_iso()
    if caller is None:
        # Walk stack to find the calling script
        import inspect
        frame = inspect.currentframe().f_back
        caller = os.path.basename(frame.f_code.co_filename) if frame else "unknown"
    entry = f"{ts}  {action:<10}  {key:<40}  caller={caller}"
    if detail:
        entry += f"  {detail}"
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception:
        pass  # audit logging should never break the tool


# --- Commands ---

def cmd_list(service_filter=None):
    creds = read_registry()
    if not creds:
        print("No credentials stored.")
        return

    missing = []
    for c in creds:
        # Filter by service name OR key prefix
        if service_filter:
            svc = c.get("service", "")
            key = c.get("key", "")
            if svc != service_filter and not key.startswith(service_filter + "/") and service_filter.lower() not in key.lower():
                continue
        key = c["key"]
        try:
            val = keyring.get_password(KEYRING_SERVICE, key)
            status = "[OK]" if val else "[MISSING]"
            if not val:
                missing.append(key)
        except Exception:
            status = "[ERROR]"
            missing.append(key)
        print(f"  {status} {key}  (added: {c.get('added', '?')})")

    services = set(c["service"] for c in creds)
    print(f"\n{len(creds)} credentials across {len(services)} services")
    if missing:
        print(f"\nWARNING: {len(missing)} credential(s) missing from OS keyring:")
        for k in missing:
            print(f"  {k}")
        print("Run 'cred_cli.py log' to check audit history for these keys.")
    audit_log("LIST", service_filter or "*")


def cmd_store(key, clipboard=False):
    if "/" not in key:
        print(f"ERROR: key must be SERVICE/VARIABLE, got: {key}")
        sys.exit(1)
    gui_path = os.path.join(SKILL_DIR, "store_gui.py")
    if os.path.exists(gui_path):
        clip_flag = " --clipboard" if clipboard else ""
        method = "clipboard" if clipboard else "gui"
        audit_log("STORE", key, f"method={method}")
        os.system(f'python "{gui_path}" "{key}"{clip_flag}')
    else:
        print(f"ERROR: store_gui.py not found at {gui_path}")
        sys.exit(1)


def cmd_verify():
    creds = read_registry()
    healthy = []
    issues = []
    warnings = []

    for c in creds:
        key = c["key"]
        try:
            val = keyring.get_password(KEYRING_SERVICE, key)
            if not val:
                issues.append(f"  {key}: registered but not in OS keyring")
                continue

            # Content validation -- detect corrupted values
            problems = []
            if "\n" in val:
                problems.append("contains newlines (likely clipboard contamination)")
            if len(val) > 5 and val.strip().startswith(("{", "[", "<", "Resource", "Usage:", "Error", "No ")):
                problems.append(f"looks like non-secret content: {val[:40]}...")
            if any(p in key.upper() for p in ["SECRET", "TOKEN", "KEY", "PASSWORD"]):
                if len(val) < 8:
                    problems.append(f"suspiciously short ({len(val)} chars)")
                if " " in val and len(val.split()) > 3:
                    problems.append("contains multiple words (likely clipboard contamination)")

            if problems:
                warnings.append(f"  {key}: SUSPECT VALUE -- {'; '.join(problems)}")
            else:
                healthy.append(key)
        except Exception as e:
            issues.append(f"  {key}: keyring error - {e}")

    print(f"Healthy: {len(healthy)}")
    if warnings:
        print(f"Suspect: {len(warnings)} (possibly corrupted)")
        for w in warnings:
            print(w)
    if issues:
        print(f"Missing: {len(issues)}")
        for i in issues:
            print(i)
    if not issues and not warnings:
        print("No issues found.")
    audit_log("VERIFY", "*", f"healthy={len(healthy)} suspect={len(warnings)} issues={len(issues)}")


def cmd_audit(env_path=None):
    """Scan .env files for plaintext secrets."""
    env_files = []
    if env_path:
        env_files.append(("custom", env_path))
    else:
        # Scan common MCP locations
        projects = os.environ.get("MCP_DIR", os.path.expanduser("~/mcp"))
        if os.path.isdir(projects):
            for d in os.listdir(projects):
                env = os.path.join(projects, d, ".env")
                if os.path.isfile(env):
                    env_files.append((d, env))

    findings = 0
    for service, path in env_files:
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                m = re.match(r"^([A-Za-z_]\w*)=(.*)$", s)
                if not m:
                    continue
                var, val = m.group(1), m.group(2).strip().strip("'\"")
                if any(p in var.upper() for p in SECRET_PATTERNS):
                    if val and not val.startswith("credential:"):
                        print(f"  PLAINTEXT: {var} in {path}")
                        print(f"    Fix: python cred_cli.py migrate \"{path}\" {service}")
                        findings += 1

    print(f"\n{findings} plaintext secrets found across {len(env_files)} .env files")


def cmd_migrate(env_path, service):
    """Migrate plaintext secrets from .env to credential store."""
    if not os.path.isfile(env_path):
        print(f"ERROR: file not found: {env_path}")
        sys.exit(1)

    with open(env_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    creds = read_registry()
    migrated = []
    new_lines = []

    for line in lines:
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            new_lines.append(line)
            continue

        m = re.match(r"^([A-Za-z_]\w*)=(.*)$", s)
        if not m:
            new_lines.append(line)
            continue

        var = m.group(1)
        val = m.group(2).strip().strip("'\"")

        if not any(p in var.upper() for p in SECRET_PATTERNS):
            new_lines.append(line)
            continue
        if val.startswith("credential:") or not val:
            new_lines.append(line)
            continue

        key = f"{service}/{var}"
        try:
            keyring.set_password(KEYRING_SERVICE, key, val)
        except Exception as e:
            print(f"  SKIP {var}: keyring error - {e}")
            new_lines.append(line)
            continue

        # Update registry
        existing = next((c for c in creds if c["key"] == key), None)
        if existing:
            existing["added"] = now_iso()
        else:
            creds.append({"key": key, "service": service, "variable": var, "added": now_iso()})

        new_lines.append(f"{var}=credential:{key}\n")
        migrated.append(key)
        audit_log("MIGRATE", key, f"from={os.path.basename(env_path)}")
        print(f"  Migrated: {var} -> credential:{key}")

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    write_registry(creds)
    print(f"\n{len(migrated)} secrets migrated from {os.path.basename(env_path)}")


def cmd_delete(key):
    """Delete a credential from keyring and registry."""
    if "/" not in key:
        print(f"ERROR: key must be SERVICE/VARIABLE, got: {key}")
        sys.exit(1)

    creds = read_registry()
    found = any(c["key"] == key for c in creds)

    # Remove from keyring
    try:
        existing = keyring.get_password(KEYRING_SERVICE, key)
        if existing:
            keyring.delete_password(KEYRING_SERVICE, key)
            print(f"  Removed from OS keyring: {key}")
        else:
            print(f"  Not in OS keyring: {key}")
    except Exception as e:
        print(f"  Keyring error: {e}")

    # Remove from registry
    if found:
        creds = [c for c in creds if c["key"] != key]
        write_registry(creds)
        print(f"  Removed from registry: {key}")
    else:
        print(f"  Not in registry: {key}")

    # Archive
    try:
        with open(ARCHIVE_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps({"key": key, "action": "deleted", "timestamp": now_iso()}) + "\n")
    except Exception:
        pass

    audit_log("DELETE", key)
    print(f"  Deleted: {key}")


def cmd_log(key_filter=None, tail=50):
    """Show audit log entries. Optionally filter by key name."""
    if not os.path.isfile(AUDIT_LOG_PATH):
        print("No audit log yet. Operations will be logged going forward.")
        return

    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if key_filter:
        lines = [l for l in lines if key_filter in l]

    # Show last N lines
    for line in lines[-tail:]:
        print(line.rstrip())

    total = len(lines)
    if total > tail:
        print(f"\n... showing last {tail} of {total} entries. Use 'log KEY' to filter.")


PROTECTED_PATH = os.path.join(SKILL_DIR, "protected-keys.json")


def _load_protected():
    try:
        with open(PROTECTED_PATH, "r") as f:
            return json.load(f).get("protected", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_protected(keys):
    with open(PROTECTED_PATH, "w") as f:
        json.dump({"protected": sorted(set(keys))}, f, indent=2)
        f.write("\n")


def cmd_protect(key):
    """Mark a key as protected -- cannot be overwritten via clipboard store."""
    keys = _load_protected()
    if key in keys:
        print(f"Already protected: {key}")
        return
    keys.append(key)
    _save_protected(keys)
    audit_log("PROTECT", key)
    print(f"Protected: {key} (cannot be overwritten via --clipboard)")


def cmd_unprotect(key):
    """Remove protection from a key."""
    keys = _load_protected()
    if key not in keys:
        print(f"Not protected: {key}")
        return
    keys.remove(key)
    _save_protected(keys)
    audit_log("UNPROTECT", key)
    print(f"Unprotected: {key}")


def cmd_list_protected():
    """List all protected keys."""
    keys = _load_protected()
    if not keys:
        print("No protected keys.")
        print("Protect a key: python cred_cli.py protect SERVICE/KEY")
        return
    print(f"Protected keys ({len(keys)}):")
    for k in sorted(keys):
        print(f"  {k}")


# --- Main ---

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    action = sys.argv[1]
    args = sys.argv[2:]

    if action == "list":
        cmd_list(args[0] if args else None)
    elif action == "store":
        remaining = [a for a in args if a not in ("--clipboard", "--clip")]
        clipboard = "--clipboard" in args or "--clip" in args
        if not remaining:
            print("Usage: cred_cli.py store SERVICE/KEY [--clipboard]")
            sys.exit(1)
        cmd_store(remaining[0], clipboard=clipboard)
    elif action == "verify":
        cmd_verify()
    elif action == "audit":
        cmd_audit(args[0] if args else None)
    elif action == "migrate":
        if len(args) < 2:
            print("Usage: cred_cli.py migrate PATH_TO_ENV SERVICE")
            sys.exit(1)
        cmd_migrate(args[0], args[1])
    elif action == "delete":
        if not args:
            print("Usage: cred_cli.py delete SERVICE/KEY")
            sys.exit(1)
        cmd_delete(args[0])
    elif action == "log":
        key_filter = args[0] if args else None
        cmd_log(key_filter)
    elif action == "protect":
        if not args:
            print("Usage: cred_cli.py protect SERVICE/KEY")
            sys.exit(1)
        cmd_protect(args[0])
    elif action == "unprotect":
        if not args:
            print("Usage: cred_cli.py unprotect SERVICE/KEY")
            sys.exit(1)
        cmd_unprotect(args[0])
    elif action == "protected":
        cmd_list_protected()
    elif action == "securify":
        if not args:
            print("Usage: cred_cli.py securify DIRECTORY [--service NAME] [--dry-run]")
            sys.exit(1)
        from securify import securify
        directory = args[0]
        service = None
        dry_run = False
        i = 1
        while i < len(args):
            if args[i] in ("--service", "-s") and i + 1 < len(args):
                service = args[i + 1]
                i += 2
            elif args[i] in ("--dry-run", "-n"):
                dry_run = True
                i += 1
            else:
                i += 1
        securify(directory, service=service, dry_run=dry_run)
    else:
        print(f"Unknown command: {action}")
        print(__doc__)
        sys.exit(1)
