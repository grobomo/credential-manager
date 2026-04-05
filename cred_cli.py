"""
cred_cli.py - Standalone credential manager CLI.

Self-contained -- works without super-manager. Uses OS keyring directly.
Clipboard is the default (and only) method for storing credentials.
All operations are logged to audit.log (never logs secret values).

Usage:
    python cred_cli.py store SERVICE/KEY [--force]  # reads from clipboard
    python cred_cli.py store SERVICE/KEY --from-cmd "command"  # runs command, stores stdout
    python cred_cli.py list [SERVICE]
    python cred_cli.py delete SERVICE/KEY
    python cred_cli.py verify
    python cred_cli.py expire SERVICE/KEY DAYS
    python cred_cli.py rotate SERVICE/KEY [--force]  # clipboard -> replace old
    python cred_cli.py audit [PATH_TO_ENV]
    python cred_cli.py migrate PATH_TO_ENV SERVICE
    python cred_cli.py log [KEY_FILTER]
    python cred_cli.py securify DIRECTORY [--service NAME] [--dry-run]
"""
import sys
import os
import re
import json
import gc
import ctypes
import datetime
import platform
import subprocess

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
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def _secure_zero(ba):
    """Zero out a bytearray's memory (best-effort)."""
    if ba and isinstance(ba, bytearray):
        ctypes.memset((ctypes.c_char * len(ba)).from_buffer(ba), 0, len(ba))


def _validate_secret(value, key):
    """Check if a value looks like a real secret vs clipboard contamination.
    Returns (ok, reason) tuple."""
    if not value:
        return False, "empty value"
    if "\n" in value:
        return False, "contains newlines -- likely clipboard contamination"
    if len(value.split()) > 4:
        return False, f"contains {len(value.split())} words -- likely clipboard contamination"
    bad_starts = ["Resource", "Usage:", "Error", "No ", "WARNING", "INFO", "DEBUG",
                  "Traceback", "  [", "node ", "python ", "bash ", "#!/", "import "]
    for prefix in bad_starts:
        if value.startswith(prefix):
            return False, f"starts with '{prefix}' -- not a secret"
    if len(value) < 4:
        return False, f"only {len(value)} chars -- too short for a secret"
    return True, "ok"


def _read_clipboard():
    """Read clipboard content using platform-appropriate method."""
    if platform.system() == "Windows":
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "Get-Clipboard"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    elif platform.system() == "Darwin":
        result = subprocess.run(
            ["pbpaste"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    else:
        # Linux: try xclip, xsel
        for cmd in [["xclip", "-selection", "clipboard", "-o"], ["xsel", "--clipboard", "--output"]]:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return result.stdout.strip()
            except FileNotFoundError:
                continue
    return None


def _clear_clipboard():
    """Clear clipboard content after storing."""
    try:
        if platform.system() == "Windows":
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", "Set-Clipboard -Value $null"],
                capture_output=True, timeout=5
            )
        elif platform.system() == "Darwin":
            subprocess.run(["pbcopy"], input="", text=True, timeout=5)
        else:
            for cmd in [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]:
                try:
                    subprocess.run(cmd, input="", text=True, timeout=5)
                    break
                except FileNotFoundError:
                    continue
    except Exception:
        pass  # best-effort


def _run_cmd_capture(cmd_str):
    """Run a shell command and capture stdout. Returns (value, error)."""
    try:
        result = subprocess.run(
            cmd_str, shell=True, capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            return None, f"command failed (exit {result.returncode}): {stderr or '(no stderr)'}"
        value = result.stdout.strip()
        if not value:
            return None, "command produced no output"
        return value, None
    except subprocess.TimeoutExpired:
        return None, "command timed out after 30 seconds"
    except Exception as e:
        return None, f"failed to run command: {e}"


def cmd_store(key, force=False, from_cmd=None):
    """Store a credential from clipboard or command output. Validates, stores, zeros memory."""
    if "/" not in key:
        print(f"ERROR: key must be SERVICE/VARIABLE, got: {key}")
        sys.exit(1)

    # Check protected keys
    protected = _load_protected()
    if key in protected:
        existing = keyring.get_password(KEYRING_SERVICE, key)
        if existing:
            ok, _ = _validate_secret(existing, key)
            if ok:
                print(f"BLOCKED: {key} is protected and already has a valid value.")
                print(f"To overwrite, first run: python cred_cli.py unprotect {key}")
                sys.exit(1)

    # Get secret value from command or clipboard
    if from_cmd:
        method = "from-cmd"
        secret_value, err = _run_cmd_capture(from_cmd)
        if err:
            print(f"ERROR: --from-cmd failed: {err}")
            sys.exit(1)
    else:
        method = "clipboard"
        secret_value = _read_clipboard()
        if not secret_value:
            print("ERROR: clipboard is empty or inaccessible")
            print("Copy the secret to your clipboard first, then run this command.")
            sys.exit(1)

    # Validate (skip with --force)
    ok, reason = _validate_secret(secret_value, key)
    if not ok and not force:
        print(f"REJECTED: value failed validation for {key}")
        print(f"Reason: {reason}")
        print(f"Preview: {secret_value[:50]}...")
        print("Use --force to store anyway.")
        audit_log("REJECT", key, f"method={method} reason={reason}")
        sys.exit(1)
    if not ok and force:
        print(f"WARNING: validation failed ({reason}) but --force used, storing anyway.")
        audit_log("STORE", key, f"method={method} forced=true reason={reason}")

    # Store in keyring
    secret_buf = bytearray(secret_value.encode('utf-8'))
    try:
        keyring.set_password(KEYRING_SERVICE, key, secret_buf.decode('utf-8'))
        audit_log("STORE", key, f"method={method}")
    except Exception as e:
        print(f"ERROR: failed to store: {e}")
        sys.exit(1)
    finally:
        _secure_zero(secret_buf)

    # Clear clipboard only if we read from it
    if not from_cmd:
        _clear_clipboard()

    # Update registry
    creds = read_registry()
    service = key.split("/")[0]
    variable = key.split("/", 1)[1]
    existing = next((c for c in creds if c["key"] == key), None)
    if existing:
        existing["added"] = now_iso()
    else:
        creds.append({"key": key, "service": service, "variable": variable, "added": now_iso()})
    write_registry(creds)

    # Zero the local variable too
    secret_value = None
    del secret_buf
    gc.collect()

    source = "command output" if from_cmd else "clipboard (clipboard cleared)"
    print(f"OK - {key} stored from {source}")


def cmd_verify():
    creds = read_registry()
    healthy = []
    issues = []
    warnings = []

    expired = []
    for c in creds:
        key = c["key"]
        try:
            val = keyring.get_password(KEYRING_SERVICE, key)
            if not val:
                issues.append(f"  {key}: registered but not in OS keyring")
                continue

            # Expiry check
            exp = c.get("expires")
            if exp:
                try:
                    exp_dt = datetime.datetime.strptime(exp, "%Y-%m-%dT%H:%M:%SZ").replace(
                        tzinfo=datetime.timezone.utc)
                    now_dt = datetime.datetime.now(datetime.timezone.utc)
                    if now_dt > exp_dt:
                        expired.append(f"  {key}: EXPIRED on {exp}")
                    elif (exp_dt - now_dt).days < 7:
                        warnings.append(f"  {key}: expires in {(exp_dt - now_dt).days} days ({exp})")
                except ValueError:
                    pass

            # Content validation -- detect corrupted values
            problems = []
            if "\n" in val:
                problems.append("contains newlines (likely clipboard contamination)")
            if len(val) > 5 and val.strip().startswith(("{", "[", "<", "Resource", "Usage:", "Error", "No ")):
                problems.append("looks like non-secret content (starts with structural/error text)")
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
    if expired:
        print(f"Expired: {len(expired)}")
        for e in expired:
            print(e)
    if warnings:
        print(f"Warnings: {len(warnings)}")
        for w in warnings:
            print(w)
    if issues:
        print(f"Missing: {len(issues)}")
        for i in issues:
            print(i)
    if not issues and not warnings and not expired:
        print("No issues found.")
    audit_log("VERIFY", "*", f"healthy={len(healthy)} expired={len(expired)} suspect={len(warnings)} issues={len(issues)}")


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
    print(f"Protected: {key} (cannot be overwritten via store)")


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


def cmd_expire(key, days):
    """Set expiry date for a credential (days from now)."""
    if "/" not in key:
        print(f"ERROR: key must be SERVICE/VARIABLE, got: {key}")
        sys.exit(1)

    creds = read_registry()
    entry = next((c for c in creds if c["key"] == key), None)
    if not entry:
        print(f"ERROR: {key} not found in registry")
        sys.exit(1)

    exp_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
    entry["expires"] = exp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    write_registry(creds)
    audit_log("EXPIRE", key, f"days={days} expires={entry['expires']}")
    print(f"Set expiry for {key}: {entry['expires']} ({days} days from now)")


def cmd_rotate(key, force=False, from_cmd=None):
    """Rotate a credential: store new value from clipboard or command, archive old value's metadata."""
    if "/" not in key:
        print(f"ERROR: key must be SERVICE/VARIABLE, got: {key}")
        sys.exit(1)

    # Check old value exists
    old_val = keyring.get_password(KEYRING_SERVICE, key)
    if not old_val:
        print(f"No existing value for {key}. Use 'store' instead.")
        sys.exit(1)

    # Archive rotation event (never archive actual values)
    try:
        with open(ARCHIVE_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "key": key, "action": "rotated", "timestamp": now_iso()
            }) + "\n")
    except Exception:
        pass

    # Store new value
    cmd_store(key, force=force, from_cmd=from_cmd)
    audit_log("ROTATE", key)
    print(f"Rotated: {key} (old value archived, new value stored)")


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
        force = "--force" in args or "-f" in args
        from_cmd = None
        filtered = []
        i = 0
        while i < len(args):
            if args[i] == "--from-cmd" and i + 1 < len(args):
                from_cmd = args[i + 1]
                i += 2
            elif args[i] in ("--clipboard", "--clip", "--force", "-f"):
                i += 1
            else:
                filtered.append(args[i])
                i += 1
        if not filtered:
            print("Usage: cred_cli.py store SERVICE/KEY [--force] [--from-cmd \"command\"]")
            print("Copy the secret to your clipboard first, or use --from-cmd.")
            sys.exit(1)
        cmd_store(filtered[0], force=force, from_cmd=from_cmd)
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
    elif action == "expire":
        if len(args) < 2:
            print("Usage: cred_cli.py expire SERVICE/KEY DAYS")
            sys.exit(1)
        try:
            days = int(args[1])
        except ValueError:
            print(f"ERROR: DAYS must be an integer, got: {args[1]}")
            sys.exit(1)
        cmd_expire(args[0], days)
    elif action == "rotate":
        force = "--force" in args or "-f" in args
        from_cmd = None
        filtered = []
        i = 0
        while i < len(args):
            if args[i] == "--from-cmd" and i + 1 < len(args):
                from_cmd = args[i + 1]
                i += 2
            elif args[i] in ("--force", "-f"):
                i += 1
            else:
                filtered.append(args[i])
                i += 1
        if not filtered:
            print("Usage: cred_cli.py rotate SERVICE/KEY [--force] [--from-cmd \"command\"]")
            print("Copy the NEW secret to clipboard first, or use --from-cmd.")
            sys.exit(1)
        cmd_rotate(filtered[0], force=force, from_cmd=from_cmd)
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
