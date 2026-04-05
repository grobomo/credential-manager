"""
claude_cred.py - Credential resolution for Claude Code MCP servers and skills.

Usage (replaces manual .env loader):
    import sys, os
    sys.path.insert(0, os.path.expanduser('~/.claude/super-manager/credentials'))
    from claude_cred import load_env
    load_env()

Or resolve a single credential:
    from claude_cred import resolve
    token = resolve("wiki-lite/CONFLUENCE_API_TOKEN")
"""
import os
import inspect
from pathlib import Path

SERVICE = "claude-code"

def resolve(key):
    """Resolve a credential from the OS credential store.

    Args:
        key: Credential key in 'service/VARIABLE' format
    Returns:
        The credential value string.
    Raises:
        ValueError if not found.
    """
    import keyring
    value = keyring.get_password(SERVICE, key)
    if value is None:
        raise ValueError("Credential not found in OS store: {}".format(key))
    return value

def resolve_value(value):
    """If value starts with 'credential:', resolve from OS store. Otherwise return as-is."""
    if isinstance(value, str) and value.startswith("credential:"):
        return resolve(value[len("credential:"):])
    return value

def load_env(env_path=None, set_environ=True):
    """Load .env file and resolve credential: prefixes.

    Args:
        env_path: Path to .env file. If None, auto-detects from calling script's directory.
        set_environ: If True, sets os.environ (default behavior matching existing servers).
    Returns:
        Dict of resolved key-value pairs.
    """
    if env_path is None:
        caller_file = inspect.stack()[1].filename
        env_path = str(Path(caller_file).parent / '.env')

    env_file = Path(env_path)
    result = {}

    if not env_file.exists():
        return result

    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip().strip('"\'')

        # Resolve credential: prefix
        value = resolve_value(value)

        result[key] = value
        if set_environ:
            os.environ[key] = value

    return result
