"""
store.py - Convenience entry point for storing credentials.

Usage:
    python store.py SERVICE/KEY [--force] [--from-cmd "command"]
    (copy the secret to clipboard first, or use --from-cmd)

Delegates to cred_cli.py store command.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cred_cli import cmd_store

if __name__ == "__main__":
    args = sys.argv[1:]
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
        print("Usage: python store.py SERVICE/KEY [--force] [--from-cmd \"command\"]")
        print("Copy the secret to your clipboard first, or use --from-cmd.")
        sys.exit(1)
    cmd_store(filtered[0], force=force, from_cmd=from_cmd)
