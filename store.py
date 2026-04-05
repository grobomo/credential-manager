"""
store.py - Convenience entry point for storing credentials.

Usage:
    python store.py SERVICE/KEY
    (copy the secret to clipboard first)

Delegates to cred_cli.py store command.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cred_cli import cmd_store

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python store.py SERVICE/KEY")
        print("Copy the secret to your clipboard first, then run this command.")
        sys.exit(1)
    key = sys.argv[1]
    cmd_store(key)
