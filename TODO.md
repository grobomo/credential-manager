# Credential Manager — TODO

## UX Fixes (completed 2026-04-05)
- [x] T001: Archive store_gui.py — clipboard is now the default/only store method, no GUI
- [x] T002: Created store.py as intuitive entry point (delegates to cred_cli.py)
- [x] T003: Rewrote cmd_store to read clipboard directly via subprocess (powershell Get-Clipboard / pbpaste), validate, store, clear clipboard, zero memory. No GUI dependency.
- [x] T004: Updated SKILL.md — removed GUI references, documented clipboard-first workflow
- [x] T005: Verified E2E: clipboard → store → retrieve → correct value → clipboard cleared

## Unblocked: rone-teams-poller needs rdsec-gateway/access-token stored
Ready to run: `python store.py rdsec-gateway/access-token`
User copies token from RONE portal to clipboard first.

## Code Review (completed 2026-04-05)
- [x] T006: Fix security leak — cmd_verify was printing partial credential values
- [x] T007: DRY — securify.py now imports read_registry/write_registry from cred_cli.py
- [x] T008: Gitignore data files (audit.log, credential-registry.json, protected-keys.json, archived-credentials.jsonl)
- [x] T009: Fix stale --clipboard reference in cmd_protect message
- [x] T010: Fix datetime.utcnow() deprecation warning

## Hardening (completed 2026-04-05)
- [x] T011: Added `--force` flag to store/rotate to bypass validation
- [x] T012: Added `expire` command + expiry checking in verify (warns <7 days, flags expired)
- [x] T013: Added `rotate` command — archives rotation event, stores new from clipboard

## --from-cmd: pipe command output into keyring (completed 2026-04-05)
- [x] T016: Add `--from-cmd "command"` flag to cmd_store — runs command, captures stdout, stores in keyring, zeros memory. Also works with rotate. E2E tested with echo.
- [ ] T017: Fix contaminated creds by re-storing via `--from-cmd` (requires user to identify which creds are contaminated and provide the source command)
- [x] T018: Update SKILL.md with --from-cmd usage docs

## Code review hardening (2026-04-05)
- [x] T019: Fix command injection in claude-cred.js resolve() — added key format validation regex
- [x] T020: Fix stale import paths in claude_cred.py and claude-cred.js docstrings (super-manager -> skills)
- [x] T021: Fix stale import path in SKILL.md Node.js example
- [x] T022: Update store.py to forward --from-cmd and --force flags
