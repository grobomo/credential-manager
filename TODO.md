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
