---


name: credential-manager
description: Store and retrieve API tokens/secrets in OS credential store (Windows Credential Manager / macOS Keychain)
keywords:
  - credential
  - secret
  - token
  - keyring
  - vault
  - password
  - api_key
  - apikey
  - jwt
  - bearer
  - rdsec
  - sops
  - from-literal
  - api
  - key
  - auth
  - bot
  - access
  - private
  - webhook
  - openai
  - anthropic
  - telegram
  - gateway
  - encryption
  - kubectl
  - paste
  - enter
  - any
  - come
  - up:
---

# Credential Manager

Stores API tokens/secrets in the OS credential store instead of plaintext files. Part of super-manager.

## HARD RULES (non-negotiable)

- **NEVER** ask user to paste/type credentials in chat
- **NEVER** output credential values in chat, logs, or memory
- **NEVER** read .env files (may contain secrets)
- **NEVER** write secrets to plaintext files, YAML, JSON, or scripts
- **NEVER** put real credentials in kubectl commands, docker env flags, or shell variables
- **ALWAYS** use this skill when ANY of these come up: API key, token, secret, JWT, password, bearer token, webhook secret, client secret, access key, private key
- **ALWAYS** use clipboard-based store for new credentials -- never accept them as text input
- **ALWAYS** use `credential:` prefix in .env files for secret values
- When generating k8s secrets, deploy scripts, or docker commands that need credentials: reference the credential store, never hardcode values

## Storing Credentials

When user needs to store a token/key/secret:

1. Determine key name from context (e.g. "rdsec api key" -> `rdsec/API_KEY`)
2. Tell user to copy the secret to their clipboard
3. Run: `python ~/.claude/skills/credential-manager/store.py SERVICE/KEY`

Reads clipboard, validates content (rejects non-secrets), stores in keyring, clears clipboard, zeros memory.

## Retrieving Credentials (for scripts/deploys)

When a script or deploy needs a stored credential:

```bash
# Retrieve a credential value for use in a command (never echo it)
python -c "
import sys, os
sys.path.insert(0, os.path.expanduser('~/.claude/skills/credential-manager'))
from claude_cred import resolve
val = resolve('SERVICE/KEY')
if val: print(val)
" | <command-that-consumes-stdin>
```

For kubectl secrets:
```bash
# Create k8s secret from credential store (no plaintext)
python ~/.claude/skills/credential-manager/kubectl_secret.py \
  --name openclaw-secrets \
  --namespace my-project \
  --key rdsec/API_KEY:RDSEC_API_KEY \
  --key telegram/BOT_TOKEN:TELEGRAM_BOT_TOKEN \
  --key openclaw/GATEWAY_TOKEN:OPENCLAW_GATEWAY_TOKEN
```

## Commands

All credential operations use `cred_cli.py` directly -- NOT super_manager.py.

```bash
# Store (reads from clipboard — user copies secret first)
python ~/.claude/skills/credential-manager/store.py SERVICE/KEY
# or equivalently:
python ~/.claude/skills/credential-manager/cred_cli.py store SERVICE/KEY

# List stored (names only, with health status)
python ~/.claude/skills/credential-manager/cred_cli.py list

# List by service
python ~/.claude/skills/credential-manager/cred_cli.py list SERVICE

# Verify store health
python ~/.claude/skills/credential-manager/cred_cli.py verify

# Audit .env files for plaintext secrets
python ~/.claude/skills/credential-manager/cred_cli.py audit /path/.env

# Migrate .env to credential store
python ~/.claude/skills/credential-manager/cred_cli.py migrate /path/.env SERVICE

# Scan code for hardcoded secrets
python ~/.claude/skills/credential-manager/cred_cli.py securify DIRECTORY --dry-run

# First-time setup
python ~/.claude/skills/credential-manager/setup.py
```

## Integration

### .env files -- non-secrets stay plaintext, secrets use `credential:` prefix:
```
API_URL=https://example.com
API_TOKEN=credential:my-service/API_TOKEN
```

### Python (MCP servers/skills):
```python
import sys, os
sys.path.insert(0, os.path.expanduser('~/.claude/skills/credential-manager'))
from claude_cred import load_env
load_env()  # Resolves credential: prefixes from .env
```

### Node.js:
```javascript
const { loadEnvFile } = require(
  require('path').join(require('os').homedir(), '.claude/super-manager/credentials/claude-cred.js')
);
loadEnvFile(__dirname + '/.env');
```

## Storage

| Platform | Backend | Encryption |
|----------|---------|------------|
| Windows | Credential Manager (DPAPI) | AES-256 tied to user login |
| macOS | Keychain | AES-256 with secure enclave |

Service name: `claude-code`. Key format: `SERVICE/VARIABLE`.

## Files

```
~/.claude/skills/credential-manager/
├── store.py                  # Convenience entry point for storing credentials
├── cred_cli.py               # Full CLI (store, list, verify, audit, migrate, securify, protect)
├── claude_cred.py            # Python resolver (credential: prefix)
├── claude-cred.js            # Node.js resolver
├── credential-registry.json  # Key name index (no secrets)
├── setup.py                  # First-time setup + verification
└── archive/store_gui.py      # Archived GUI (replaced by clipboard workflow)
```

Requires `keyring` Python package (auto-installed by setup.py).

## TODO

- [x] Add `--clipboard` flag to `cred_cli.py store` (2026-03-10) -- reads from OS clipboard, stores, clears clipboard, zeros memory
- [x] Make clipboard the default store method, remove GUI dependency (2026-04-05)
