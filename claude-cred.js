/**
 * claude-cred.js - Credential resolution for Claude Code Node.js MCP servers.
 *
 * Usage:
 *   const path = require('path');
 *   const os = require('os');
 *   const { resolve, loadEnvFile } = require(
 *     path.join(os.homedir(), '.claude/super-manager/credentials/claude-cred.js')
 *   );
 *   loadEnvFile(__dirname + '/.env');
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const SERVICE = 'claude-code';

/**
 * Resolve a credential from the OS credential store.
 * @param {string} key - Credential key in 'service/VARIABLE' format
 * @returns {string} The credential value
 * @throws {Error} If credential not found
 */
function resolve(key) {
    try {
        // Shell out to Python keyring - only happens at startup, not per-request
        const cmd = `python -c "import keyring; v=keyring.get_password('${SERVICE}','${key}'); print(v if v else '')"`;
        const result = execSync(cmd, { encoding: 'utf-8', timeout: 10000 }).trim();
        if (!result || result === 'None') {
            throw new Error('Credential not found: ' + key);
        }
        return result;
    } catch (e) {
        throw new Error('Failed to resolve credential ' + key + ': ' + e.message);
    }
}

/**
 * If value starts with 'credential:', resolve from OS store. Otherwise return as-is.
 */
function resolveValue(value) {
    if (typeof value === 'string' && value.startsWith('credential:')) {
        return resolve(value.slice('credential:'.length));
    }
    return value;
}

/**
 * Load .env file and resolve credential: prefixes into process.env.
 * @param {string} envPath - Path to .env file
 * @returns {Object} Resolved key-value pairs
 */
function loadEnvFile(envPath) {
    if (!fs.existsSync(envPath)) return {};
    const result = {};
    const content = fs.readFileSync(envPath, 'utf-8');
    for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue;
        const eqIdx = trimmed.indexOf('=');
        const key = trimmed.slice(0, eqIdx).trim();
        let value = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
        value = resolveValue(value);
        result[key] = value;
        process.env[key] = value;
    }
    return result;
}

module.exports = { resolve, resolveValue, loadEnvFile };
