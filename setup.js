#!/usr/bin/env node
/**
 * Credential Manager Setup (Node.js)
 *
 * Installs credential-management instruction file, ensures registry exists,
 * and verifies environment. Uses shared setup-utils.js for backup/restore.
 *
 * Usage:
 *   node setup.js          # Install
 *   node setup.js --check  # Verify only (no changes)
 *
 * Note: The Python setup.py handles keyring verification and .env scanning.
 *       This Node.js setup.js follows the shared setup-utils pattern for
 *       instruction/backup management.
 */

var fs = require('fs');
var path = require('path');
var os = require('os');

var HOME = os.homedir();
var CLAUDE_DIR = path.join(HOME, '.claude');
var SKILL_DIR = path.join(CLAUDE_DIR, 'skills', 'credential-manager');
var REGISTRY_FILE = path.join(SKILL_DIR, 'credential-registry.json');

// Shared setup utilities
var utils = require(path.join(CLAUDE_DIR, 'super-manager', 'shared', 'setup-utils.js'));

var MANAGER_NAME = 'credential-manager';

// ================================================================
// Instruction content (embedded from credential-management.md)
// ================================================================

var INSTRUCTION_CONTENT = [
  '---',
  'id: credential-management',
  'keywords: [credential, api, key, token, secret, env, plaintext, password, store, expired, rotate, securify]',
  'description: Credential management rules for secrets and API tokens',
  'name: Credential management rules',
  'enabled: true',
  'priority: 10',
  '---',
  '',
  '# Credential Management Instructions',
  '',
  '- **NEVER read .env files** that may contain API tokens or secrets',
  '- **NEVER output credential values** in chat, logs, or memory files',
  '- Use `python ~/.claude/skills/credential-manager/cred_cli.py list` to see stored credentials (names only)',
  '- Use `python ~/.claude/skills/credential-manager/cred_cli.py verify` to check health',
  '- If a user needs to store a new token, tell them to run the store command themselves:',
  '  `python ~/.claude/skills/credential-manager/store_gui.py SERVICE/KEY`',
  '- If plaintext tokens found in .env: `python ~/.claude/skills/credential-manager/cred_cli.py migrate <path> <service>`',
  '- To scan code for hardcoded secrets: `python ~/.claude/skills/credential-manager/securify.py <dir> --dry-run`'
].join('\n');

// ================================================================
// Check mode (--check flag)
// ================================================================

function check() {
  var issues = [];
  var ok = [];

  // 1. Instruction file
  var instrPath = path.join(utils.INSTRUCTIONS_DIR, 'UserPromptSubmit', 'credential-management.md');
  if (fs.existsSync(instrPath)) {
    ok.push('Instruction file exists: ' + instrPath);
  } else {
    issues.push('Missing instruction file: ' + instrPath);
  }

  // 2. Credential registry
  if (fs.existsSync(REGISTRY_FILE)) {
    try {
      var data = JSON.parse(fs.readFileSync(REGISTRY_FILE, 'utf8'));
      var count = (data.credentials || []).length;
      ok.push('Registry exists: ' + count + ' credentials');
    } catch (e) {
      issues.push('Registry is invalid JSON: ' + REGISTRY_FILE);
    }
  } else {
    issues.push('Missing credential registry: ' + REGISTRY_FILE);
  }

  // 3. Python keyring
  ok.push('Python keyring: run "python -c \\"import keyring\\"" to verify');

  // 4. Instruction-manager dependency
  var imDep = utils.checkDependency('instruction-manager');
  if (imDep.installed) {
    ok.push('instruction-manager: installed');
  } else {
    issues.push('instruction-manager: not installed (direct-write fallback used)');
  }

  // Print
  console.log('');
  console.log('[' + MANAGER_NAME + ':check] ================================');
  if (ok.length > 0) {
    console.log('[' + MANAGER_NAME + ':check] OK:');
    for (var i = 0; i < ok.length; i++) {
      console.log('[' + MANAGER_NAME + ':check]   ' + ok[i]);
    }
  }
  if (issues.length > 0) {
    console.log('[' + MANAGER_NAME + ':check] Issues:');
    for (var j = 0; j < issues.length; j++) {
      console.log('[' + MANAGER_NAME + ':check]   [!] ' + issues[j]);
    }
  }
  console.log('[' + MANAGER_NAME + ':check] ================================');
  console.log('');

  return issues.length === 0;
}

// ================================================================
// Setup
// ================================================================

function setup() {
  console.log('[' + MANAGER_NAME + ':setup] Starting installation...');
  console.log('');

  var warnings = [];
  var instructionResults = [];

  // ------------------------------------------------------------------
  // Step 1: Check dependencies
  // ------------------------------------------------------------------
  console.log('[1/4] Checking dependencies...');
  var imDep = utils.checkDependency('instruction-manager');
  if (imDep.installed) {
    console.log('  instruction-manager: installed');
  } else {
    console.log('  instruction-manager: not installed (will use direct-write fallback)');
    warnings.push('Install instruction-manager for better keyword matching');
  }

  // ------------------------------------------------------------------
  // Step 2: Backup existing files
  // ------------------------------------------------------------------
  console.log('[2/4] Creating backup...');
  var filesToBackup = [utils.SETTINGS_JSON];

  // Back up existing instruction file if it exists
  var existingInstr = path.join(utils.INSTRUCTIONS_DIR, 'UserPromptSubmit', 'credential-management.md');
  if (fs.existsSync(existingInstr)) {
    filesToBackup.push(existingInstr);
  }

  // Back up existing registry if it exists
  if (fs.existsSync(REGISTRY_FILE)) {
    filesToBackup.push(REGISTRY_FILE);
  }

  var backupResult = utils.backup(MANAGER_NAME, filesToBackup);
  console.log('  Backup: ' + backupResult.backupDir);

  // ------------------------------------------------------------------
  // Step 3: Install instruction file
  // ------------------------------------------------------------------
  console.log('[3/4] Installing instruction file...');
  var instrResult = utils.installInstruction({
    id: 'credential-management',
    content: INSTRUCTION_CONTENT,
    event: 'UserPromptSubmit'
  });
  console.log('  Method: ' + instrResult.method);
  console.log('  Path: ' + instrResult.path);
  instructionResults.push(instrResult);

  // Track created file if it was newly written
  if (instrResult.method !== 'skipped') {
    utils.trackCreatedFile(backupResult.backupDir, instrResult.path);
  }

  // ------------------------------------------------------------------
  // Step 4: Ensure credential-registry.json exists
  // ------------------------------------------------------------------
  console.log('[4/4] Ensuring credential registry...');
  var registryCreated = false;
  if (!fs.existsSync(REGISTRY_FILE)) {
    fs.mkdirSync(path.dirname(REGISTRY_FILE), { recursive: true });
    fs.writeFileSync(REGISTRY_FILE, JSON.stringify({ credentials: [] }, null, 2), 'utf8');
    utils.trackCreatedFile(backupResult.backupDir, REGISTRY_FILE);
    console.log('  Created empty registry: ' + REGISTRY_FILE);
    registryCreated = true;
  } else {
    try {
      var data = JSON.parse(fs.readFileSync(REGISTRY_FILE, 'utf8'));
      var count = (data.credentials || []).length;
      console.log('  Registry exists: ' + count + ' credentials registered');
    } catch (e) {
      console.log('  Registry exists but invalid JSON - recreating...');
      fs.writeFileSync(REGISTRY_FILE, JSON.stringify({ credentials: [] }, null, 2), 'utf8');
      registryCreated = true;
    }
  }

  // ------------------------------------------------------------------
  // Python keyring note
  // ------------------------------------------------------------------
  console.log('');
  console.log('[' + MANAGER_NAME + ':setup] NOTE: Python keyring module is required.');
  console.log('[' + MANAGER_NAME + ':setup]   Verify: python -c "import keyring"');
  console.log('[' + MANAGER_NAME + ':setup]   Install: pip install keyring');
  console.log('[' + MANAGER_NAME + ':setup]   Full Python setup: python "' + path.join(SKILL_DIR, 'setup.py').replace(/\\/g, '/') + '"');

  // ------------------------------------------------------------------
  // Print summary
  // ------------------------------------------------------------------
  utils.printSummary({
    manager: MANAGER_NAME,
    backup: backupResult,
    instructions: instructionResults,
    hooks: [],
    warnings: warnings
  });
}

// ================================================================
// Main
// ================================================================

function main() {
  var args = process.argv.slice(2);

  if (args.indexOf('--check') !== -1) {
    var ok = check();
    process.exit(ok ? 0 : 1);
    return;
  }

  setup();
}

// ================================================================
// Exports (for programmatic use by other managers)
// ================================================================

module.exports = {
  setup: setup,
  check: check
};

if (require.main === module) main();
