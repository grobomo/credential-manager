#!/usr/bin/env node
/**
 * Credential Manager Uninstall
 *
 * Restores files from the most recent backup and archives instruction files.
 * Uses shared setup-utils.js for backup discovery and restore.
 *
 * Usage:
 *   node uninstall.js
 *
 * What it does:
 *   1. Finds the latest credential-manager backup
 *   2. Restores backed-up files (settings.json, etc.)
 *   3. Archives the credential-management instruction file (never deletes)
 *   4. Prints summary of changes
 *
 * What it does NOT do:
 *   - Does not remove credential-registry.json (your stored key names)
 *   - Does not remove Python files (cred_cli.py, setup.py, etc.)
 *   - Does not remove credentials from OS credential store
 */

var fs = require('fs');
var path = require('path');
var os = require('os');

var HOME = os.homedir();
var CLAUDE_DIR = path.join(HOME, '.claude');

// Shared setup utilities
var utils = require(path.join(CLAUDE_DIR, 'super-manager', 'shared', 'setup-utils.js'));

var MANAGER_NAME = 'credential-manager';

// ================================================================
// Uninstall
// ================================================================

function uninstall() {
  console.log('');
  console.log('[' + MANAGER_NAME + ':uninstall] ============================================');
  console.log('[' + MANAGER_NAME + ':uninstall] Starting uninstall...');
  console.log('[' + MANAGER_NAME + ':uninstall] ============================================');
  console.log('');

  var errors = [];

  // ------------------------------------------------------------------
  // Step 1: Find latest backup
  // ------------------------------------------------------------------
  console.log('[1/3] Finding latest backup...');
  var backupDir = utils.findLatestBackup(MANAGER_NAME);

  if (!backupDir) {
    console.log('  No backup found for ' + MANAGER_NAME);
    console.log('  Continuing with instruction removal only...');
  } else {
    console.log('  Found: ' + backupDir);
  }

  // ------------------------------------------------------------------
  // Step 2: Restore from backup (if available)
  // ------------------------------------------------------------------
  if (backupDir) {
    console.log('[2/3] Restoring from backup...');
    var restoreResult = utils.restore(backupDir);

    if (restoreResult.restored.length > 0) {
      console.log('  Restored:');
      for (var i = 0; i < restoreResult.restored.length; i++) {
        console.log('    ' + restoreResult.restored[i]);
      }
    }

    if (restoreResult.removed.length > 0) {
      console.log('  Removed (archived):');
      for (var j = 0; j < restoreResult.removed.length; j++) {
        console.log('    ' + restoreResult.removed[j]);
      }
    }

    if (restoreResult.errors.length > 0) {
      console.log('  Errors:');
      for (var k = 0; k < restoreResult.errors.length; k++) {
        console.log('    [!] ' + restoreResult.errors[k]);
        errors.push(restoreResult.errors[k]);
      }
    }
  } else {
    console.log('[2/3] Skipping restore (no backup)...');
  }

  // ------------------------------------------------------------------
  // Step 3: Archive instruction file
  // ------------------------------------------------------------------
  console.log('[3/3] Archiving instruction file...');
  var archivePath = utils.removeInstruction('credential-management', 'UserPromptSubmit');

  if (archivePath) {
    console.log('  Archived: credential-management.md');
    console.log('    -> ' + archivePath);
  } else {
    console.log('  Instruction file not found (already removed or never installed)');
  }

  // ------------------------------------------------------------------
  // Summary
  // ------------------------------------------------------------------
  console.log('');
  console.log('[' + MANAGER_NAME + ':uninstall] ============================================');
  console.log('[' + MANAGER_NAME + ':uninstall] Uninstall Complete');
  console.log('[' + MANAGER_NAME + ':uninstall] ============================================');

  if (errors.length > 0) {
    console.log('[' + MANAGER_NAME + ':uninstall] Errors: ' + errors.length);
    for (var e = 0; e < errors.length; e++) {
      console.log('[' + MANAGER_NAME + ':uninstall]   [!] ' + errors[e]);
    }
  } else {
    console.log('[' + MANAGER_NAME + ':uninstall] All clean.');
  }

  console.log('[' + MANAGER_NAME + ':uninstall] Preserved:');
  console.log('[' + MANAGER_NAME + ':uninstall]   - credential-registry.json (your key names)');
  console.log('[' + MANAGER_NAME + ':uninstall]   - Python files (cred_cli.py, setup.py, etc.)');
  console.log('[' + MANAGER_NAME + ':uninstall]   - OS credential store entries (use cred_cli.py to manage)');
  console.log('[' + MANAGER_NAME + ':uninstall] Reinstall:');
  console.log('[' + MANAGER_NAME + ':uninstall]   node ~/.claude/skills/' + MANAGER_NAME + '/setup.js');
  console.log('[' + MANAGER_NAME + ':uninstall] ============================================');
  console.log('');

  return errors.length === 0;
}

// ================================================================
// Main
// ================================================================

module.exports = { uninstall: uninstall };

if (require.main === module) {
  var ok = uninstall();
  process.exit(ok ? 0 : 1);
}
