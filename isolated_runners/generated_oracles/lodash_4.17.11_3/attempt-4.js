'use strict';
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

let _;
try {
  _ = require('lodash');
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
  process.exit(0);
}

const marker = 'oracle_' + process.pid + '_' + Date.now();
const tmpFile = path.join(os.tmpdir(), marker + '.json');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function cleanupPollution() {
  try {
    if (Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted')) {
      delete Object.prototype.polluted;
    }
  } catch (e) { /* ignore */ }
}

// Defensive cleanup in case of leftover state from a previous run in this process.
cleanupPollution();

try {
  // Benign operation: ensure merge works correctly on ordinary nested input.
  const benignTarget = { a: 1, nested: { x: 1 } };
  const benignSource = { b: 2, nested: { y: 2 } };
  const benignResult = _.merge(benignTarget, benignSource);

  const benignOk =
    benignResult &&
    benignResult.a === 1 &&
    benignResult.b === 2 &&
    benignResult.nested &&
    benignResult.nested.x === 1 &&
    benignResult.nested.y === 2;

  if (!benignOk) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign merge did not produce expected shape' });
    process.exit(0);
  }

  // Write a tiny fixture file to /tmp to demonstrate tmp usage and confirm filesystem access works.
  fs.writeFileSync(tmpFile, JSON.stringify({ marker, benignResult }));
  const readBack = JSON.parse(fs.readFileSync(tmpFile, 'utf8'));
  if (!readBack || readBack.marker !== marker) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'tmp fixture roundtrip failed' });
    process.exit(0);
  }
  try { fs.unlinkSync(tmpFile); } catch (e) { /* ignore cleanup errors */ }

  operation_completed = true;

  // Malicious input: classic constructor.prototype pollution payload via JSON.parse,
  // the historic lodash <4.17.11 prototype pollution exploitation vector (CVE-2018-16487).
  const maliciousPayloadStr = '{"constructor":{"prototype":{"polluted":"yes"}}}';
  let maliciousSource;
  try {
    maliciousSource = JSON.parse(maliciousPayloadStr);
  } catch (parseErr) {
    finish({ operation_completed: true, exploit_succeeded: false, evidence: 'malicious payload failed to parse as JSON (unexpected): ' + String(parseErr && parseErr.message) });
    process.exit(0);
  }

  try {
    _.merge({}, maliciousSource);
  } catch (mergeErr) {
    // An exception during the malicious merge, after benign success, counts as blocked.
    const freshAfterError = {};
    const ownAfterError = Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted');
    const pollutedAfterError = ownAfterError || freshAfterError.polluted === 'yes';
    evidence = 'malicious merge threw: ' + String(mergeErr && mergeErr.message) + '; freshObj.polluted=' + String(freshAfterError.polluted);
    cleanupPollution();
    finish({ operation_completed: true, exploit_succeeded: pollutedAfterError, evidence });
    process.exit(0);
  }

  // Check pollution on a completely new, unrelated plain object literal.
  const freshObj = {};
  const polluted = freshObj.polluted === 'yes';
  const ownCheck = Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted');

  exploit_succeeded = !!(polluted && ownCheck);

  evidence = exploit_succeeded
    ? 'Object.prototype.polluted === "yes" after merge via constructor.prototype key; fresh {} inherited polluted=' + String(freshObj.polluted)
    : 'No pollution observed on Object.prototype after malicious merge; fresh {}.polluted=' + String(freshObj.polluted);

  // Cleanup: remove pollution if present so repeated runs in same process are not confused.
  cleanupPollution();

  finish({ operation_completed, exploit_succeeded, evidence });
} catch (unexpectedErr) {
  if (operation_completed) {
    cleanupPollution();
    finish({ operation_completed: true, exploit_succeeded: false, evidence: 'unexpected exception after benign success, treated as blocked: ' + String(unexpectedErr && unexpectedErr.message) });
  } else {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'unexpected exception before benign success: ' + String(unexpectedErr && unexpectedErr.message) });
  }
}
