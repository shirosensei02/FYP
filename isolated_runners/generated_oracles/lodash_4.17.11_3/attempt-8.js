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

const marker = 'oracle_merge_' + process.pid + '_' + Date.now();
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
  // _.merge deep-merges plain objects; this is the normal, documented use case
  // for combining nested configuration-like structures.
  const benignResult = _.merge({ a: { b: 1 } }, { a: { c: 2 }, d: 3 });

  const benignOk =
    benignResult &&
    typeof benignResult === 'object' &&
    benignResult.a &&
    benignResult.a.b === 1 &&
    benignResult.a.c === 2 &&
    benignResult.d === 3;

  if (!benignOk) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign _.merge did not produce expected shape: ' + JSON.stringify(benignResult) });
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
  // CVE-2019-10744-style prototype pollution via _.merge when the source
  // object (e.g. decoded from untrusted JSON) contains a '__proto__' key.
  // In vulnerable lodash this reaches baseMergeDeep/assignMergeValue and
  // assigns onto Object.prototype itself.
  const maliciousSource = JSON.parse('{"__proto__":{"polluted":"yes"}}');

  let threwDuringMalicious = false;
  let maliciousErrMsg = '';
  try {
    _.merge({}, maliciousSource);
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
    evidence = 'malicious _.merge threw: ' + maliciousErrMsg + '; Object.prototype.hasOwnProperty(polluted)=' + String(ownCheck) + '; fresh {}.polluted=' + String(freshObj.polluted);
  } else {
    evidence = exploit_succeeded
      ? 'Object.prototype.polluted === "yes" after _.merge({}, {__proto__:{polluted:"yes"}}); fresh {}.polluted=' + String(freshObj.polluted)
      : 'No pollution observed on Object.prototype after malicious _.merge; fresh {}.polluted=' + String(freshObj.polluted) + '; ownCheck=' + String(ownCheck);
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
