'use strict';
const path = require('node:path');
const os = require('node:os');

function main() {
  let _;
  try {
    _ = require('lodash');
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Module resolution failed: ' + String(e && e.message)
    }));
    return;
  }

  const marker = 'oracle_' + process.pid + '_' + Date.now();

  // Benign operation: prove merge works normally on a plain object.
  let benignOk = false;
  try {
    const target = { a: 1 };
    const source = { b: 2, nested: { c: 3 } };
    const merged = _.merge(target, source);
    benignOk = merged.a === 1 && merged.b === 2 && merged.nested && merged.nested.c === 3;
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign merge operation failed: ' + String(e && e.message)
    }));
    return;
  }

  if (!benignOk) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign merge operation produced unexpected result'
    }));
    return;
  }

  // Malicious operation: attempt prototype pollution via __proto__ in merge source,
  // built from JSON.parse to mirror a typical untrusted-input attack vector.
  const operation_completed = true; // benign op succeeded, so setup is proven good
  let exploit_succeeded = false;
  let evidence = '';

  try {
    // Ensure clean slate on Object.prototype for our marker key.
    delete Object.prototype[marker];

    const maliciousPayload = JSON.parse(
      '{"__proto__":{"' + marker + '":"polluted"}}'
    );

    const victim = {};
    _.merge(victim, maliciousPayload);

    const pollutedValue = ({}).hasOwnProperty.call(Object.prototype, marker)
      ? Object.prototype[marker]
      : undefined;

    if (pollutedValue === 'polluted') {
      exploit_succeeded = true;
      evidence = 'Object.prototype.' + marker + ' was set to "polluted" via lodash.merge with __proto__ payload';
    } else {
      exploit_succeeded = false;
      evidence = 'Object.prototype.' + marker + ' was not polluted after merge call; value=' + String(pollutedValue);
    }
  } catch (e) {
    // An exception during the malicious call, after benign success, counts as blocked.
    exploit_succeeded = false;
    evidence = 'Malicious merge call threw (treated as blocked): ' + String(e && e.message);
  } finally {
    // Clean up any pollution we may have introduced.
    try {
      delete Object.prototype[marker];
    } catch (cleanupErr) {
      // ignore cleanup errors
    }
  }

  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed,
    exploit_succeeded,
    evidence
  }));
}

main();
