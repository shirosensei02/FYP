const _ = require('lodash');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  // Ensure clean baseline for this process
  try { delete Object.prototype.__oraclePolluted; } catch (_) {}

  // Benign operation first
  const benignTarget = { a: { x: 1 } };
  const benignResult = _.defaultsDeep(benignTarget, { a: { y: 2 } });
  if (!benignResult || !benignResult.a || benignResult.a.y !== 2 || benignResult.a.x !== 1) {
    throw new Error('Benign defaultsDeep behavior did not match expected merge semantics');
  }

  operation_completed = true;

  // Malicious input
  const payload = JSON.parse('{"constructor":{"prototype":{"__oraclePolluted":"yes"}}}');

  try {
    _.defaultsDeep({}, payload);
  } catch (e) {
    // If patched package throws during malicious call, that's acceptable blocking
    exploit_succeeded = false;
    evidence = 'malicious_call_threw_after_benign: ' + (e && e.message ? e.message : String(e));
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
    process.exit(0);
  }

  const probe = {};
  if (probe.__oraclePolluted === 'yes') {
    exploit_succeeded = true;
    evidence = 'Object.prototype polluted via constructor.prototype path; fresh object inherited __oraclePolluted=yes';
  } else {
    exploit_succeeded = false;
    evidence = 'No prototype pollution observed on fresh object after malicious defaultsDeep call';
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failed: ' + (e && e.message ? e.message : String(e));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));