const _ = require('lodash');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function done() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  }));
}

try {
  // Ensure clean state for this process
  try { delete Object.prototype.__oracle_pp_flag__; } catch (_) {}

  // Benign operation first: normal set should work
  const benignObj = {};
  _.set(benignObj, 'safe.path', 123);
  if (!benignObj.safe || benignObj.safe.path !== 123) {
    throw new Error('benign _.set failed');
  }

  operation_completed = true;

  // Malicious input: classic prototype-pollution path
  try {
    _.set({}, '__proto__.__oracle_pp_flag__', 'PWNED');
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious _.set threw: ' + (e && e.message ? e.message : String(e));
    done();
    return;
  }

  const polluted = ({}).__oracle_pp_flag__ === 'PWNED';
  exploit_succeeded = polluted;
  evidence = polluted
    ? 'prototype polluted via _.set("__proto__.__oracle_pp_flag__")'
    : 'no prototype pollution observed';

  // Best-effort cleanup
  try { delete Object.prototype.__oracle_pp_flag__; } catch (_) {}
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (e && e.message ? e.message : String(e));
}

done();