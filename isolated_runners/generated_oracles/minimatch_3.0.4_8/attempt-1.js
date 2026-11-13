const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  const out = {
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  };
  console.log('ORACLE_RESULT ' + JSON.stringify(out));
}

try {
  // Benign operation first: prove public API works normally.
  const benign = minimatch('abc', 'a*');
  if (typeof benign !== 'boolean') {
    throw new Error('Benign call did not return boolean');
  }

  operation_completed = true;

  // Malicious input attempting to trigger vulnerable behavior.
  try {
    const res = minimatch('a', '(');
    exploit_succeeded = false;
    evidence = 'malicious_call_returned:' + String(res);
  } catch (err) {
    const msg = (err && err.message) ? err.message : String(err);
    const name = (err && err.name) ? err.name : 'Error';
    // Throw here indicates vulnerable behavior for this regression check.
    exploit_succeeded = true;
    evidence = 'malicious_call_threw:' + name + ':' + msg;
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + ((err && err.message) ? err.message : String(err));
}

finish();