const minimatch = require('minimatch');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const benignOut = minimatch.braceExpand('x{y,z}w');
  if (!Array.isArray(benignOut) || benignOut.length !== 2 || benignOut[0] !== 'xyw' || benignOut[1] !== 'xzw') {
    throw new Error('benign braceExpand validation failed');
  }

  operation_completed = true;

  // CVE targets minimatch.braceExpand's brace-detection regex in vulnerable versions.
  // Use a bounded crafted payload that typically causes much slower behavior pre-fix.
  const n = 30000;
  const malicious = '{' + '\\'.repeat(n);

  let elapsed;
  try {
    const t0 = Date.now();
    minimatch.braceExpand(malicious);
    elapsed = Date.now() - t0;
  } catch (e) {
    // Throwing on malicious input after successful benign path counts as blocked.
    exploit_succeeded = false;
    evidence = 'malicious_threw=' + (e && e.name ? e.name : 'Error') + ';input_backslashes=' + n;
    console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
    process.exit(0);
  }

  // Absolute threshold plus relative-to-benign factor to distinguish vulnerable slowness.
  const benignSample = '{a,b}';
  const b0 = Date.now();
  for (let i = 0; i < 2000; i++) minimatch.braceExpand(benignSample);
  const benignLoopMs = Date.now() - b0;
  const ratio = benignLoopMs > 0 ? (elapsed / benignLoopMs) : elapsed;

  exploit_succeeded = elapsed > 250 && ratio > 8;
  evidence = 'malicious_elapsed_ms=' + elapsed + ';benign_loop_ms=' + benignLoopMs + ';ratio=' + ratio.toFixed(2) + ';input_backslashes=' + n;
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failed=' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({ operation_completed, exploit_succeeded, evidence }));