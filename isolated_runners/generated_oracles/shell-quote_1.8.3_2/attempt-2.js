'use strict';

const shellQuote = require('shell-quote');
const os = require('node:os');
const path = require('node:path');

function main() {
  const marker = 'SQ_MARKER_' + process.pid + '_' + Date.now();

  let result = { operation_completed: false, exploit_succeeded: false, evidence: '' };

  try {
    // Benign operation: ensure quote() works normally on plain strings/args.
    const benignInput = ['echo', 'hello ' + marker, '&&', 'ls'];
    const benignOutput = shellQuote.quote(benignInput);

    if (typeof benignOutput !== 'string' || benignOutput.length === 0 || !benignOutput.includes(marker)) {
      result.evidence = 'Benign quote() call did not produce expected output: ' + JSON.stringify(benignOutput);
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    // A second benign sanity check: quoting an object with a normal "op" field
    // should wrap/escape as expected and not throw.
    const benignOpInput = [{ op: '&&' }, 'echo', marker];
    const benignOpOutput = shellQuote.quote(benignOpInput);
    if (typeof benignOpOutput !== 'string' || benignOpOutput.length === 0) {
      result.evidence = 'Benign op-object quote() call failed: ' + JSON.stringify(benignOpOutput);
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    // Benign operation succeeded.
    result.operation_completed = true;

    // Malicious input: an object whose .op value contains a newline.
    // In the vulnerable version, quote() does not escape newlines inside
    // the .op field, so the resulting string would contain a literal
    // newline character, which could allow injection of extra shell
    // commands when the output is later executed by a shell.
    const maliciousOp = 'echo pwned_' + marker + '\n' + 'echo second_' + marker;
    const maliciousInput = [{ op: maliciousOp }];

    let maliciousOutput;
    try {
      maliciousOutput = shellQuote.quote(maliciousInput);
    } catch (e) {
      // An exception from the malicious call counts as blocked, since setup
      // and benign operations already succeeded.
      result.exploit_succeeded = false;
      result.evidence = 'quote() threw on malicious .op input (treated as blocked): ' + String(e && e.message ? e.message : e);
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    if (typeof maliciousOutput !== 'string') {
      result.exploit_succeeded = false;
      result.evidence = 'quote() with malicious .op did not return a string; treated as safe: ' + JSON.stringify(maliciousOutput);
      console.log('ORACLE_RESULT ' + JSON.stringify(result));
      return;
    }

    const containsRawNewline = maliciousOutput.indexOf('\n') !== -1;

    if (containsRawNewline) {
      // Vulnerable: the newline character passed through unescaped, which
      // would allow injection of a second shell command when this string
      // is later passed to a shell for execution.
      result.exploit_succeeded = true;
      result.evidence = 'quote() output contains an unescaped literal newline from .op value: ' + JSON.stringify(maliciousOutput);
    } else {
      // Patched: newline should be escaped (e.g. as $\'\\n\' or similar),
      // so no raw newline character appears in the output.
      result.exploit_succeeded = false;
      result.evidence = 'quote() output did not contain a raw newline; .op value was properly escaped: ' + JSON.stringify(maliciousOutput);
    }

    console.log('ORACLE_RESULT ' + JSON.stringify(result));
  } catch (e) {
    // Any unexpected exception (setup, module resolution, fixture, or
    // during the benign operation) must be reported as operation_completed=false.
    const out = {
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'Unexpected exception: ' + String(e && e.stack ? e.stack : e)
    };
    console.log('ORACLE_RESULT ' + JSON.stringify(out));
  }
}

main();
