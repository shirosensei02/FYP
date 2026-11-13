'use strict';

const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

function finish(result) {
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

let shellQuote;
try {
  shellQuote = require('shell-quote');
} catch (e) {
  finish({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'module resolution failed: ' + String(e && e.message || e)
  });
  process.exit(0);
}

const marker = 'MARKER_' + process.pid + '_' + Date.now();

let operationCompleted = false;

try {
  // Benign operation: quote a plain array of simple strings.
  const benignResult = shellQuote.quote(['echo', 'hello_' + marker]);

  if (typeof benignResult !== 'string' || benignResult.length === 0) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign quote() call did not return a non-empty string; got: ' + JSON.stringify(benignResult)
    });
    process.exit(0);
  }

  if (benignResult.indexOf('hello_' + marker) === -1) {
    finish({
      operation_completed: false,
      exploit_succeeded: false,
      evidence: 'benign quote() call did not contain expected marker text; got: ' + JSON.stringify(benignResult)
    });
    process.exit(0);
  }

  operationCompleted = true;

  // Malicious operation: object with .op value containing embedded newlines.
  const injectedFragment = 'INJECTED_' + marker;
  const maliciousOpValue = 'before_' + marker + '\n' + injectedFragment + '\necho after_' + marker;

  let maliciousResult;
  try {
    maliciousResult = shellQuote.quote(['echo', { op: maliciousOpValue }]);
  } catch (innerErr) {
    // A thrown exception from the malicious call, after benign success,
    // counts as the vulnerability being blocked.
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious quote() call threw after benign success (blocked): ' + String(innerErr && innerErr.message || innerErr)
    });
    process.exit(0);
  }

  if (typeof maliciousResult !== 'string') {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'malicious quote() call did not return a string; type: ' + typeof maliciousResult
    });
    process.exit(0);
  }

  // Check whether a raw, unescaped newline made it into the output,
  // with the injected fragment appearing on its own line (i.e. not
  // escaped as \\n literal text, and not otherwise neutralized).
  const hasRawNewline = maliciousResult.indexOf('\n') !== -1;
  const containsInjectedFragment = maliciousResult.indexOf(injectedFragment) !== -1;

  // To confirm genuine injection (not just the fragment appearing as
  // escaped/quoted literal text), check that the fragment is preceded
  // immediately by a raw newline character rather than an escaped
  // representation such as '\\n' (backslash followed by n).
  let genuineLineSplit = false;
  if (hasRawNewline && containsInjectedFragment) {
    const idx = maliciousResult.indexOf(injectedFragment);
    if (idx > 0 && maliciousResult[idx - 1] === '\n') {
      genuineLineSplit = true;
    }
  }

  if (genuineLineSplit) {
    finish({
      operation_completed: true,
      exploit_succeeded: true,
      evidence: 'quote() output contains unescaped raw newline splitting attacker content onto its own line: ' + JSON.stringify(maliciousResult)
    });
  } else {
    finish({
      operation_completed: true,
      exploit_succeeded: false,
      evidence: 'quote() output did not contain an unescaped raw newline splitting injected content; result: ' + JSON.stringify(maliciousResult)
    });
  }
} catch (outerErr) {
  finish({
    operation_completed: operationCompleted,
    exploit_succeeded: false,
    evidence: 'unexpected exception during oracle execution: ' + String(outerErr && outerErr.message || outerErr)
  });
}
