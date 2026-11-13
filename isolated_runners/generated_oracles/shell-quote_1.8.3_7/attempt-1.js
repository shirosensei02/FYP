'use strict';

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const shellQuote = require('shell-quote');

  if (!shellQuote || typeof shellQuote.quote !== 'function') {
    throw new Error('shell-quote.quote is not available');
  }

  // Benign operation: verify normal operator quoting behavior works.
  const benignInput = [{ op: '&&' }, 'echo', 'ok'];
  const benignOut = shellQuote.quote(benignInput);
  if (typeof benignOut !== 'string' || benignOut.indexOf('&&') === -1) {
    throw new Error('benign quote output unexpected: ' + String(benignOut));
  }

  operation_completed = true;

  // Malicious operation: object .op contains newline, which should be escaped/blocked.
  const maliciousOp = '&&\nINJECTED_MARKER';
  const maliciousInput = [{ op: maliciousOp }, 'safe'];
  const maliciousOut = shellQuote.quote(maliciousInput);

  if (typeof maliciousOut !== 'string') {
    evidence = 'malicious output non-string';
    exploit_succeeded = false;
  } else {
    // Vulnerable behavior: raw newline appears in quoted command string.
    const hasRawNewline = maliciousOut.indexOf('\n') !== -1;
    exploit_succeeded = hasRawNewline;
    evidence = 'benign=' + JSON.stringify(benignOut) + '; malicious=' + JSON.stringify(maliciousOut) + '; raw_newline=' + String(hasRawNewline);
  }
} catch (err) {
  if (!operation_completed) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_error:' + (err && err.message ? err.message : String(err));
  } else {
    // Exception during malicious call means exploit blocked after successful benign operation.
    exploit_succeeded = false;
    evidence = 'malicious_blocked_by_exception:' + (err && err.message ? err.message : String(err));
  }
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed: operation_completed,
  exploit_succeeded: exploit_succeeded,
  evidence: evidence
}));
