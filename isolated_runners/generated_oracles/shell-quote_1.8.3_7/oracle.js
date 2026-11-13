'use strict';

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  const shellQuote = require('shell-quote');
  if (!shellQuote || typeof shellQuote.quote !== 'function') {
    throw new Error('shell-quote.quote not available');
  }

  // Benign: ordinary string arguments should quote safely and not include newlines.
  const benignInput = ['echo', 'ok'];
  const benignOut = shellQuote.quote(benignInput);
  if (typeof benignOut !== 'string' || benignOut.length === 0) {
    throw new Error('benign output invalid');
  }
  if (benignOut.indexOf('\n') !== -1 || benignOut.indexOf('\r') !== -1) {
    throw new Error('benign output unexpectedly contains newline chars');
  }

  operation_completed = true;

  // Malicious: operator token with embedded newline should be escaped/blocked.
  const maliciousInput = [{ op: '&&\nINJECTED' }, 'echo', 'safe'];
  const maliciousOut = shellQuote.quote(maliciousInput);

  if (typeof maliciousOut !== 'string') {
    exploit_succeeded = false;
    evidence = 'malicious output not string';
  } else {
    const hasRawNewline = maliciousOut.indexOf('\n') !== -1 || maliciousOut.indexOf('\r') !== -1;
    exploit_succeeded = hasRawNewline;
    evidence = 'benign=' + JSON.stringify(benignOut) + '; malicious=' + JSON.stringify(maliciousOut) + '; raw_newline=' + String(hasRawNewline);
  }
} catch (err) {
  if (!operation_completed) {
    operation_completed = false;
    exploit_succeeded = false;
    evidence = 'setup_or_benign_error:' + (err && err.message ? err.message : String(err));
  } else {
    exploit_succeeded = false;
    evidence = 'malicious_blocked_by_exception:' + (err && err.message ? err.message : String(err));
  }
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed: operation_completed,
  exploit_succeeded: exploit_succeeded,
  evidence: evidence
}));
