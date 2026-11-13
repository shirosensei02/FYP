'use strict';
const shellQuote = require('shell-quote');
const MARKER = 'ORACLE_MARKER_' + process.pid + '_' + Date.now();

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  const out = {
    operation_completed: operation_completed,
    exploit_succeeded: exploit_succeeded,
    evidence: evidence
  };
  console.log('ORACLE_RESULT ' + JSON.stringify(out));
}

try {
  // Benign operation first: prove quote() works normally on simple tokens,
  // including a normal object-token with a safe operator value (e.g. '&&').
  // Note: quote() always backslash-escapes op characters one-by-one, so the
  // expected benign output has each character of '&&' individually escaped.
  const benignTokens = ['echo', MARKER, { op: '&&' }, 'true'];
  const benignResult = shellQuote.quote(benignTokens);

  if (typeof benignResult !== 'string' || benignResult.indexOf(MARKER) === -1) {
    throw new Error('benign quote() operation did not include marker token: ' + JSON.stringify(benignResult));
  }
  // Confirm the operator characters (escaped or not) are present in some form.
  if (benignResult.indexOf('&') === -1) {
    throw new Error('benign quote() operation did not include operator characters: ' + JSON.stringify(benignResult));
  }

  // Benign call succeeded.
  operation_completed = true;

  // Malicious input: an object token whose .op contains a literal newline,
  // simulating attacker-influenced data reaching quote() via a documented
  // object-token path (direct construction or envFn return splicing).
  const maliciousOp = 'FOO\necho INJECTED_' + MARKER;
  const maliciousTokens = ['echo', 'safe', { op: maliciousOp }, 'bar'];

  let maliciousResult;
  try {
    maliciousResult = shellQuote.quote(maliciousTokens);
  } catch (e) {
    // If quote() itself throws on malicious input, the vulnerability is blocked.
    evidence = 'quote() threw on malicious object-token input: ' + (e && e.message);
    exploit_succeeded = false;
    finish();
    process.exit(0);
  }

  // Check whether the raw newline survived unescaped into the quoted output.
  // In the vulnerable version, the escaping regex /(.)/g does not match \n,
  // so the newline passes through literally, allowing a second shell command
  // to be smuggled in. In the patched version the newline is escaped (e.g.
  // represented as a backslash-prefixed sequence rather than a raw 0x0A byte),
  // so no raw newline character remains in the output.
  const containsRawNewline = typeof maliciousResult === 'string' && maliciousResult.indexOf('\n') !== -1;

  if (containsRawNewline) {
    exploit_succeeded = true;
    evidence = 'quote() output contains an unescaped raw newline from object .op field, enabling command injection: ' + JSON.stringify(maliciousResult);
  } else {
    exploit_succeeded = false;
    evidence = 'quote() output did not contain a raw unescaped newline; .op newline was properly escaped: ' + JSON.stringify(maliciousResult);
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'Exception during setup or benign operation: ' + (e && e.message ? e.message : String(e));
}

finish();
