'use strict';
const shellQuote = require('shell-quote');

const MARKER = 'SQ_MARKER_' + process.pid + '_' + Date.now();

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: operation_completed,
    exploit_succeeded: exploit_succeeded,
    evidence: evidence
  }));
}

try {
  // Benign usage first: prove quote() works normally with plain strings.
  const benignResult = shellQuote.quote(['echo', 'hello', MARKER]);
  if (typeof benignResult !== 'string' || benignResult.indexOf(MARKER) === -1) {
    throw new Error('benign quote() did not produce expected output');
  }

  // Benign operation succeeded.
  operation_completed = true;

  // Malicious input: an object token whose .op contains a literal newline, simulating
  // attacker-influenced data reaching quote() via a deserialized argument array or envFn splice.
  const maliciousOp = '\n'; // literal newline acting as command separator in POSIX shells
  const maliciousTokens = [
    'echo',
    'safe',
    { op: maliciousOp },
    'echo ' + MARKER + '_INJECTED'
  ];

  let maliciousResult;
  try {
    maliciousResult = shellQuote.quote(maliciousTokens);
  } catch (innerErr) {
    // A patched version may throw on invalid/unrecognized operator tokens - that counts as blocked.
    evidence = 'quote() rejected malicious object token after benign call succeeded: ' + String(innerErr && innerErr.message);
    exploit_succeeded = false;
    finish();
    process.exit(0);
  }

  // Determine if the raw, unescaped newline made it into the output string.
  // If a literal, unescaped newline appears in the output, a downstream shell consumer
  // would treat it as a command separator, enabling command injection.
  // An escaped newline would appear as the two characters backslash followed by 'n' (\\n)
  // or a backslash immediately followed by an actual newline character.
  let rawUnescapedNewline = false;
  for (let i = 0; i < maliciousResult.length; i++) {
    if (maliciousResult[i] === '\n') {
      // Check if preceded by a backslash (i.e. escaped)
      if (i === 0 || maliciousResult[i - 1] !== '\\') {
        rawUnescapedNewline = true;
        break;
      }
    }
  }

  if (rawUnescapedNewline) {
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
