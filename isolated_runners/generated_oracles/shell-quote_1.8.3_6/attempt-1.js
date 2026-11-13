'use strict';

var shellQuote;
var operationCompleted = false;
var exploitSucceeded = false;
var evidence = '';

function finish() {
  var result = {
    operation_completed: operationCompleted,
    exploit_succeeded: exploitSucceeded,
    evidence: evidence
  };
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  shellQuote = require('shell-quote');
  if (!shellQuote || typeof shellQuote.quote !== 'function') {
    evidence = 'shell-quote.quote is unavailable';
    finish();
  } else {
    var benignInput = ['safe', { op: '&&' }, 'echo'];
    var benignOut = shellQuote.quote(benignInput);

    if (typeof benignOut !== 'string' || benignOut.indexOf('&&') === -1) {
      evidence = 'benign quote() did not produce expected operator output: ' + String(benignOut);
      finish();
    } else {
      operationCompleted = true;

      var marker = 'ORACLE_NL_INJECTION_MARKER';
      var maliciousInput = ['x', { op: '\n' + marker + '\n' }, 'y'];

      try {
        var maliciousOut = shellQuote.quote(maliciousInput);
        if (typeof maliciousOut !== 'string') {
          exploitSucceeded = false;
          evidence = 'malicious quote() returned non-string';
        } else {
          var hasRawNewline = maliciousOut.indexOf('\n') !== -1;
          var hasMarker = maliciousOut.indexOf(marker) !== -1;
          exploitSucceeded = hasRawNewline && hasMarker;
          evidence = 'benign=' + JSON.stringify(benignOut) + '; malicious=' + JSON.stringify(maliciousOut) + '; hasRawNewline=' + hasRawNewline + '; hasMarker=' + hasMarker;
        }
      } catch (e) {
        exploitSucceeded = false;
        evidence = 'malicious input blocked with exception: ' + (e && e.message ? e.message : String(e));
      }

      finish();
    }
  }
} catch (e) {
  operationCompleted = false;
  exploitSucceeded = false;
  evidence = 'setup/module failure: ' + (e && e.message ? e.message : String(e));
  finish();
}