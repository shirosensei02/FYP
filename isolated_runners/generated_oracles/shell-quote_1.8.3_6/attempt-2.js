'use strict';

var operationCompleted = false;
var exploitSucceeded = false;
var evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: operationCompleted,
    exploit_succeeded: exploitSucceeded,
    evidence: evidence
  }));
}

try {
  var shellQuote = require('shell-quote');
  if (!shellQuote || typeof shellQuote.quote !== 'function') {
    evidence = 'setup failure: shell-quote.quote is not available';
    emit();
  } else {
    // Benign operation: use plain words only so behavior is stable across versions.
    var benignInput = ['alpha', 'beta'];
    var benignOut;
    try {
      benignOut = shellQuote.quote(benignInput);
    } catch (e1) {
      evidence = 'benign operation threw: ' + (e1 && e1.message ? e1.message : String(e1));
      emit();
      return;
    }

    if (typeof benignOut !== 'string' || benignOut.indexOf('alpha') === -1 || benignOut.indexOf('beta') === -1) {
      evidence = 'benign operation unexpected output: ' + String(benignOut);
      emit();
      return;
    }

    operationCompleted = true;

    // Malicious operation: operator object with raw newlines should be escaped/blocked.
    var marker = 'SQ_NEWLINE_IN_OP_MARKER';
    var maliciousInput = ['cmd', { op: '\n' + marker + '\n' }, 'tail'];

    try {
      var maliciousOut = shellQuote.quote(maliciousInput);
      if (typeof maliciousOut !== 'string') {
        exploitSucceeded = false;
        evidence = 'malicious call returned non-string; benign=' + JSON.stringify(benignOut);
      } else {
        var hasRawNewline = maliciousOut.indexOf('\n') !== -1;
        var hasMarker = maliciousOut.indexOf(marker) !== -1;
        exploitSucceeded = hasRawNewline && hasMarker;
        evidence = 'benign=' + JSON.stringify(benignOut) + '; malicious=' + JSON.stringify(maliciousOut) + '; raw_newline=' + hasRawNewline + '; marker_present=' + hasMarker;
      }
    } catch (e2) {
      exploitSucceeded = false;
      evidence = 'malicious input blocked by exception: ' + (e2 && e2.message ? e2.message : String(e2));
    }

    emit();
  }
} catch (e) {
  operationCompleted = false;
  exploitSucceeded = false;
  evidence = 'setup/module failure: ' + (e && e.message ? e.message : String(e));
  emit();
}
