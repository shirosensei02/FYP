'use strict';

var operationCompleted = false;
var exploitSucceeded = false;
var evidence = '';

function finish() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: operationCompleted,
    exploit_succeeded: exploitSucceeded,
    evidence: evidence
  }));
}

try {
  var shellQuote = require('shell-quote');
  if (!shellQuote || typeof shellQuote.quote !== 'function') {
    evidence = 'setup failure: missing shell-quote.quote';
    finish();
  } else {
    var benignOut;
    try {
      benignOut = shellQuote.quote(['alpha', 'beta']);
    } catch (e) {
      evidence = 'benign operation threw: ' + (e && e.message ? e.message : String(e));
      finish();
      return;
    }

    if (typeof benignOut !== 'string' || benignOut.indexOf('alpha') === -1 || benignOut.indexOf('beta') === -1) {
      evidence = 'benign operation unexpected output: ' + String(benignOut);
      finish();
      return;
    }

    operationCompleted = true;

    var marker = 'SQ_OP_NL_MARKER';
    var payloadOp = '\n' + marker + '\n';
    var maliciousInput = ['cmd', { op: payloadOp }, 'tail'];

    try {
      var out = shellQuote.quote(maliciousInput);
      if (typeof out !== 'string') {
        exploitSucceeded = false;
        evidence = 'malicious output non-string: ' + String(out);
      } else {
        var expected = 'cmd ' + payloadOp + ' tail';
        exploitSucceeded = out === expected;
        evidence = 'benign=' + JSON.stringify(benignOut)
          + '; malicious=' + JSON.stringify(out)
          + '; expected=' + JSON.stringify(expected)
          + '; exact_match=' + String(out === expected);
      }
    } catch (e2) {
      exploitSucceeded = false;
      evidence = 'malicious input blocked by exception: ' + (e2 && e2.message ? e2.message : String(e2));
    }

    finish();
  }
} catch (eTop) {
  operationCompleted = false;
  exploitSucceeded = false;
  evidence = 'setup/module failure: ' + (eTop && eTop.message ? eTop.message : String(eTop));
  finish();
}
