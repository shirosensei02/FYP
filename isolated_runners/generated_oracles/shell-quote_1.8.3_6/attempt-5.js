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
  var sq = require('shell-quote');
  if (!sq || typeof sq.quote !== 'function') {
    evidence = 'setup failure: shell-quote.quote missing';
    emit();
  } else {
    var benignOut;
    try {
      benignOut = sq.quote(['alpha', 'beta']);
    } catch (e) {
      evidence = 'benign call threw: ' + (e && e.message ? e.message : String(e));
      emit();
      return;
    }

    if (typeof benignOut !== 'string' || benignOut.indexOf('alpha') === -1 || benignOut.indexOf('beta') === -1) {
      evidence = 'benign output unexpected: ' + String(benignOut);
      emit();
      return;
    }

    operationCompleted = true;

    var marker = 'SQ_NEWLINE_MARKER_7f2b1';
    var payloadOp = '\n' + marker + '\n';
    var maliciousInput = ['cmd', { op: payloadOp }, 'tail'];

    try {
      var maliciousOut = sq.quote(maliciousInput);
      if (typeof maliciousOut !== 'string') {
        exploitSucceeded = false;
        evidence = 'malicious output non-string: ' + String(maliciousOut);
      } else {
        var hasLiteralBackslashNMarker = maliciousOut.indexOf('\\n' + marker + '\\n') !== -1;
        var hasRawNewlineMarker = maliciousOut.indexOf('\n' + marker + '\n') !== -1;

        exploitSucceeded = hasLiteralBackslashNMarker;
        evidence = 'benign=' + JSON.stringify(benignOut)
          + '; malicious=' + JSON.stringify(maliciousOut)
          + '; has_literal_backslash_n_marker=' + String(hasLiteralBackslashNMarker)
          + '; has_raw_newline_marker=' + String(hasRawNewlineMarker);
      }
    } catch (e2) {
      exploitSucceeded = false;
      evidence = 'malicious blocked by exception: ' + (e2 && e2.message ? e2.message : String(e2));
    }

    emit();
  }
} catch (topErr) {
  operationCompleted = false;
  exploitSucceeded = false;
  evidence = 'setup/module failure: ' + (topErr && topErr.message ? topErr.message : String(topErr));
  emit();
}
