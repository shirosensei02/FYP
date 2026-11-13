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
    var benign;
    try {
      benign = sq.quote(['alpha', 'beta']);
    } catch (e) {
      evidence = 'benign call threw: ' + (e && e.message ? e.message : String(e));
      emit();
      return;
    }

    if (typeof benign !== 'string' || benign.indexOf('alpha') === -1 || benign.indexOf('beta') === -1) {
      evidence = 'benign output unexpected: ' + String(benign);
      emit();
      return;
    }

    operationCompleted = true;

    var marker = 'SQNL_MARK';
    var payload = '\n' + marker + '\n';
    var input = ['cmd', { op: payload }, 'tail'];

    try {
      var out = sq.quote(input);
      if (typeof out !== 'string') {
        exploitSucceeded = false;
        evidence = 'malicious output non-string: ' + String(out);
      } else {
        var hasRawNewlineMarker = out.indexOf('\n' + marker + '\n') !== -1;
        exploitSucceeded = hasRawNewlineMarker;
        evidence = 'benign=' + JSON.stringify(benign)
          + '; malicious=' + JSON.stringify(out)
          + '; raw_newline_marker_present=' + String(hasRawNewlineMarker);
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
