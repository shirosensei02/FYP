'use strict';

var operation_completed = false;
var exploit_succeeded = false;
var evidence = '';

try {
  var sq = require('shell-quote');
  if (!sq || typeof sq.quote !== 'function') {
    throw new Error('quote_api_unavailable');
  }

  // Benign operation: quote plain string args and verify a stable, expected shape.
  var benignOut = sq.quote(['echo', 'ok']);
  if (typeof benignOut !== 'string') {
    throw new Error('benign_not_string');
  }
  if (benignOut !== 'echo ok') {
    throw new Error('benign_unexpected:' + JSON.stringify(benignOut));
  }

  operation_completed = true;

  var marker = 'GHSA_W7JW_789Q_3M8P_MARK';
  var maliciousOp = '&&\n' + marker;

  try {
    var out = sq.quote(['safe', { op: maliciousOp }, 'tail']);
    if (typeof out !== 'string') {
      exploit_succeeded = true;
      evidence = 'malicious_non_string';
    } else {
      var containsRawNewline = out.indexOf('\n') !== -1;
      var containsMarker = out.indexOf(marker) !== -1;
      // Vulnerable: raw line terminator survives into output, splitting shell command.
      exploit_succeeded = containsRawNewline && containsMarker;
      evidence = 'out=' + JSON.stringify(out) + ';raw_newline=' + containsRawNewline + ';marker=' + containsMarker;
    }
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'malicious_blocked:' + (err && err.message ? err.message : String(err));
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_error:' + (e && e.message ? e.message : String(e));
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed: operation_completed,
  exploit_succeeded: exploit_succeeded,
  evidence: evidence
}));
