'use strict';

var operation_completed = false;
var exploit_succeeded = false;
var evidence = '';

try {
  var sq = require('shell-quote');
  if (!sq || typeof sq.quote !== 'function') {
    throw new Error('quote_api_unavailable');
  }

  // Benign use: only string args, deterministic and should always work.
  var benignOut = sq.quote(['echo', 'ok']);
  if (typeof benignOut !== 'string') {
    throw new Error('benign_non_string_output');
  }
  if (benignOut.indexOf('echo') === -1 || benignOut.indexOf('ok') === -1) {
    throw new Error('benign_unexpected_output:' + JSON.stringify(benignOut));
  }

  operation_completed = true;

  // Malicious object token: newline in .op should be rejected/sanitized by fixed versions.
  var marker = 'GHSA_W7JW_789Q_3M8P_MARK';
  var payloadOp = '&&\n' + marker;

  try {
    var out = sq.quote(['safe', { op: payloadOp }, 'tail']);
    if (typeof out !== 'string') {
      exploit_succeeded = true;
      evidence = 'malicious_return_type:' + (typeof out);
    } else {
      var hasRawNewline = out.indexOf('\n') !== -1;
      var hasMarker = out.indexOf(marker) !== -1;
      exploit_succeeded = hasRawNewline && hasMarker;
      evidence = 'output=' + JSON.stringify(out) + ';raw_newline=' + hasRawNewline + ';marker=' + hasMarker;
    }
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious_rejected';
  }
} catch (eTop) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure:' + (eTop && eTop.message ? eTop.message : String(eTop));
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed: operation_completed,
  exploit_succeeded: exploit_succeeded,
  evidence: evidence
}));
