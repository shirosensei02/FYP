'use strict';

var operation_completed = false;
var exploit_succeeded = false;
var evidence = '';

try {
  var shellQuote = require('shell-quote');
  if (!shellQuote || typeof shellQuote.quote !== 'function') {
    throw new Error('quote API unavailable');
  }

  var quote = shellQuote.quote;

  // Benign operation must succeed first.
  var benign = quote(['echo', { op: '&&' }, 'ok']);
  if (typeof benign !== 'string' || benign.indexOf('echo') === -1 || benign.indexOf('ok') === -1) {
    throw new Error('benign quote() behavior unexpected');
  }

  operation_completed = true;

  var marker = 'ORACLE_NL_OP_9277_MARK';
  var payload = { op: '&&\n' + marker };

  try {
    var out = quote(['safe', payload, 'tail']);
    if (typeof out !== 'string') {
      exploit_succeeded = true;
      evidence = 'malicious quote() returned non-string';
    } else {
      var hasLiteralNewline = out.indexOf('\n') !== -1;
      var hasUnescapedMarkerLine = out.indexOf('\n' + marker) !== -1;
      exploit_succeeded = hasLiteralNewline && hasUnescapedMarkerLine;
      evidence = 'quoted=' + JSON.stringify(out) + '; has_literal_newline=' + hasLiteralNewline + '; has_newline_marker=' + hasUnescapedMarkerLine;
    }
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'malicious input blocked: ' + (err && err.message ? err.message : String(err));
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed: operation_completed,
  exploit_succeeded: exploit_succeeded,
  evidence: evidence
}));
