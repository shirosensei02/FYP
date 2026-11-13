'use strict';

var operation_completed = false;
var exploit_succeeded = false;
var evidence = '';

try {
  var shellQuote = require('shell-quote');
  if (!shellQuote || typeof shellQuote.quote !== 'function') {
    throw new Error('shell-quote.quote is not available');
  }

  var quote = shellQuote.quote;

  // Benign API use: object token operator from documented model.
  var benignOut = quote(['echo', { op: '&&' }, 'ok']);
  if (typeof benignOut !== 'string' || benignOut.indexOf('echo') === -1 || benignOut.indexOf('ok') === -1) {
    throw new Error('benign quote output invalid');
  }

  operation_completed = true;

  // Malicious input: newline in .op should not be allowed through as a literal line break.
  var marker = 'ORACLE_INJECT_MARKER_9277';
  var maliciousToken = { op: '&&\n' + marker };

  try {
    var out = quote(['safe', maliciousToken, 'tail']);

    if (typeof out !== 'string') {
      exploit_succeeded = true;
      evidence = 'malicious call returned non-string';
    } else {
      var hasLiteralNewline = out.indexOf('\n') !== -1;
      var markerPresent = out.indexOf(marker) !== -1;

      // Vulnerable: newline passes through literally, enabling command separation in shell contexts.
      exploit_succeeded = hasLiteralNewline && markerPresent;
      evidence = 'out=' + JSON.stringify(out) + '; literal_newline=' + hasLiteralNewline + '; marker_present=' + markerPresent;
    }
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious input rejected: ' + (e && e.message ? e.message : String(e));
  }
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (e && e.message ? e.message : String(e));
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed: operation_completed,
  exploit_succeeded: exploit_succeeded,
  evidence: evidence
}));
