'use strict';

var operation_completed = false;
var exploit_succeeded = false;
var evidence = '';

try {
  var sq = require('shell-quote');
  var quote = sq && sq.quote;

  if (typeof quote !== 'function') {
    throw new Error('quote API is unavailable');
  }

  // Benign operation: documented object token with normal operator text
  var benign = quote(['echo', { op: '&&' }, 'ok']);
  if (typeof benign !== 'string' || benign.indexOf('echo') === -1 || benign.indexOf('ok') === -1) {
    throw new Error('benign quote output was not a valid command string');
  }

  operation_completed = true;

  // Malicious operation: newline in object .op should be rejected/safely handled in patched versions
  var payload = { op: '&&\nINJECTED_SECOND_COMMAND' };
  try {
    var out = quote(['safe', payload, 'tail']);

    if (typeof out !== 'string') {
      exploit_succeeded = true;
      evidence = 'malicious quote returned non-string output';
    } else {
      var hasLiteralNewline = out.indexOf('\n') !== -1;
      var hasInjectedMarker = out.indexOf('INJECTED_SECOND_COMMAND') !== -1;

      // Vulnerable behavior: newline survives into emitted shell text with attacker marker present.
      exploit_succeeded = hasLiteralNewline && hasInjectedMarker;
      evidence = 'output=' + JSON.stringify(out) + '; newline=' + hasLiteralNewline + '; marker=' + hasInjectedMarker;
    }
  } catch (malErr) {
    exploit_succeeded = false;
    evidence = 'malicious input blocked: ' + (malErr && malErr.message ? malErr.message : String(malErr));
  }
} catch (err) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failed: ' + (err && err.message ? err.message : String(err));
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed: operation_completed,
  exploit_succeeded: exploit_succeeded,
  evidence: evidence
}));
