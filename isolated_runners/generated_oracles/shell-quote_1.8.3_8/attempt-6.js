'use strict';

var operation_completed = false;
var exploit_succeeded = false;
var evidence = '';

try {
  var sq = require('shell-quote');
  if (!sq || typeof sq.quote !== 'function') {
    throw new Error('missing quote()');
  }

  // Benign API use must succeed first.
  var benignOut = sq.quote(['echo', { op: '&&' }, 'ok']);
  if (typeof benignOut !== 'string') {
    throw new Error('benign quote() did not return string');
  }
  if (benignOut.indexOf('echo') === -1 || benignOut.indexOf('ok') === -1 || benignOut.indexOf('&&') === -1) {
    throw new Error('benign quote() output unexpected: ' + JSON.stringify(benignOut));
  }

  operation_completed = true;

  // Malicious object token: newline inside .op should not be allowed.
  var marker = 'ORACLE_GHSA_W7JW_789Q_3M8P';
  var payloadOp = '&&\n' + marker;

  try {
    var out = sq.quote(['safe', { op: payloadOp }, 'tail']);
    if (typeof out !== 'string') {
      exploit_succeeded = true;
      evidence = 'malicious quote() returned non-string';
    } else {
      var hasRawNewline = out.indexOf('\n') !== -1;
      var hasMarker = out.indexOf(marker) !== -1;
      // Vulnerable behavior: returns output that still contains a literal newline
      // and attacker-controlled continuation text.
      exploit_succeeded = hasRawNewline && hasMarker;
      evidence = 'out=' + JSON.stringify(out)
        + '; has_raw_newline=' + hasRawNewline
        + '; has_marker=' + hasMarker;
    }
  } catch (err) {
    exploit_succeeded = false;
    evidence = 'malicious input rejected: ' + (err && err.message ? err.message : String(err));
  }
} catch (errTop) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (errTop && errTop.message ? errTop.message : String(errTop));
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed: operation_completed,
  exploit_succeeded: exploit_succeeded,
  evidence: evidence
}));
