'use strict';

var operation_completed = false;
var exploit_succeeded = false;
var evidence = '';

try {
  var sq = require('shell-quote');
  if (!sq || typeof sq.quote !== 'function') {
    throw new Error('quote API missing');
  }

  var benign = sq.quote(['echo', { op: '&&' }, 'ok']);
  if (typeof benign !== 'string' || benign.indexOf('echo') === -1 || benign.indexOf('ok') === -1) {
    throw new Error('benign quote behavior unexpected');
  }

  operation_completed = true;

  var marker = 'ORACLE_GHSA_W7JW_789Q_3M8P_MARK';
  var payloadOp = '&&\n' + marker;

  try {
    var out = sq.quote(['safe', { op: payloadOp }, 'tail']);
    if (typeof out !== 'string') {
      exploit_succeeded = true;
      evidence = 'malicious call returned non-string output';
    } else {
      var rawNewline = out.indexOf('\n') !== -1;
      var markerPresent = out.indexOf(marker) !== -1;
      var backslashNMarker = out.indexOf('\\n' + marker) !== -1;
      exploit_succeeded = rawNewline && markerPresent;
      evidence = 'quoted=' + JSON.stringify(out)
        + '; raw_newline=' + rawNewline
        + '; marker_present=' + markerPresent
        + '; backslash_n_marker=' + backslashNMarker;
    }
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious token rejected: ' + (e && e.message ? e.message : String(e));
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
