'use strict';

var operation_completed = false;
var exploit_succeeded = false;
var evidence = '';

try {
  var sq = require('shell-quote');
  if (!sq || typeof sq.quote !== 'function') {
    throw new Error('quote_missing');
  }

  // Benign: documented object op token with a normal operator should round-trip.
  var benign = sq.quote(['echo', { op: '&&' }, 'ok']);
  if (typeof benign !== 'string') {
    throw new Error('benign_not_string');
  }
  if (benign.indexOf('echo') === -1 || benign.indexOf('ok') === -1 || benign.indexOf('&&') === -1) {
    throw new Error('benign_unexpected:' + JSON.stringify(benign));
  }

  operation_completed = true;

  var marker = 'GHSA_W7JW_789Q_3M8P_SPLIT';
  var injected = '&&\n' + marker;

  try {
    var out = sq.quote(['safe', { op: injected }, 'tail']);
    if (typeof out !== 'string') {
      exploit_succeeded = true;
      evidence = 'malicious_non_string_return';
    } else {
      var hasLineBreak = /[\n\r\u2028\u2029]/.test(out);
      var hasMarker = out.indexOf(marker) !== -1;
      // Vulnerable behavior: line terminator survives into emitted command string.
      exploit_succeeded = hasLineBreak && hasMarker;
      evidence = 'out=' + JSON.stringify(out) + ';linebreak=' + hasLineBreak + ';marker=' + hasMarker;
    }
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious_input_blocked';
  }
} catch (eTop) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_error:' + (eTop && eTop.message ? eTop.message : String(eTop));
}

console.log('ORACLE_RESULT ' + JSON.stringify({
  operation_completed: operation_completed,
  exploit_succeeded: exploit_succeeded,
  evidence: evidence
}));
