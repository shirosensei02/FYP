const _ = require('lodash');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function emit() {
  console.log('ORACLE_RESULT ' + JSON.stringify({
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  }));
}

try {
  const marker = '__oracle_pp_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2) + '__';

  try { delete Object.prototype[marker]; } catch (e) {}

  const benignTarget = { x: { y: 1 } };
  const benignSource = { x: { z: 2 } };
  const benignOut = _.defaultsDeep({}, benignTarget, benignSource);
  if (!benignOut || !benignOut.x || benignOut.x.y !== 1 || benignOut.x.z !== 2) {
    throw new Error('benign _.defaultsDeep failed');
  }

  operation_completed = true;

  let threw = false;
  let throwMsg = '';
  try {
    _.defaultsDeep({}, JSON.parse('{"constructor":{"prototype":{"' + marker + '":"polluted"}}}'));
  } catch (e) {
    threw = true;
    throwMsg = e && e.message ? e.message : String(e);
  }

  const polluted = ({}[marker] === 'polluted');
  exploit_succeeded = polluted;

  if (polluted) {
    evidence = 'Object prototype polluted via _.defaultsDeep constructor.prototype path';
  } else if (threw) {
    evidence = 'malicious defaultsDeep blocked with throw: ' + throwMsg;
  } else {
    evidence = 'malicious defaultsDeep completed without observable prototype pollution';
  }

  try { delete Object.prototype[marker]; } catch (e) {}
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (e && e.message ? e.message : String(e));
}

emit();